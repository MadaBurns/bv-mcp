// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

/**
 * Pure analysis for the non-scoring `http_redirect` check.
 *
 * Takes the redirect chains `check-http-redirect.ts` walked from `http://` and `https://` on the
 * apex and on `www`, and returns findings. No fetching here.
 *
 * A host or chain that could not be fetched stays distinct from a bad one: it is reported as not
 * assessed, never as "does not redirect". Only a chain that ended on a real answer can say the
 * redirect is missing.
 */

import type { Finding, Severity } from '../types';
import { createFinding } from '../check-utils';
import { isBlockedProbeStatus } from './ssl-analysis';

/** Redirects the walker follows before it gives up on a chain. */
export const MAX_REDIRECT_HOPS = 6;

/** More redirects than this is reported as an overlong chain. */
export const MAX_RECOMMENDED_HOPS = 5;

/** Statuses that read as temporary where a permanent HTTP-to-HTTPS upgrade is expected. */
const TEMPORARY_REDIRECT_STATUSES: ReadonlySet<number> = new Set([302, 307]);

/** Statuses that say nothing about a host: an auth wall or rate limit is not a served page. */
const NON_ERROR_WALLS: ReadonlySet<number> = new Set([401, 403, 429]);

/** One response in a walked chain. */
export interface RedirectStep {
	/** The URL requested. */
	url: string;
	status: number;
	/** The absolute URL this response redirects to, or `null` when it is not a followable redirect. */
	next: string | null;
}

/**
 * How a chain ended.
 * - `final`: the last step is not a redirect.
 * - `loop`: the last step redirects to a URL already requested.
 * - `exhausted`: the walker stopped at {@link MAX_REDIRECT_HOPS} with the last step still redirecting.
 * - `interrupted`: fetching the last step's target failed.
 */
export type ChainEnd = 'final' | 'loop' | 'exhausted' | 'interrupted';

/**
 * Why a request in a chain did not produce a response.
 * - `deadline`: our own clock or abort ended it (the time limit ran out, or the scan was cancelled).
 *   Says nothing about the target.
 * - `robots_disallowed`: the target's robots.txt disallows the request, so it was never sent.
 * - `request_refused`: the scanner's outbound-request guard refused the URL (for example a plain-http
 *   hop to a foreign host), so it was never sent.
 * - `network`: the request was sent and failed on the wire (connection refused, DNS, TLS, reset).
 */
export type FailureCause = 'deadline' | 'robots_disallowed' | 'request_refused' | 'network';

export interface RedirectChain {
	startUrl: string;
	steps: RedirectStep[];
	end: ChainEnd;
	/** Why the walk was cut short; set when `end` is `interrupted`. Absent reads as `network`. */
	cause?: FailureCause;
}

export type HostLabel = 'apex' | 'www';

/**
 * The two chains walked for one host. `null`: the first request failed, so nothing was measured;
 * `httpFailure` / `httpsFailure` say why. Absent reads as `network`.
 */
export interface HostWalk {
	label: HostLabel;
	hostname: string;
	http: RedirectChain | null;
	https: RedirectChain | null;
	httpFailure?: FailureCause;
	httpsFailure?: FailureCause;
}

function finding(severity: Severity, title: string, detail: string, metadata: Record<string, unknown> = {}): Finding {
	return createFinding('http_redirect', title, severity, detail, metadata);
}

/** A fact that could not be measured. Never `missingControl`: nothing was observed, so nothing is claimed absent. */
export function notAssessedFinding(title: string, reason: string, errorKind: string): Finding {
	return finding('info', title, `not assessed: ${reason}.`, { inconclusive: true, errorKind });
}

/** Which cause outranks another when several apply: never blame the target for our own abort. */
const CAUSE_PRIORITY: readonly FailureCause[] = ['deadline', 'robots_disallowed', 'request_refused', 'network'];

/** The single cause that best explains several failures. An absent cause reads as `network`. */
export function dominantCause(causes: readonly (FailureCause | undefined)[]): FailureCause {
	const seen = new Set(causes.map((cause) => cause ?? 'network'));
	return CAUSE_PRIORITY.find((cause) => seen.has(cause)) ?? 'network';
}

/**
 * The "not assessed" sentence for `what` (a request, a start URL or a host) that produced no
 * response. Only `network` says the request failed: a deadline, a robots.txt disallow and a refused
 * URL are our side of the exchange, never the target failing.
 */
function causeReason(cause: FailureCause, what: string): string {
	switch (cause) {
		case 'deadline':
			return `not assessed within the time limit: ${what} did not complete before it ran out`;
		case 'robots_disallowed':
			return `not assessed: ${what} was not requested because the site's robots.txt disallows it`;
		case 'request_refused':
			return `not assessed: ${what} was not requested because the scanner's outbound-request guard refused the URL`;
		case 'network':
			return `not assessed: ${what} failed with a network or TLS error`;
	}
}

/**
 * A fact that could not be measured because of `cause`. `errorKind` stays the legacy token for a
 * network failure and is the cause itself otherwise. Never `missingControl`: nothing was observed.
 */
function causeFinding(title: string, cause: FailureCause, what: string, networkKind: string): Finding {
	const errorKind = cause === 'network' ? networkKind : cause;
	return finding('info', title, `${causeReason(cause, what)}.`, { inconclusive: true, errorKind, cause });
}

const isHttps = (url: string): boolean => url.startsWith('https://');

const hostnameOf = (url: string): string => URL.parse(url)?.hostname ?? '';

const lastStep = (chain: RedirectChain): RedirectStep => chain.steps[chain.steps.length - 1];

export function redirectCount(chain: RedirectChain): number {
	return chain.steps.filter((step) => step.next !== null).length;
}

/** True once any request in the chain, or the target of its last redirect, is HTTPS. */
function reachesHttps(chain: RedirectChain): boolean {
	return chain.steps.some((step) => isHttps(step.url) || (step.next !== null && isHttps(step.next)));
}

function tag(host: HostWalk, scheme: 'http' | 'https', chain: RedirectChain): Record<string, unknown> {
	return { host: host.label, hostname: host.hostname, scheme, startUrl: chain.startUrl };
}

function chainShapeFinding(host: HostWalk, scheme: 'http' | 'https', chain: RedirectChain): Finding | null {
	const meta = { ...tag(host, scheme, chain), redirects: redirectCount(chain) };
	if (chain.end === 'loop') {
		return finding('medium', `Redirect loop (${host.label})`, `${chain.startUrl} redirects in a loop and never reaches a page. Break the cycle so the URL settles on one final page.`, meta);
	}
	if (redirectCount(chain) > MAX_RECOMMENDED_HOPS) {
		const tail = chain.end === 'exhausted' ? ` and still had not settled after ${MAX_REDIRECT_HOPS} redirects` : '';
		return finding('medium', `Long redirect chain (${host.label})`, `${chain.startUrl} takes ${redirectCount(chain)} redirects${tail}. Keep it to ${MAX_RECOMMENDED_HOPS} or fewer; ideally redirect straight to the final URL.`, meta);
	}
	return null;
}

function downgradeFinding(host: HostWalk, scheme: 'http' | 'https', chain: RedirectChain): Finding | null {
	const step = chain.steps.find((candidate) => candidate.next !== null && isHttps(candidate.url) && !isHttps(candidate.next));
	if (!step) return null;
	return finding('high', `HTTPS redirects down to HTTP (${host.label})`, `${step.url} redirects to ${step.next}, which drops encryption. Redirect only to https:// URLs.`, {
		...tag(host, scheme, chain),
		from: step.url,
		to: step.next,
	});
}

function interruptedFinding(host: HostWalk, scheme: 'http' | 'https', chain: RedirectChain): Finding | null {
	if (chain.end !== 'interrupted') return null;
	return causeFinding(`Redirect chain not fully assessed (${host.label})`, chain.cause ?? 'network', `the request that follows ${lastStep(chain).url}`, 'chain_interrupted');
}

/** The missing-upgrade verdict, or an abstention when the plain-HTTP answer cannot be read as one. */
function missingUpgradeFinding(host: HostWalk, chain: RedirectChain): Finding | null {
	if (chain.end !== 'final' || reachesHttps(chain)) return null;
	const answer = lastStep(chain);
	if (isBlockedProbeStatus(answer.status)) {
		return notAssessedFinding(`HTTP redirect not assessed (${host.label})`, `${chain.startUrl} answered HTTP ${answer.status}, which says nothing about a redirect`, 'blocked_probe');
	}
	const severity: Severity = host.label === 'apex' ? 'high' : 'medium';
	return finding(severity, `HTTP does not redirect to HTTPS (${host.label})`, `${chain.startUrl} is served over plain HTTP (HTTP ${answer.status}) without redirecting to HTTPS. Redirect all HTTP requests to HTTPS.`, {
		...tag(host, 'http', chain),
		finalStatus: answer.status,
	});
}

/** The HSTS preload rule: the first hop must stay on the same host and upgrade to HTTPS before any other host is involved. */
function crossHostFirstHopFinding(host: HostWalk, chain: RedirectChain): Finding | null {
	const first = chain.steps[0];
	if (!first?.next || isHttps(first.next) || !reachesHttps(chain)) return null;
	if (hostnameOf(first.next) === hostnameOf(first.url)) return null;
	return finding('medium', `HTTP redirects to another host before HTTPS (${host.label})`, `${first.url} first redirects to ${first.next} over plain HTTP and only upgrades later. Redirect to https:// on the same host first, then to the other host (the HSTS preload list requires this).`, {
		...tag(host, 'http', chain),
		firstHop: first.next,
	});
}

function temporaryUpgradeFinding(host: HostWalk, chain: RedirectChain): Finding | null {
	const step = chain.steps.find((candidate) => candidate.next !== null && !isHttps(candidate.url) && isHttps(candidate.next));
	if (!step || !TEMPORARY_REDIRECT_STATUSES.has(step.status)) return null;
	return finding('info', `HTTP upgrade uses a temporary redirect (${host.label})`, `${step.url} upgrades to HTTPS with HTTP ${step.status}. A permanent redirect (301 or 308) lets browsers and crawlers cache the upgrade.`, {
		...tag(host, 'http', chain),
		status: step.status,
	});
}

function plainHttpFindings(host: HostWalk, chain: RedirectChain): Array<Finding | null> {
	return [missingUpgradeFinding(host, chain), crossHostFirstHopFinding(host, chain), temporaryUpgradeFinding(host, chain)];
}

function chainFindings(host: HostWalk, scheme: 'http' | 'https', chain: RedirectChain): Finding[] {
	const found = [chainShapeFinding(host, scheme, chain), downgradeFinding(host, scheme, chain), interruptedFinding(host, scheme, chain)];
	if (scheme === 'http') found.push(...plainHttpFindings(host, chain));
	return found.filter((item): item is Finding => item !== null);
}

/** Every start URL whose first request failed, as not assessed, or one www-specific finding when the whole host is silent. */
function unmeasuredFindings(host: HostWalk): Finding[] {
	if (host.http === null && host.https === null) {
		const cause = dominantCause([host.httpFailure, host.httpsFailure]);
		// "not resolvable or not served" is a claim about www itself, so only a network failure may make it.
		const title = host.label === 'apex' ? 'Apex host not assessed' : cause === 'network' ? 'www host not resolvable or not served' : 'www host not assessed';
		return [causeFinding(title, cause, `${host.hostname} over http or https`, 'host_unreachable')];
	}
	const missing: Array<'http' | 'https'> = [];
	if (host.http === null) missing.push('http');
	if (host.https === null) missing.push('https');
	return missing.map((scheme) =>
		causeFinding(`${scheme.toUpperCase()} redirects not assessed (${host.label})`, (scheme === 'http' ? host.httpFailure : host.httpsFailure) ?? 'network', `${scheme}://${host.hostname}/`, 'fetch_failed'),
	);
}

/**
 * True when the HTTP walk already passed through the HTTPS start URL. Both walks then ended on the
 * same tail, so the HTTPS chain's shape problems are already in the HTTP chain's findings.
 */
function httpWalkCoversHttps(host: HostWalk): boolean {
	const start = host.https?.startUrl;
	return host.http?.steps.some((step) => step.url === start) ?? false;
}

function hostFindings(host: HostWalk): Finding[] {
	const found = unmeasuredFindings(host);
	if (host.http) found.push(...chainFindings(host, 'http', host.http));
	if (host.https && !httpWalkCoversHttps(host)) found.push(...chainFindings(host, 'https', host.https));
	return found;
}

interface Landing {
	url: string;
	origin: string;
	status: number;
}

/** Where the host settles: its HTTPS chain's last page, else its HTTP chain's. `null` when no chain finished. */
function landingOf(host: HostWalk): Landing | null {
	const chain = [host.https, host.http].find((candidate) => candidate?.end === 'final');
	if (!chain) return null;
	const answer = lastStep(chain);
	const origin = URL.parse(answer.url)?.origin;
	return origin ? { url: answer.url, origin, status: answer.status } : null;
}

const isServed = (status: number): boolean => status >= 200 && status < 300;

/** A real error answer; an auth wall or rate limit is not evidence the host fails to serve. */
const isErrorAnswer = (status: number): boolean => status >= 400 && !NON_ERROR_WALLS.has(status);

function parityFinding(apex: Landing, www: Landing): Finding | null {
	if (apex.origin === www.origin) return null;
	const meta = { apexLanding: apex.url, apexStatus: apex.status, wwwLanding: www.url, wwwStatus: www.status };
	if ((isServed(apex.status) && isErrorAnswer(www.status)) || (isErrorAnswer(apex.status) && isServed(www.status))) {
		const broken = isErrorAnswer(www.status) ? 'www' : 'apex';
		return finding('low', 'Apex and www disagree: one serves, one errors', `The apex lands on ${apex.url} (HTTP ${apex.status}) but www lands on ${www.url} (HTTP ${www.status}). Make ${broken} serve the site or redirect to the host that does.`, meta);
	}
	if (isServed(apex.status) && isServed(www.status)) {
		return finding('low', 'Apex and www end on different origins', `The apex lands on ${apex.url} and www on ${www.url}. Redirect one host to the other so the site has a single canonical origin.`, meta);
	}
	return null;
}

function parityFindings(apex: HostWalk, www: HostWalk): Finding[] {
	const apexLanding = landingOf(apex);
	const wwwLanding = landingOf(www);
	if (!apexLanding || !wwwLanding) return [];
	return [parityFinding(apexLanding, wwwLanding)].filter((item): item is Finding => item !== null);
}

/** The finding for a domain on which no request got an answer, worded by why. */
export function nothingMeasuredFinding(domain: string, apex: HostWalk, www: HostWalk): Finding {
	const cause = dominantCause([apex.httpFailure, apex.httpsFailure, www.httpFailure, www.httpsFailure]);
	return causeFinding('HTTP redirects not assessed', cause, `${domain} and www.${domain} over http or https`, 'fetch_failed');
}

/** True when no chain on either host got a first response. */
export function nothingMeasured(apex: HostWalk, www: HostWalk): boolean {
	return [apex.http, apex.https, www.http, www.https].every((chain) => chain === null);
}

/** Every finding for the domain: per-chain redirect problems, unmeasured hosts, and apex/www parity. */
export function analyzeHttpRedirects(apex: HostWalk, www: HostWalk): Finding[] {
	return [...hostFindings(apex), ...hostFindings(www), ...parityFindings(apex, www)];
}
