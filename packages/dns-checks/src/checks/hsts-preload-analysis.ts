// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

/**
 * Pure analysis for the non-scoring `hsts_preload` check.
 *
 * Two independent facts are combined: whether the apex's `Strict-Transport-Security` header
 * meets the hstspreload.org submission rules (eligibility), and whether hstspreload.org already
 * lists the domain (membership). No fetching here: `check-hsts-preload.ts` owns the I/O.
 *
 * Every fact that could not be measured stays distinct from a negative one. A missing apex page
 * is "header not assessed", never "no HSTS"; a failed status lookup is `not_assessed`, never
 * "not preloaded".
 */

import type { Finding, Severity } from '../types';
import { createFinding } from '../check-utils';
import type { CappedPage } from './page-fetch';
import { isBlockedProbeStatus } from './ssl-analysis';

/** hstspreload.org submission rule: `max-age` of at least one year. */
export const PRELOAD_MIN_MAX_AGE = 31_536_000;

/** Status endpoint of the hstspreload.org API. */
export const PRELOAD_STATUS_API = 'https://hstspreload.org/api/v2/status';

/** Longest status response read; the real payload is a few hundred bytes. */
export const PRELOAD_STATUS_MAX_BYTES = 16_384;

const PRELOAD_URL = 'https://hstspreload.org/';

// `max-age` is matched exactly as ssl-analysis.ts does (RFC 6797 §6.1: a whole directive, value
// possibly a quoted-string). ssl-analysis keeps its regexes private and its scored behaviour must
// not change, so the pattern is mirrored here rather than imported. `includeSubDomains` and
// `preload` are anchored on `;` as well: a token inside another directive does not count.
const MAX_AGE_PATTERN = /(?:^|;)\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*(?=;|$)/i;
const INCLUDE_SUBDOMAINS_PATTERN = /(?:^|;)\s*includeSubDomains\s*(?=;|$)/i;
const PRELOAD_PATTERN = /(?:^|;)\s*preload\s*(?=;|$)/i;

export interface PreloadEligibility {
	headerPresent: boolean;
	/** Seconds, or `null` when the header has no valid `max-age`. */
	maxAge: number | null;
	includeSubDomains: boolean;
	preload: boolean;
	/** Does `http://<apex>/` redirect to https on the same host first? `null` when unmeasured. */
	redirectsToHttps: boolean | null;
	/** Each requirement that is not met, as a phrase completing "missing ...". */
	missing: string[];
	/** `false`: a known requirement fails. `null`: every header requirement is met but the redirect was not measured. */
	eligible: boolean | null;
}

export type PreloadStatus = 'preloaded' | 'pending' | 'unknown' | 'rejected';

export type PreloadMembership = { status: PreloadStatus } | { status: 'not_assessed'; reason: string };

/** What the apex HTTPS response said about HSTS, or why that is not known. */
export type HstsObservation = { measured: true; header: string | null } | { measured: false; reason: string };

const PRELOAD_STATUSES: ReadonlySet<string> = new Set<PreloadStatus>(['preloaded', 'pending', 'unknown', 'rejected']);

function isPreloadStatus(value: unknown): value is PreloadStatus {
	return typeof value === 'string' && PRELOAD_STATUSES.has(value);
}

function parseMaxAge(header: string): number | null {
	const match = header.match(MAX_AGE_PATTERN);
	return match ? Number.parseInt(match[1] ?? match[2], 10) : null;
}

function maxAgeProblem(maxAge: number | null): string | null {
	if (maxAge === null) return 'a valid max-age directive';
	if (maxAge < PRELOAD_MIN_MAX_AGE) return `a max-age of at least ${PRELOAD_MIN_MAX_AGE} seconds (it is ${maxAge})`;
	return null;
}

/**
 * Check an HSTS header against the hstspreload.org submission rules: `max-age` of at least
 * 31536000, `includeSubDomains`, `preload`, and an HTTP-to-HTTPS redirect on the apex.
 *
 * `hstsHeader` is `null` when the apex answered without the header. `redirectsToHttps` is `null`
 * when the redirect could not be measured; that never counts as a failed requirement.
 */
export function assessPreloadEligibility(hstsHeader: string | null, context: { redirectsToHttps: boolean | null }): PreloadEligibility {
	const { redirectsToHttps } = context;
	const maxAge = hstsHeader === null ? null : parseMaxAge(hstsHeader);
	const includeSubDomains = hstsHeader !== null && INCLUDE_SUBDOMAINS_PATTERN.test(hstsHeader);
	const preload = hstsHeader !== null && PRELOAD_PATTERN.test(hstsHeader);
	const missing = [
		hstsHeader === null ? 'a Strict-Transport-Security header' : maxAgeProblem(maxAge),
		hstsHeader !== null && !includeSubDomains ? 'the includeSubDomains directive' : null,
		hstsHeader !== null && !preload ? 'the preload directive' : null,
		redirectsToHttps === false ? 'an HTTP-to-HTTPS redirect on the same host' : null,
	].filter((requirement): requirement is string => requirement !== null);
	const eligible = missing.length > 0 ? false : redirectsToHttps === null ? null : true;
	return { headerPresent: hstsHeader !== null, maxAge, includeSubDomains, preload, redirectsToHttps, missing, eligible };
}

/** Read the apex's own HSTS header, or say why it is unknown. A blocked answer without the header says nothing about HSTS. */
export function observeHsts(page: CappedPage | null, host: string): HstsObservation {
	if (page === null) return { measured: false, reason: `https://${host}/ could not be fetched` };
	const header = page.headers.get('strict-transport-security');
	if (header === null && isBlockedProbeStatus(page.status)) {
		return { measured: false, reason: `https://${host}/ answered HTTP ${page.status}, an edge, WAF, rate-limit or server-error response rather than the site's own` };
	}
	return { measured: true, header };
}

function isRedirectStatus(status: number): boolean {
	return status === 0 || (status >= 300 && status < 400);
}

/**
 * Did `http://<host>/` answer with a redirect to https on the SAME host? hstspreload.org rejects
 * a first hop to another host (for example the www form) even when that host then serves https.
 *
 * `page` is the FIRST response only (fetched with `maxRedirects: 0`), so its `Location` is read
 * directly and the hop is never followed. `null` when the plain-HTTP leg could not be measured.
 */
export function httpRedirectsToHttps(page: CappedPage | null, host: string): boolean | null {
	if (page === null) return null;
	const location = page.headers.get('location');
	if (isRedirectStatus(page.status) && location !== null) {
		const target = URL.parse(location, `http://${host}/`);
		return target?.protocol === 'https:' && target.hostname.toLowerCase() === host.toLowerCase();
	}
	return isBlockedProbeStatus(page.status) ? null : false;
}

function notAssessed(reason: string): PreloadMembership {
	return { status: 'not_assessed', reason };
}

/**
 * Map a hstspreload.org status response to a membership. Anything but a JSON object carrying one
 * of the four documented statuses (for this domain) is `not_assessed`: an error is never read as
 * "not preloaded".
 */
export function parsePreloadStatus(text: string, domain: string): PreloadMembership {
	let payload: unknown;
	try {
		payload = JSON.parse(text);
	} catch {
		return notAssessed('hstspreload.org returned a response that is not JSON');
	}
	if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) return notAssessed('hstspreload.org returned an unexpected response shape');
	const { status, name } = payload as { status?: unknown; name?: unknown };
	if (!isPreloadStatus(status)) return notAssessed('hstspreload.org returned an unrecognised status');
	if (typeof name === 'string' && name.toLowerCase().replace(/\.$/, '') !== domain.toLowerCase()) {
		return notAssessed('hstspreload.org answered for a different domain');
	}
	return { status };
}

// ── Findings ─────────────────────────────────────────────────────────────────

const HEADER_EXAMPLE = 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload';
const PRELOAD_COMMITMENT = 'Preloading commits every subdomain to HTTPS and removal takes months, so confirm all subdomains serve valid HTTPS first.';

function finding(severity: Severity, title: string, detail: string, metadata?: Record<string, unknown>): Finding {
	return createFinding('hsts_preload', title, severity, detail, metadata);
}

/** A fact that could not be measured. Never `missingControl`: nothing was observed, so nothing is claimed absent. */
export function notAssessedFinding(title: string, reason: string, errorKind: string): Finding {
	return finding('info', title, `not assessed: ${reason}.`, { inconclusive: true, errorKind });
}

function notEligibleFinding(domain: string, eligibility: PreloadEligibility): Finding {
	return finding(
		'low',
		'Not eligible for the HSTS preload list',
		`${domain} cannot be submitted to the HSTS preload list yet: it is missing ${eligibility.missing.join('; ')}. Serve ${HEADER_EXAMPLE} on the apex over HTTPS and redirect plain HTTP to HTTPS on the same host. ${PRELOAD_COMMITMENT}`,
		{ eligible: false, missing: eligibility.missing.join('; ') },
	);
}

function eligibleNotSubmittedFinding(domain: string, eligibility: PreloadEligibility | null): Finding {
	const redirectNote = eligibility?.redirectsToHttps === null ? ' The HTTP-to-HTTPS redirect could not be measured, so confirm it separately.' : '';
	return finding(
		'info',
		'Eligible for the HSTS preload list, not submitted',
		`${domain} serves a header that meets the hstspreload.org rules but is not on the preload list. To submit it, enter the domain at ${PRELOAD_URL}?domain=${domain} and tick the confirmation. ${PRELOAD_COMMITMENT}${redirectNote}`,
		{ eligible: eligibility?.eligible ?? null, membership: 'unknown' },
	);
}

function notListedFinding(domain: string): Finding {
	return finding('info', 'Not on the HSTS preload list', `${domain} is not on the HSTS preload list, and its HSTS header could not be read to say whether it is eligible.`, { membership: 'unknown' });
}

function removalRiskFinding(domain: string, eligibility: PreloadEligibility): Finding {
	return finding(
		'medium',
		'HSTS preload removal risk',
		`${domain} is on the HSTS preload list but no longer meets the requirements: it is missing ${eligibility.missing.join('; ')}. hstspreload.org may remove a domain that stops meeting them, which drops the HTTPS-only protection browsers ship for it. Restore ${HEADER_EXAMPLE}.`,
		{ membership: 'preloaded', eligible: false, missing: eligibility.missing.join('; ') },
	);
}

function preloadedFinding(domain: string): Finding {
	return finding('info', 'Domain is on the HSTS preload list', `${domain} is on the HSTS preload list, so browsers connect to it over HTTPS before any first visit.`, { membership: 'preloaded', pass: true });
}

function pendingFinding(domain: string): Finding {
	return finding('info', 'HSTS preload submission pending', `${domain} has been submitted to the HSTS preload list and is waiting to be included in a browser release.`, { membership: 'pending' });
}

function rejectedFinding(domain: string): Finding {
	return finding(
		'low',
		'HSTS preload submission rejected',
		`hstspreload.org reports a rejected submission for ${domain}. Fix the header and redirect requirements, then resubmit at ${PRELOAD_URL}?domain=${domain}.`,
		{ membership: 'rejected' },
	);
}

type MembershipFinding = (domain: string, eligibility: PreloadEligibility | null) => Finding | null;

const MEMBERSHIP_FINDINGS: Record<PreloadStatus, MembershipFinding> = {
	preloaded: (domain, eligibility) => (eligibility?.eligible === false ? removalRiskFinding(domain, eligibility) : preloadedFinding(domain)),
	pending: (domain) => pendingFinding(domain),
	rejected: (domain) => rejectedFinding(domain),
	// A known-ineligible header already has its own finding; do not invite a submission that would fail.
	unknown: (domain, eligibility) => (eligibility === null ? notListedFinding(domain) : eligibility.eligible === false ? null : eligibleNotSubmittedFinding(domain, eligibility)),
};

function headerFinding(domain: string, observation: HstsObservation, eligibility: PreloadEligibility | null, membership: PreloadMembership): Finding | null {
	if (!observation.measured) return notAssessedFinding('HSTS header not assessed', observation.reason, 'header_unmeasured');
	// A preloaded domain with a failing header gets the removal-risk finding instead.
	if (membership.status === 'preloaded') return null;
	return eligibility?.eligible === false ? notEligibleFinding(domain, eligibility) : null;
}

function membershipFinding(domain: string, membership: PreloadMembership, eligibility: PreloadEligibility | null): Finding | null {
	if (membership.status === 'not_assessed') return notAssessedFinding('HSTS preload status not assessed', membership.reason, 'membership_unmeasured');
	return MEMBERSHIP_FINDINGS[membership.status](domain, eligibility);
}

/** Every finding for one domain. `redirectsToHttps` is `null` when the plain-HTTP leg was not measured. */
export function analyzeHstsPreload(domain: string, observation: HstsObservation, redirectsToHttps: boolean | null, membership: PreloadMembership): Finding[] {
	const eligibility = observation.measured ? assessPreloadEligibility(observation.header, { redirectsToHttps }) : null;
	const findings = [headerFinding(domain, observation, eligibility, membership), membershipFinding(domain, membership, eligibility)];
	return findings.filter((found): found is Finding => found !== null);
}
