// SPDX-License-Identifier: BUSL-1.1

/**
 * The NON-SCORING "web posture" section of `scan_domain` (US-16 T10).
 *
 * Runs the six `NON_SCORING_CATEGORIES` checks from `@blackveil/dns-checks` (web content, CSP
 * quality, HSTS preload, HTTP redirect chain, security.txt, certificate posture) next to the scored
 * fan-out and returns them as a separate section. They are deliberately NOT in
 * `CHECK_DISPATCH` / `SCAN_CATEGORIES`: their results never enter `ScanDomainResult.checks`, so
 * they cannot reach the score, the grade, the category scores, the finding counts or the evidence
 * ratio. (The package filters these categories out of every scoring entry point as well; keeping
 * them out of the scored array is the first line, not the only one.)
 *
 * It must never delay or fail the scored result (SQ-487):
 *  - Opt-in. Only a caller that passes `webPosture: true` runs it, and only the scan_domain tool
 *    handler does. Every other `scanDomain` caller would discard it, so it makes no requests for them.
 *  - It starts after the scored fan-out has been dispatched, and at most
 *    {@link WEB_POSTURE_MAX_CONCURRENT_FETCHES} of its fetches are in flight at once. A Worker opens
 *    at most 6 connections at a time, so a hung web host cannot queue the scored checks behind it.
 *  - Once the scored result is ready it waits at most {@link WEB_POSTURE_GRACE_MS}. A check still
 *    running then is reported as not assessed (`notAssessedReason: 'deadline'`). It keeps running in
 *    the background and is cut off by the overall deadline below.
 *  - One overall deadline ({@link webPostureDeadlineMs}: 8 s, clamped to the fetch budget the scored
 *    raw-fetch checks already self-bound to) ends that background run. A check still running at the
 *    deadline is not assessed (`checkStatus: 'timeout'`), and the deadline aborts its subrequests.
 *  - Like the scored checks (SQ-498), a check shares an in-flight run but writes nothing to the
 *    per-check cache: the section is persisted only inside the scan-level cache entry.
 *  - Nothing here rejects: a thrown check becomes a not-assessed result.
 *  - One GET per host: the apex and www homepages are fetched once and handed to `web_content`,
 *    `csp_quality` and `hsts_preload` as `pages`.
 */

import {
	checkCertPosture,
	checkCspQuality,
	checkHstsPreload,
	checkHttpRedirect,
	checkSecurityTxt,
	checkWebContent,
	fetchPageCapped,
	withRobotsGate,
	type CappedPage,
	type CertMetadata,
	type FetchFunction,
} from '@blackveil/dns-checks';
import { createFinding, type CheckCategory, type CheckResult } from '../../lib/scoring';
import { safeFetch } from '../../lib/safe-fetch';
import { withAbortSignal } from '../../lib/abort-signal';
import { withRobotsFetchMemo, type RobotsFetchMemo } from '../../lib/robots-memo';
import { makeQueryDNS } from '../../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../../lib/dns-types';
import { certstreamHeaders } from '../../lib/certstream-headers';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../../lib/response-body';
import { isoOrUndefined, OWNED_INDEX_MAX_STALENESS_MS, parseOwnedIndexCoverage } from '../../lib/ct-coverage';
import { buildCheckCacheKey, runWithCache } from '../../lib/cache';
import { fetchBudgetFor } from '../../lib/fetch-budget';
import { Semaphore } from '../../lib/semaphore';
import type { ScanRuntimeOptions } from './post-processing';

/** Overall wall-clock for the whole section (ticket SQ-484). The caller clamps it to the per-check budget. */
export const WEB_POSTURE_DEADLINE_MS = 8_000;

/** How long the scored result waits for the section once the score is ready (SQ-487). */
export const WEB_POSTURE_GRACE_MS = 750;

/** Most section fetches in flight at once (SQ-487). Workers allow 6 open connections; the scored checks keep the rest. */
export const WEB_POSTURE_MAX_CONCURRENT_FETCHES = 2;

/** The six non-scoring categories, in the order the section reports them. */
export const WEB_POSTURE_CATEGORIES = [
	'web_content',
	'csp_quality',
	'hsts_preload',
	'http_redirect',
	'security_txt',
	'cert_posture',
] as const satisfies readonly CheckCategory[];

type WebPostureCategory = (typeof WEB_POSTURE_CATEGORIES)[number];

/** The section `scan_domain` returns next to (never inside) the scored checks. */
export interface WebPostureSection {
	/** Always true: nothing in `results` is scored, graded, or counted in the evidence ratio. */
	nonScoring: true;
	/** One result per category, in {@link WEB_POSTURE_CATEGORIES} order. */
	results: CheckResult[];
}

export interface WebPostureOptions {
	/** The scan's DNS options (shared query cache), used for cert_posture's CAA and TLSA lookups. */
	dnsOptions?: QueryDnsOptions;
	/** The scan-level abort signal. Composed with the section's own deadline. */
	signal?: AbortSignal;
	/** The scan's robots.txt fetch memo, so the target's robots.txt is fetched once per scan. */
	robotsMemo?: RobotsFetchMemo;
	/** Overall deadline in ms. Default {@link WEB_POSTURE_DEADLINE_MS}. */
	deadlineMs?: number;
	/** BV_CERTSTREAM binding (the bv-ct-index query API). Absent → cert_posture is not assessed. */
	certstream?: { fetch: typeof fetch };
	certstreamAuthToken?: string;
	/** Injectable clock (epoch ms) for the CT-index freshness rule. */
	nowMs?: number;
	/** Bypass the read of an already-cached per-check result (direct `check_*` calls write those). */
	forceRefresh?: boolean;
}

/** `WEB_POSTURE_ENABLED` kill switch. Default on; only the literal "false" turns the section off. */
export function parseWebPostureEnabled(raw: string | undefined): boolean {
	return raw?.trim().toLowerCase() !== 'false';
}

/** The scan options that decide whether the section runs. `webPosture` is the scan_domain tool's opt-in. */
export type WebPostureRequest = Pick<ScanRuntimeOptions, 'webPostureEnabled' | 'profile'> & { webPosture?: boolean };

/**
 * The caller asked for the section (`webPosture: true`), the kill switch is on, and the profile is
 * not the DNS-infrastructure one (which scans name servers only, so it has no web checks).
 */
export function wantsWebPosture(request: WebPostureRequest | undefined): boolean {
	return request?.webPosture === true && request.webPostureEnabled !== false && request.profile !== 'authoritative_dns_infra';
}

// ─── Fetch routing ───────────────────────────────────────────────────────────

function parseRequestUrl(input: RequestInfo | URL): URL | null {
	try {
		return new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
	} catch {
		return null;
	}
}

/** The scanned host and its www host: the only hosts this section treats as first party. */
function firstPartyHosts(domain: string): Set<string> {
	const host = domain.toLowerCase();
	return new Set(host.startsWith('www.') ? [host] : [host, `www.${host}`]);
}

/**
 * The fetch every web posture check uses.
 *
 * Routing copies check-ssl's first-party rule (SQ-60): `safeFetch` is https-only, so a plain-HTTP
 * request to the already-validated scanned apex or www host goes out raw. EVERYTHING else goes
 * through `safeFetch`: https to those hosts, hstspreload.org, and any redirect target. A plain-HTTP
 * hop to a foreign host (an attacker-controlled `Location:`) is therefore refused, never fetched.
 *
 * Requests to the first-party hosts are robots-gated like the existing scan probes, beneath the
 * scan's shared robots.txt memo. Third-party requests are not gated: the target's robots.txt has no
 * authority over them.
 *
 * @internal Exported for the routing regression.
 */
export function createWebPostureFetch(domain: string, signal?: AbortSignal, robotsMemo?: RobotsFetchMemo): FetchFunction {
	const firstParty = firstPartyHosts(domain);
	const isFirstParty = (url: URL | null): boolean => url !== null && firstParty.has(url.hostname);
	const routed: typeof fetch = (input, init) => {
		const url = parseRequestUrl(input);
		return url?.protocol === 'http:' && isFirstParty(url) ? fetch(input, init) : safeFetch(input, init);
	};
	const base = withAbortSignal(routed, signal);
	const gated = withRobotsGate(withRobotsFetchMemo(base, robotsMemo));
	return (url, init) => (isFirstParty(parseRequestUrl(url)) ? gated(url, init) : base(url, init));
}

/**
 * Let at most `limit` calls of `fetchFn` run at once; the rest wait in order. A waiting call is
 * dropped (rejects) when `signal` aborts.
 *
 * This wraps the whole routed fetch, robots gate included. A first-party call fetches robots.txt and
 * then the page inside one slot, one after the other. The slot is freed when the response arrives;
 * the checks read the (size-capped) body after that. The shared robots.txt memo sits beneath this
 * limit, so a scored check that reuses a robots.txt fetch the section started never waits here.
 *
 * @internal Exported for the concurrency regression.
 */
export function limitConcurrentFetches(fetchFn: FetchFunction, limit: number, signal?: AbortSignal): FetchFunction {
	const slots = new Semaphore(limit);
	return (url, init) => slots.run(() => fetchFn(url, init), signal);
}

// ─── Shared homepage GETs ────────────────────────────────────────────────────

interface HostPages {
	apex?: CappedPage | null;
	www?: CappedPage | null;
}

/**
 * One capped GET per host. A null page means the fetch failed; the checks do not retry it.
 *
 * `timeoutMs` is the per-fetch budget, and callers pass the section deadline (see `buildRunners`).
 */
async function fetchHomepages(domain: string, fetchFn: FetchFunction, timeoutMs: number): Promise<HostPages> {
	const apex = fetchPageCapped(`https://${domain}/`, fetchFn, { timeout: timeoutMs });
	if (domain.startsWith('www.')) return { apex: await apex };
	const www = fetchPageCapped(`https://www.${domain}/`, fetchFn, { timeout: timeoutMs });
	return { apex: await apex, www: await www };
}

// ─── cert_posture input from BV_CERTSTREAM /cert-meta ────────────────────────

const CERT_META_MAX_BODY_BYTES = 64 * 1024;
const MAX_TEXT_FIELD_CHARS = 200;
const MAX_KEY_BITS = 16_384;
const KNOWN_KEY_TYPES = new Set(['rsa', 'ec']);

/** What `checkCertPosture` is given. Null input means the check abstains (not assessed). */
export interface CertPostureInput {
	certificate: CertMetadata;
	/** The issuer as a `CN=` DN, so the package's CA table matches it on its CN patterns. */
	issuerDn: string | null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
	return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function textField(value: unknown): string | null {
	return typeof value === 'string' && value.trim() !== '' ? value.trim().slice(0, MAX_TEXT_FIELD_CHARS) : null;
}

function epochSecondsOf(value: unknown): number | null {
	const iso = isoOrUndefined(value);
	return iso === undefined ? null : Math.floor(Date.parse(iso) / 1000);
}

function keyBitsOf(value: unknown): number | null {
	return typeof value === 'number' && Number.isInteger(value) && value > 0 && value <= MAX_KEY_BITS ? value : null;
}

/** Key details only when bv-ct-index parsed a key type (CERT_DETAILS). Otherwise key strength stays not assessed. */
function keyDetailsOf(row: Record<string, unknown>): Pick<CertMetadata, 'keyType' | 'keyBits' | 'sigAlg'> {
	if (typeof row.keyType !== 'string' || !KNOWN_KEY_TYPES.has(row.keyType)) return {};
	return { keyType: row.keyType as 'rsa' | 'ec', keyBits: keyBitsOf(row.keyBits), sigAlg: textField(row.sigAlg) };
}

/**
 * The owned index answered and is current. bv-ct-index only holds precertificates logged since
 * `indexStartedAt` ("forward-from"), so a stale or legacy answer cannot say which certificate is the
 * newest: a renewal it has not seen would surface as a false "expired".
 */
function isCurrentOwnedIndex(raw: unknown, nowMs: number): boolean {
	const coverage = parseOwnedIndexCoverage(raw);
	if (coverage?.indexStartedAt === undefined || coverage.freshThrough === undefined) return false;
	return nowMs - Date.parse(coverage.freshThrough) <= OWNED_INDEX_MAX_STALENESS_MS;
}

/**
 * bv-ct-index's issuer is a bare CN (else O), e.g. "R11", "WE1". Present it as a `CN=` DN so the
 * package's CA table applies its CN patterns. Separators are blanked so the value cannot smuggle a
 * second DN attribute. An issuer the table does not know stays "not assessed", never a mismatch.
 */
function issuerDnOf(issuer: string | null): string | null {
	return issuer === null ? null : `CN=${issuer.replace(/[,/;]/g, ' ').trim()}`;
}

/**
 * Map a `/cert-meta` body onto the cert_posture input. Null (abstain) when the body is not an
 * owned, current index answer, or when it has no exact-name row (`notAfter` null): with forward-from
 * coverage a missing row means "not observed since the index started", never "no certificate".
 *
 * @internal Exported for the coverage and CN-issuer regressions.
 */
export function certPostureInputFromCertMeta(domain: string, body: unknown, nowMs: number): CertPostureInput | null {
	const row = asRecord(body);
	if (row === null || row.error || !isCurrentOwnedIndex(row.coverage, nowMs)) return null;
	const notAfter = epochSecondsOf(row.notAfter);
	if (notAfter === null) return null;
	const issuer = textField(row.issuer);
	const certificate: CertMetadata = {
		domain,
		issuer,
		notBefore: epochSecondsOf(row.notBefore),
		notAfter,
		sans: [],
		serial: textField(row.serial),
		source: 'ct',
		...keyDetailsOf(row),
	};
	return { certificate, issuerDn: issuerDnOf(issuer) };
}

/** Read `/cert-meta` for the scanned domain. Any failure, or an unbound binding, is null (abstain). */
async function loadCertPostureInput(domain: string, options: WebPostureOptions, signal: AbortSignal): Promise<CertPostureInput | null> {
	if (!options.certstream) return null;
	try {
		const response = await options.certstream.fetch(`https://certstream/cert-meta?domain=${encodeURIComponent(domain)}`, {
			headers: certstreamHeaders(options.certstreamAuthToken),
			signal,
		});
		if (!response.ok) {
			await disposeUnreadResponseBody(response);
			return null;
		}
		const body = await readJsonResponseCapped<unknown>(response, CERT_META_MAX_BODY_BYTES);
		return certPostureInputFromCertMeta(domain, body, options.nowMs ?? Date.now());
	} catch {
		return null;
	}
}

// ─── Running the section ─────────────────────────────────────────────────────

type CheckRunner = () => Promise<CheckResult>;

/**
 * `deadlineMs` is the section deadline, and it is the only clock a section fetch runs against.
 *
 * Every fetch here waits in {@link limitConcurrentFetches}, but the package checks start their own
 * budget (`AbortSignal.timeout`) before they call it. Left at their 5 s defaults, a hop that waited
 * behind slow fetches would reach its slot already aborted and read as the target failing. The
 * section signal still ends everything at the deadline and drops whatever is still queued, so the
 * budget handed to the checks is the deadline itself.
 */
function buildRunners(
	domain: string,
	fetchFn: FetchFunction,
	signal: AbortSignal,
	options: WebPostureOptions,
	deadlineMs: number,
): Record<WebPostureCategory, CheckRunner> {
	let homepages: Promise<HostPages> | undefined;
	const pages = (): Promise<HostPages> => (homepages ??= fetchHomepages(domain, fetchFn, deadlineMs));
	const certPosture = async (): Promise<CheckResult> => {
		const input = await loadCertPostureInput(domain, options, signal);
		return checkCertPosture(domain, makeQueryDNS(options.dnsOptions), input ?? { certificate: null });
	};
	return {
		web_content: async () => checkWebContent(domain, fetchFn, { pages: await pages() }),
		csp_quality: async () => checkCspQuality(domain, fetchFn, { pages: await pages() }),
		hsts_preload: async () => checkHstsPreload(domain, fetchFn, { pages: await pages() }),
		http_redirect: () => checkHttpRedirect(domain, fetchFn, { timeout: deadlineMs }),
		security_txt: () => checkSecurityTxt(domain, fetchFn, { timeout: deadlineMs }),
		cert_posture: certPosture,
	};
}

function notAssessedResult(
	category: WebPostureCategory,
	status: 'timeout' | 'error',
	detail: string,
	extraMetadata: Record<string, unknown> = {},
): CheckResult {
	const finding = createFinding(category, `${category.toUpperCase()} not assessed`, 'info', detail, {
		notAssessed: true,
		confidence: 'heuristic',
		...extraMetadata,
	});
	return { category, findings: [finding], score: 0, passed: false, partial: true, checkStatus: status };
}

/** Resolves (with null) once the signal aborts: the deadline, or the scan itself being cancelled. */
function whenAborted(signal: AbortSignal): Promise<null> {
	return new Promise((resolve) => {
		if (signal.aborted) resolve(null);
		signal.addEventListener('abort', () => resolve(null), { once: true });
	});
}

/**
 * Share the in-flight run for the same key, writing nothing to KV or memory (SQ-498; the same rule
 * as `runDedupedCheck` in scan/check-retry.ts). This copy predates that function's move out of
 * scan-domain.ts, when importing it here would have been a cycle; check-retry.ts does not import this
 * module. Two concurrent scans of one domain in an isolate therefore run each web posture check once.
 */
function dedupedRunner(domain: string, category: WebPostureCategory, run: CheckRunner, options: WebPostureOptions): CheckRunner {
	return () => runWithCache(buildCheckCacheKey(domain, category), run, undefined, undefined, options.forceRefresh, () => false, true);
}

async function settleCheck(
	category: WebPostureCategory,
	run: CheckRunner,
	cutoff: Promise<null>,
	deadlineMs: number,
): Promise<CheckResult> {
	try {
		const result = await Promise.race([run(), cutoff]);
		return result ?? notAssessedResult(category, 'timeout', `Did not complete within the ${deadlineMs / 1000}s web posture time limit.`);
	} catch {
		return notAssessedResult(category, 'error', 'The check failed before it produced a result.');
	}
}

/** A started section. No promise here ever rejects. */
export interface WebPostureRun {
	/** Each check's result as it settles, in {@link WEB_POSTURE_CATEGORIES} order. */
	checks: { category: WebPostureCategory; result: Promise<CheckResult> }[];
	/** The whole section, settled by the section deadline at the latest. */
	section: Promise<WebPostureSection>;
}

/**
 * Start the six non-scoring checks for `domain`. Every category is always present, either measured
 * or explicitly not assessed.
 */
export function startWebPosture(domain: string, options: WebPostureOptions = {}): WebPostureRun {
	const deadlineMs = options.deadlineMs ?? WEB_POSTURE_DEADLINE_MS;
	const deadline = new AbortController();
	const timer = setTimeout(() => deadline.abort(new DOMException('web posture deadline', 'TimeoutError')), deadlineMs);
	const signal = options.signal ? AbortSignal.any([deadline.signal, options.signal]) : deadline.signal;
	const fetchFn = limitConcurrentFetches(
		createWebPostureFetch(domain, signal, options.robotsMemo),
		WEB_POSTURE_MAX_CONCURRENT_FETCHES,
		signal,
	);
	const runners = buildRunners(domain, fetchFn, signal, options, deadlineMs);
	const cutoff = whenAborted(signal);
	const checks = WEB_POSTURE_CATEGORIES.map((category) => ({
		category,
		result: settleCheck(category, dedupedRunner(domain, category, runners[category], options), cutoff, deadlineMs),
	}));
	const section = Promise.all(checks.map((check) => check.result)).then((results): WebPostureSection => {
		clearTimeout(timer);
		// Every check has settled; cancel whatever a timed-out check left in flight.
		deadline.abort();
		return { nonScoring: true, results };
	});
	return { checks, section };
}

// ─── scan_domain integration ─────────────────────────────────────────────────

/** The per-scan state `scanDomain` shares with the section. */
export interface ScanWebPostureContext {
	scanDns: QueryDnsOptions;
	robotsMemo: RobotsFetchMemo;
	signal: AbortSignal;
	/** The scan's per-check budget; the section's deadline is the fetch share of it. */
	perCheckTimeoutMs: number;
}

/**
 * The section's deadline: {@link WEB_POSTURE_DEADLINE_MS}, clamped to `fetchBudgetFor(perCheck)`,
 * the network budget the scored raw-fetch checks (`ssl`, `http_security`) self-bound to on every
 * scan. The section probes the same hosts, so it cannot run past the point those scored checks are
 * already allowed to run to, and it lands before the per-check killer. 7250 ms at the 8 s default.
 */
export function webPostureDeadlineMs(perCheckTimeoutMs: number): number {
	return Math.min(WEB_POSTURE_DEADLINE_MS, fetchBudgetFor(perCheckTimeoutMs));
}

/**
 * Launch the section for a resolving domain, once the scored fan-out has been dispatched. Undefined
 * unless {@link wantsWebPosture}: the caller did not opt in, the kill switch is off, or the profile
 * is the DNS-infrastructure one.
 */
export function startScanWebPosture(
	domain: string,
	runtimeOptions: (WebPostureRequest & Pick<ScanRuntimeOptions, 'certstream' | 'certstreamAuthToken' | 'forceRefresh'>) | undefined,
	scan: ScanWebPostureContext,
): WebPostureRun | undefined {
	if (!wantsWebPosture(runtimeOptions)) return undefined;
	return startWebPosture(domain, {
		dnsOptions: scan.scanDns,
		signal: scan.signal,
		robotsMemo: scan.robotsMemo,
		deadlineMs: webPostureDeadlineMs(scan.perCheckTimeoutMs),
		certstream: runtimeOptions?.certstream,
		certstreamAuthToken: runtimeOptions?.certstreamAuthToken,
		forceRefresh: runtimeOptions?.forceRefresh,
	});
}

function deadlineResult(category: WebPostureCategory, graceMs: number): CheckResult {
	return notAssessedResult(
		category,
		'timeout',
		`Still running ${graceMs / 1000}s after the score was ready. The score is never held back for this section.`,
		{ notAssessedReason: 'deadline' },
	);
}

async function settleWithinGrace(check: WebPostureRun['checks'][number], grace: Promise<null>, graceMs: number): Promise<CheckResult> {
	return (await Promise.race([check.result, grace])) ?? deadlineResult(check.category, graceMs);
}

/**
 * Attach the section to the scored result, waiting at most `graceMs` from now (the moment the
 * scored result is ready). A check not finished by then is reported as not assessed with reason
 * "deadline". The run itself is handed to `waitUntil`, so those checks still finish in the
 * background. Nothing here can fail the scored result.
 */
export async function attachWebPosture<T extends object>(
	result: T,
	run: WebPostureRun | undefined,
	waitUntil?: (promise: Promise<unknown>) => void,
	graceMs: number = WEB_POSTURE_GRACE_MS,
): Promise<T & { webPosture?: WebPostureSection }> {
	if (run === undefined) return result;
	waitUntil?.(run.section);
	let timer: ReturnType<typeof setTimeout> | undefined;
	const grace = new Promise<null>((resolve) => {
		timer = setTimeout(() => resolve(null), graceMs);
	});
	try {
		const results = await Promise.all(run.checks.map((check) => settleWithinGrace(check, grace, graceMs)));
		return { ...result, webPosture: { nonScoring: true, results } };
	} catch {
		return result;
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Only a caller that wants the section (see {@link wantsWebPosture}) gets one. Everyone else has it
 * removed, including from a cached result written while the kill switch was on or by scan_domain.
 */
export function applyWebPostureSwitch<T extends { webPosture?: WebPostureSection }>(result: T, request: WebPostureRequest | undefined): T {
	if (wantsWebPosture(request) || result.webPosture === undefined) return result;
	const withoutSection = { ...result };
	delete withoutSection.webPosture;
	return withoutSection;
}

/**
 * A cached scan can answer this caller unless the caller wants the section and the cached result
 * has none, because a caller that skipped the section wrote it. That caller rescans: the scored
 * checks are re-run (SQ-498: they are not cached per check), and the new result, section included,
 * replaces the entry.
 */
export function canReplayCachedScan(cached: { webPosture?: WebPostureSection }, request: WebPostureRequest | undefined): boolean {
	return cached.webPosture !== undefined || !wantsWebPosture(request);
}
