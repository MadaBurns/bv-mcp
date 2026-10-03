// SPDX-License-Identifier: BUSL-1.1

/**
 * SAN-cert correlator (Phase-4 brand-discovery, tier-1 signal).
 *
 * Queries crt.sh for a seed domain, extracts every Subject Alternative Name
 * from the matched certificates, and returns the set of *sibling* co-owned
 * domains: not the seed itself, not subdomains of the seed (those are the
 * job of `discover_subdomains`), and not invalid hostnames.
 *
 * Adopted from the well-known technique used by `bit4woo/teemo`. Because CT
 * logs are append-only and global, a single wildcard or multi-domain cert
 * publicly correlates everything the customer renews together — a near-
 * deterministic ownership signal at zero query cost.
 *
 * Backends (a ladder, not a fan-out): the bv-certstream binding, then direct
 * crt.sh, then — when crt.sh could not answer the co-listing question (it failed,
 * or it answered with no siblings; see Path B) — Certspotter (#1189). Every
 * call returns a {@link CtCoverage} record of which backends were asked and what
 * each said, so `coOwnedDomains: []` is readable as "nothing found" vs "the
 * source that could have found it was throttled / restricted / never asked".
 *
 * Failure modes follow the bv-mcp tool-wrapper convention: this function
 * MUST NOT throw on network/rate-limit/timeout — only on programmer error
 * (invalid input). Callers can interrogate `queryStatus` instead.
 */

import { JSONParser } from '@streamparser/json-whatwg';
import type { CtCoverage, CtSourceAttempt, CtSourceOutcome } from '../../lib/ct-coverage';
import { buildCtCoverage } from '../../lib/ct-coverage';
import { isPublicSuffixApex } from '../../lib/public-suffix';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../../lib/response-body';
import { safeFetch } from '../../lib/safe-fetch';
import { validateDomain } from '../../lib/sanitize';
import { fetchCertspotterEntries } from '../../tools/discover-subdomains';

/**
 * Default WHOLE-CALL budget (ms): certstream + crt.sh + the Certspotter failover
 * all fit inside it. Callers with their own deadline pass `timeoutMs` explicitly.
 */
const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * Share of the call budget the crt.sh ladder (certstream binding + direct crt.sh
 * with every retry and backoff) may spend. The remaining 40% is RESERVED for the
 * Certspotter failover (#1189).
 *
 * ⚠️ DERIVED, not chosen — same lesson as #738 item 3 in `discover-subdomains.ts`:
 * when the first source was allowed to consume the whole timeout, the second was
 * structurally unreachable exactly when it was needed (crt.sh throttling).
 * Reserving the failover's slice up front is what makes it reachable.
 */
const CRTSH_BUDGET_SHARE = 0.6;

/**
 * Share of the crt.sh window the certstream binding may take, so a hung worker
 * cannot starve the direct crt.sh path of its whole slice.
 */
const CERTSTREAM_WINDOW_SHARE = 0.5;

/** Default cap on certs to consider per seed query. */
const DEFAULT_MAX_CERTS = 200;

/**
 * Signal Saturation: If we process this many certificates without discovering
 * a new unique sibling domain, we assume the signal is saturated and abort.
 */
const SATURATION_THRESHOLD = 100;

/**
 * Hard safety cap on the raw stream bytes to prevent runaway resource usage.
 */
const MAX_STREAM_BYTES = 25 * 1024 * 1024;

/** Maximum service-binding `/sans` payload retained before direct-source fallback. */
const MAX_CERTSTREAM_BODY_BYTES = 5 * 1024 * 1024;

/**
 * Default retries on transient failures (error / rate_limited / timeout).
 * crt.sh is throttled per-IP and intermittently 5xx's on tier-1 brand queries;
 * 2 retries with backoff is enough to absorb a single throttle window without
 * blowing the SAN signal's contribution to the orchestrator.
 */
const DEFAULT_MAX_RETRIES = 2;

/** Default initial backoff in ms; doubles each retry with ±50% jitter. */
const DEFAULT_INITIAL_BACKOFF_MS = 500;

export interface SanCorrelationOptions {
	/**
	 * WHOLE-CALL budget in ms (defaults to 15000), not a per-attempt timeout: the
	 * crt.sh ladder gets {@link CRTSH_BUDGET_SHARE} of it and the Certspotter
	 * failover the rest. Callers pass the budget their arm actually has so the two
	 * cannot disagree.
	 */
	timeoutMs?: number;
	/** Cap on the number of CT entries (crt.sh or Certspotter) that contribute to the result. Defaults to 200. */
	maxCertsPerDomain?: number;
	/** Override the underlying fetch implementation (used for testing). Defaults to `safeFetch`. */
	fetchFn?: typeof fetch;
	/** Max retry attempts on transient failures (error/rate_limited/timeout). Default 2 (3 total attempts). Set to 0 to disable. */
	maxRetries?: number;
	/** Initial backoff in ms; doubles each retry with ±50% jitter. Default 500. */
	initialBackoffMs?: number;
	/** Sleep function override (test hook to skip real timers). */
	sleepFn?: (ms: number) => Promise<void>;
	/**
	 * Optional bv-certstream-worker service binding. When provided, queries are
	 * routed through the worker's `/sans` endpoint (Cloudflare egress + cache)
	 * before falling back to direct crt.sh. Mirrors the pattern in
	 * `discover-subdomains.ts` (which uses the `/enumerate` endpoint for
	 * subdomain enumeration). Distinct endpoint because subdomain vs sibling
	 * discovery use different crt.sh query shapes and different result filters.
	 */
	certstream?: { fetch: typeof fetch };
	/**
	 * Bearer token for the bv-certstream-worker `/sans` endpoint. The worker's
	 * admin routes require `Authorization: Bearer <token>` — omitting it makes the
	 * `/sans` call 401 and silently fall through to the (rate-limited) direct
	 * crt.sh path, which fails for large brands. Mirrors `discover-subdomains.ts`
	 * (`queryCertstreamEndpoint`'s `certstreamAuthToken`).
	 */
	certstreamAuthToken?: string;
	/**
	 * SSLMate Cert Spotter API token, sent as `Authorization: Bearer` on the
	 * Certspotter failover. Absent → unauthenticated (still functional, but on a
	 * per-IP per-hour quota that a batch sweep exhausts).
	 */
	certspotterToken?: string;
	/**
	 * Set true to never consult Certspotter on this call. `correlateSansRecursive`
	 * sets it once a sibling call saw Certspotter throttle (#735: a 429 means the
	 * shared quota is spent, and retrying extends the lockout).
	 */
	skipCertspotter?: boolean;
	/**
	 * Caller-supplied abort signal. Cancels in-flight crt.sh fetches when the
	 * audit budget fires — the JSON parse for tier-1 brands (mega-portfolio-scale)
	 * is the single largest CPU sink in the orchestrator, so cancelling it
	 * mid-stream is what lets the consumer's catch handler win the race
	 * against CF's CPU kill.
	 */
	signal?: AbortSignal;
}

/** Response shape from bv-certstream-worker `/sans` endpoint. */
interface CertstreamSansResponse {
	domain: string;
	names: string[];
	certificateCount: number;
	timedOut: boolean;
	cached: boolean;
	error?: string;
}

export interface SanCorrelationResult {
	seedDomain: string;
	/** Deduped, alphabetically sorted, lowercase ASCII sibling domains. */
	coOwnedDomains: string[];
	/** crt.sh `id` values of the certs that produced the matches (capped by maxCertsPerDomain). Empty for Certspotter/certstream answers. */
	certIds: number[];
	/**
	 * Across ALL consulted backends (#1189):
	 *  - `ok`      — at least one backend answered (an answer of "no siblings" counts, so an
	 *                 empty list with a degraded `coverage` is still `ok`);
	 *  - `partial` — the answering backend reported truncation (certstream `timedOut` with
	 *                 data, or Certspotter pagination cut short);
	 *  - `timeout` | `rate_limited` | `error` — EVERY consulted backend failed. The value is
	 *                 the primary (certstream/crt.sh) failure; what Certspotter said is in
	 *                 `coverage`.
	 */
	queryStatus: 'ok' | 'partial' | 'rate_limited' | 'timeout' | 'error';
	/**
	 * What was asked and what each source said. `coOwnedDomains: []` must be read
	 * through this: "crt.sh timed out and Certspotter was restricted / not consulted /
	 * answered empty" is a different statement from "no sibling certificates exist".
	 */
	coverage: CtCoverage;
}

/** What one backend produced, before the coverage record is attached. */
type SanAnswer = Omit<SanCorrelationResult, 'coverage'>;

/** A single crt.sh JSON response entry (subset we use). */
interface CrtShEntry {
	id?: number;
	name_value?: string;
	/** The certificate's CN — the one cross-apex signal crt.sh's search can give (see Path B). */
	common_name?: string;
	entry_timestamp?: string;
}

/**
 * Build the empty/error-shape result.
 */
function emptyResult(seedDomain: string, status: SanCorrelationResult['queryStatus']): SanAnswer {
	return { seedDomain, coOwnedDomains: [], certIds: [], queryStatus: status };
}

/**
 * Extract sibling domains from a single SAN string (crt.sh `name_value`, which
 * Certspotter entries are normalized into by joining `dns_names` with newlines).
 */
function extractSiblingsFromNameValue(nameValue: string, seedLower: string): string[] {
	return filterSiblingNames(nameValue.split(/[\n,]/), seedLower);
}

/**
 * THE SAN → co-owned-domain filter, shared by every backend: drop the seed, drop
 * subdomains of the seed, unwrap wildcards (`*.foo.com` → `foo.com`), drop invalid
 * hostnames. Returns deduped, sorted hosts.
 */
function filterSiblingNames(names: readonly unknown[], seedLower: string): string[] {
	const seedSuffix = `.${seedLower}`;
	const siblings = new Set<string>();
	for (const raw of names) {
		let host = String(raw).trim().toLowerCase();
		if (!host) continue;
		if (host.startsWith('*.')) host = host.slice(2);
		if (!host) continue;
		if (host === seedLower) continue;
		if (host.endsWith(seedSuffix)) continue;
		if (!validateDomain(host).valid) continue;
		siblings.add(host);
	}
	return Array.from(siblings).sort();
}

function defaultSleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Try the bv-certstream-worker `/sans` endpoint. Returns null on failure so the
 * outer fallback can switch to direct crt.sh.
 *
 * Failure modes folded into null: non-OK status, fetch throw, malformed JSON,
 * `error` field set, or `timedOut: true`. The worker handles its own crt.sh
 * timeout (default 30s, longer than bv-mcp's 15s) — we apply a single
 * outer timeout here matching the caller's budget.
 */
async function attemptCertstreamSans(
	seedLower: string,
	timeoutMs: number,
	certstream: { fetch: typeof fetch },
	certstreamAuthToken?: string,
): Promise<SanAnswer | null> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

	let response: Response;
	try {
		response = await certstream.fetch(`https://certstream/sans?domain=${encodeURIComponent(seedLower)}`, {
			...(certstreamAuthToken ? { headers: { Authorization: `Bearer ${certstreamAuthToken}` } } : {}),
			signal: controller.signal,
		});
	} catch {
		clearTimeout(timeoutId);
		return null;
	}

	if (!response.ok) {
		await disposeUnreadResponseBody(response);
		clearTimeout(timeoutId);
		return null;
	}

	const parsed = await readJsonResponseCapped<CertstreamSansResponse>(response, MAX_CERTSTREAM_BODY_BYTES).finally(() =>
		clearTimeout(timeoutId),
	);
	if (parsed === null) return null;
	const data = parsed;
	if (data.error || !Array.isArray(data.names)) return null;

	// Apply the same sibling filter as the direct crt.sh path: drop the seed,
	// drop subdomains of the seed, drop wildcards (`*.foo.com` → `foo.com`),
	// drop invalid hostnames. The worker doesn't pre-filter — sibling-vs-subdomain
	// semantics live in the consumer.
	const siblings = filterSiblingNames(data.names, seedLower);
	if (data.timedOut) {
		return siblings.length > 0
			? {
					seedDomain: seedLower,
					coOwnedDomains: siblings,
					certIds: [],
					queryStatus: 'partial',
				}
			: null;
	}

	return {
		seedDomain: seedLower,
		coOwnedDomains: siblings,
		certIds: [],
		queryStatus: 'ok',
	};
}

/**
 * Single fetch+parse attempt against crt.sh. Never throws on transient
 * failures — the outer `correlateSans` decides whether to retry based on
 * the returned `queryStatus`.
 */
async function attemptCorrelation(
	seedLower: string,
	url: string,
	timeoutMs: number,
	maxCerts: number,
	fetchFn: typeof fetch,
	callerSignal?: AbortSignal,
): Promise<SanAnswer> {
	if (callerSignal?.aborted) return emptyResult(seedLower, 'timeout');
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
	// Compose internal timeout + caller signal. Either firing cancels the fetch
	// — and critically aborts the streaming JSON parse below before it consumes
	// the worker's CPU budget chewing through a multi-MB crt.sh response.
	const fetchSignal = callerSignal ? AbortSignal.any([controller.signal, callerSignal]) : controller.signal;

	let response: Response;
	try {
		response = await fetchFn(url, { signal: fetchSignal, redirect: 'manual' });
	} catch (err) {
		clearTimeout(timeoutId);
		if (callerSignal?.aborted) return emptyResult(seedLower, 'timeout');
		if (err instanceof Error && err.name === 'AbortError') return emptyResult(seedLower, 'timeout');
		return emptyResult(seedLower, 'error');
	}

	if (response.status === 429) {
		await disposeUnreadResponseBody(response);
		clearTimeout(timeoutId);
		return emptyResult(seedLower, 'rate_limited');
	}
	if (!response.ok) {
		await disposeUnreadResponseBody(response);
		clearTimeout(timeoutId);
		return emptyResult(seedLower, 'error');
	}

	const body = response.body;
	if (!body) {
		clearTimeout(timeoutId);
		return emptyResult(seedLower, 'ok');
	}

	const siblings = new Set<string>();
	const certIds: number[] = [];
	let certsProcessed = 0;
	let certsSinceNewDomain = 0;
	let bytesProcessed = 0;
	const parser = new JSONParser({ paths: ['$.*'] });

	const byteCounter = new TransformStream<Uint8Array, Uint8Array>({
		transform(chunk, ctrl) {
			bytesProcessed += chunk.length;
			if (bytesProcessed > MAX_STREAM_BYTES) {
				ctrl.error(new Error('Stream size limit exceeded'));
			} else {
				ctrl.enqueue(chunk);
			}
		},
	});

	const reader = body.pipeThrough(byteCounter).pipeThrough(parser).getReader();

	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;

			const entries = Array.isArray(value.value) ? value.value : [value.value];

			for (const entryRaw of entries) {
				const entry = entryRaw as CrtShEntry;
				if (!entry) continue;
				certsProcessed++;

				let foundNew = false;
				if (typeof entry.id === 'number') certIds.push(entry.id);
				for (const field of [entry.name_value, entry.common_name]) {
					if (typeof field !== 'string' || !field) continue;
					for (const sibling of extractSiblingsFromNameValue(field, seedLower)) {
						if (!siblings.has(sibling)) {
							siblings.add(sibling);
							foundNew = true;
						}
					}
				}

				if (foundNew) {
					certsSinceNewDomain = 0;
				} else {
					certsSinceNewDomain++;
				}

				if (certsProcessed >= maxCerts || certsSinceNewDomain >= SATURATION_THRESHOLD) {
					await reader.cancel();
					break;
				}
			}
		}
	} catch (err) {
		clearTimeout(timeoutId);
		if (controller.signal.aborted || callerSignal?.aborted) return emptyResult(seedLower, 'timeout');
		if (err instanceof Error && err.message === 'Stream size limit exceeded') {
			return {
				seedDomain: seedLower,
				coOwnedDomains: Array.from(siblings).sort(),
				certIds,
				queryStatus: 'ok',
			};
		}
		return emptyResult(seedLower, 'error');
	}

	clearTimeout(timeoutId);
	return {
		seedDomain: seedLower,
		coOwnedDomains: Array.from(siblings).sort(),
		certIds,
		queryStatus: 'ok',
	};
}

/**
 * Correlate co-owned sibling domains for a seed via crt.sh SAN clustering.
 * Uses a streaming JSON parser to handle large certificate histories (Tier-1 brands).
 *
 * Retries on transient `error` / `rate_limited` / `timeout` statuses with
 * jittered exponential backoff (default: 2 retries, 500ms base). crt.sh is
 * IP-throttled and intermittently 5xx's on tier-1 brand queries; without
 * retry, a single throttle window silently drops the SAN signal for that
 * target. Partial-success (stream cap hit) is `ok` and never retried.
 */
/** Options for the second-order recursive SAN expansion. */
export interface SanRecursiveOptions extends SanCorrelationOptions {
	/** Hard cap on the number of first-order candidates to probe in the second pass. Defaults to 20. */
	maxCandidates?: number;
	/** Parallel concurrency limit for second-order crt.sh queries. Defaults to 8. */
	concurrency?: number;
	/** Total wall-clock budget for the entire recursive pass (ms). Defaults to 30000. */
	totalBudgetMs?: number;
}

/** Per-candidate cross-confirmation outcome from the second-order pass. */
export interface SanRecursiveCandidate {
	/** The first-order sibling whose SANs we queried. */
	candidate: string;
	/** crt.sh `id` values of the certs that surfaced the seed in the candidate's SAN list. */
	certIds: number[];
	/** Final query status for the second-order call. */
	queryStatus: SanCorrelationResult['queryStatus'];
}

/** Aggregate result of the recursive SAN expansion. */
export interface SanRecursiveResult {
	seedDomain: string;
	/** Candidates whose own crt.sh SAN listing includes the original seed (cross-confirmation). */
	crossConfirmed: SanRecursiveCandidate[];
	/** All candidates probed (whether or not they cross-confirmed) — for telemetry/debug. */
	probed: string[];
	queryStatus: 'ok' | 'budget_exceeded' | 'error';
}

/**
 * Second-order SAN expansion pass.
 *
 * For each first-order sibling, queries crt.sh again with that sibling as the
 * seed; if the ORIGINAL seed appears in the sibling's SAN list, that's a
 * cross-cert mutual SAN inclusion — near-deterministic ownership evidence
 * that a single first-order hit cannot establish on its own.
 *
 * Bounded by `maxCandidates` (top-N by shortest registrable apex first —
 * shorter apex tends to be the canonical brand domain, which has the densest
 * SAN graph), `concurrency` (parallel crt.sh queries), and `totalBudgetMs`
 * (wall-clock cap; partial results still returned with `queryStatus:
 * 'budget_exceeded'`).
 *
 * Mutates nothing; never throws on transient failure. Each second-order query
 * reuses `attemptCertstreamSans` (preferred) → direct crt.sh (fallback) just
 * like `correlateSans`, so retry/backoff/saturation logic is shared.
 */
export async function correlateSansRecursive(
	seedDomain: string,
	firstOrderCandidates: readonly string[],
	options: SanRecursiveOptions = {},
): Promise<SanRecursiveResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const maxCandidates = Math.max(0, options.maxCandidates ?? 20);
	const concurrency = Math.max(1, options.concurrency ?? 8);
	const totalBudgetMs = Math.max(1, options.totalBudgetMs ?? 30_000);

	// Normalise + dedupe + filter invalid + drop the seed/its subdomains.
	const seedSuffix = `.${seedLower}`;
	const normalised = new Set<string>();
	for (const raw of firstOrderCandidates) {
		const host = String(raw).trim().toLowerCase().replace(/\.$/, '');
		if (!host || host === seedLower) continue;
		if (host.endsWith(seedSuffix)) continue;
		if (!validateDomain(host).valid) continue;
		normalised.add(host);
	}
	// Sort by shortest registrable apex first (then lexicographic) — shorter
	// apex domains tend to be canonical brand siblings with the densest SAN
	// graph (e.g. `github.io` before `githubusercontent-staging-edge.com`).
	const sorted = Array.from(normalised).sort((a, b) => a.length - b.length || a.localeCompare(b));
	const probedList = sorted.slice(0, maxCandidates);

	if (probedList.length === 0) {
		return { seedDomain: seedLower, crossConfirmed: [], probed: [], queryStatus: 'ok' };
	}

	const deadline = Date.now() + totalBudgetMs;
	const crossConfirmed: SanRecursiveCandidate[] = [];
	let budgetExceeded = false;

	let cursor = 0;
	let certspotterThrottled = false;
	async function worker(): Promise<void> {
		while (true) {
			if (options.signal?.aborted) {
				budgetExceeded = true;
				return;
			}
			const idx = cursor++;
			if (idx >= probedList.length) return;
			const remaining = deadline - Date.now();
			if (remaining <= 0) {
				budgetExceeded = true;
				return;
			}
			const candidate = probedList[idx];
			// `timeoutMs` is the correlator's WHOLE-CALL budget (crt.sh ladder + Certspotter
			// failover), so a candidate can never outlive the arm's remaining budget.
			const perCallTimeout = Math.min(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, remaining);
			const subResult = await correlateSans(candidate, {
				...options,
				timeoutMs: perCallTimeout,
				...(certspotterThrottled ? { skipCertspotter: true } : {}),
			});
			if (subResult.coverage.perSource.some((c) => c.source === 'certspotter' && c.outcome === 'rate_limited')) {
				certspotterThrottled = true;
			}
			if (subResult.queryStatus !== 'ok') continue;
			if (subResult.coOwnedDomains.includes(seedLower)) {
				crossConfirmed.push({
					candidate,
					certIds: subResult.certIds.slice(0, 5),
					queryStatus: subResult.queryStatus,
				});
			}
		}
	}

	const workerCount = Math.min(concurrency, probedList.length);
	await Promise.all(Array.from({ length: workerCount }, () => worker()));

	return {
		seedDomain: seedLower,
		crossConfirmed,
		probed: probedList,
		queryStatus: budgetExceeded ? 'budget_exceeded' : 'ok',
	};
}

/** Fixed ladder order, so `perSource` reads in attempt order whatever order they were recorded in. */
const SAN_SOURCE_ORDER = ['certstream', 'crtsh', 'certspotter'] as const;

/** Coverage outcome for a crt.sh / certstream answer. A clean answer naming no siblings is `empty`, not `ok`. */
function answerOutcome(answer: SanAnswer): CtSourceOutcome {
	switch (answer.queryStatus) {
		case 'ok':
		case 'partial':
			return answer.coOwnedDomains.length > 0 ? 'ok' : 'empty';
		case 'rate_limited':
			return 'rate_limited';
		case 'timeout':
			return 'timeout';
		default:
			return 'error';
	}
}

/**
 * Certspotter failover (#1189). Reuses `fetchCertspotterEntries` from
 * `discover-subdomains.ts` — one HTTP/pagination/403-classification implementation
 * for both tools — and feeds its entries through the SAME sibling filter crt.sh
 * uses. Never throws; the fetch helper folds every failure into an outcome.
 */
async function attemptCertspotter(
	seedLower: string,
	timeoutMs: number,
	deadlineMs: number,
	maxCerts: number,
	fetchFn: typeof fetch,
	certspotterToken: string | undefined,
	callerSignal?: AbortSignal,
): Promise<{ outcome: CtSourceOutcome; siblings: string[]; truncated: boolean }> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
	const signal = callerSignal ? AbortSignal.any([controller.signal, callerSignal]) : controller.signal;
	try {
		const result = await fetchCertspotterEntries(seedLower, signal, {
			fetchFn,
			deadlineMs,
			...(certspotterToken ? { certspotterToken } : {}),
		});
		const names: string[] = [];
		for (const entry of result.entries.slice(0, maxCerts)) {
			if (typeof entry.name_value === 'string') names.push(...entry.name_value.split(/[\n,]/));
		}
		const siblings = filterSiblingNames(names, seedLower);
		const answered = result.outcome === 'ok' || result.outcome === 'empty';
		return {
			outcome: answered && siblings.length === 0 ? 'empty' : result.outcome,
			siblings,
			truncated: answered && result.enumerationComplete === false,
		};
	} finally {
		clearTimeout(timeoutId);
	}
}

/**
 * Correlate co-owned sibling domains for a seed. Ladder: bv-certstream binding →
 * direct crt.sh (jittered-backoff retries) → Certspotter, the last ONLY when the
 * first two could not answer (#1189). Never throws on transient failure.
 *
 * `options.timeoutMs` is the WHOLE-CALL budget: certstream + crt.sh share
 * {@link CRTSH_BUDGET_SHARE} of it (retries and backoff included) so the Certspotter
 * attempt is always reachable inside the budget.
 */
export async function correlateSans(seedDomain: string, options: SanCorrelationOptions = {}): Promise<SanCorrelationResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');

	const totalBudgetMs = Math.max(1, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
	const startedAt = Date.now();
	const deadline = startedAt + totalBudgetMs;
	const crtshWindowMs = Math.floor(totalBudgetMs * CRTSH_BUDGET_SHARE);
	const crtshDeadline = startedAt + crtshWindowMs;
	const maxCerts = options.maxCertsPerDomain ?? DEFAULT_MAX_CERTS;
	const fetchFn = options.fetchFn ?? safeFetch;
	const maxRetries = Math.max(0, options.maxRetries ?? DEFAULT_MAX_RETRIES);
	const initialBackoffMs = Math.max(0, options.initialBackoffMs ?? DEFAULT_INITIAL_BACKOFF_MS);
	const sleepFn = options.sleepFn ?? defaultSleep;

	// Per-source attempt log → coverage record (same shape discover_subdomains builds).
	const attempts = new Map<string, CtSourceAttempt>();
	const record = (source: string, outcome: CtSourceOutcome, contributed: boolean, indexExhausted?: boolean): void => {
		attempts.set(source, { source, outcome, contributed, ...(indexExhausted === undefined ? {} : { indexExhausted }) });
	};
	const withCoverage = (answer: SanAnswer): SanCorrelationResult => ({
		...answer,
		coverage: buildCtCoverage(SAN_SOURCE_ORDER.filter((name) => attempts.has(name)).map((name) => attempts.get(name) as CtSourceAttempt)),
	});

	// #1004: Certspotter refuses EVERY query for a public-suffix apex with a
	// categorical `not_allowed_by_plan` 403. Record that up front — a record only,
	// no fetch is spent re-observing it — so it is present whichever path returns.
	const pslApex = isPublicSuffixApex(seedLower);
	if (pslApex) record('certspotter', 'provider_restricted', false);

	// Path A: prefer the bv-certstream service binding when available. Single
	// attempt because the worker has its own cache + crt.sh-side timeout; if
	// it fails we drop straight to direct crt.sh (which has its own retry).
	if (options.certstream) {
		const certstreamTimeoutMs = Math.min(crtshDeadline - Date.now(), Math.floor(crtshWindowMs * CERTSTREAM_WINDOW_SHARE));
		if (certstreamTimeoutMs > 0) {
			const csResult = await attemptCertstreamSans(seedLower, certstreamTimeoutMs, options.certstream, options.certstreamAuthToken);
			if (csResult !== null) {
				record('certstream', answerOutcome(csResult), csResult.coOwnedDomains.length > 0, csResult.queryStatus === 'ok');
				return withCoverage(csResult);
			}
			// `attemptCertstreamSans` folds every failure into null, so the reason is unknown.
			record('certstream', 'error', false);
		}
	}

	// Path B: direct crt.sh with jittered exponential-backoff retry, confined to
	// the crt.sh window so the Certspotter failover below stays reachable.
	//
	// ⚠️ STRUCTURAL LIMIT (SQ-302 / #1189): crt.sh's JSON search lists in `name_value`
	// ONLY the names that matched the query, never the certificate's full SAN list.
	// So this path can almost never surface a sibling under a different apex — an
	// `ok` with zero siblings means "crt.sh cannot answer the co-listing question",
	// NOT "no sibling certificates exist". The CN (`common_name`) is the one
	// cross-apex signal it does give, hence it is filtered alongside `name_value`.
	// Certspotter's `dns_names` carries the full list, which is why an empty crt.sh
	// answer falls through to Path C instead of returning.
	const url = `https://crt.sh/?q=${encodeURIComponent(seedLower)}&output=json`;

	let result: SanAnswer = emptyResult(seedLower, 'error');
	let crtshAttempted = false;
	for (let attempt = 0; attempt <= maxRetries; attempt++) {
		if (options.signal?.aborted) break;
		const remainingMs = crtshDeadline - Date.now();
		if (remainingMs <= 0) {
			if (!crtshAttempted) result = emptyResult(seedLower, 'timeout');
			break;
		}
		crtshAttempted = true;
		result = await attemptCorrelation(seedLower, url, remainingMs, maxCerts, fetchFn, options.signal);
		if (result.queryStatus === 'ok') break;
		// Caller-abort during the attempt → do not retry, propagate the
		// timeout-shaped empty result.
		if (options.signal?.aborted) break;
		if (attempt < maxRetries) {
			const base = initialBackoffMs * Math.pow(2, attempt);
			const jitterFactor = 0.5 + Math.random();
			const backoffMs = Math.floor(base * jitterFactor);
			// A backoff that would outlast the crt.sh window only eats the failover's slice.
			if (Date.now() + backoffMs >= crtshDeadline) break;
			await sleepFn(backoffMs);
		}
	}
	if (crtshAttempted) record('crtsh', answerOutcome(result), result.coOwnedDomains.length > 0);
	// crt.sh revealed a sibling (via a CN under another apex): no second source needed.
	if (result.queryStatus === 'ok' && result.coOwnedDomains.length > 0) return withCoverage(result);

	// Path C: Certspotter — after certstream (if any) returned nothing AND crt.sh
	// either failed or could not answer the co-listing question (zero siblings).
	// Never in parallel, never for a public-suffix apex, never once the caller has
	// cancelled.
	if (!pslApex && !options.skipCertspotter && !options.signal?.aborted) {
		const remainingMs = deadline - Date.now();
		if (remainingMs > 0) {
			const cs = await attemptCertspotter(seedLower, remainingMs, deadline, maxCerts, fetchFn, options.certspotterToken, options.signal);
			const answered = cs.outcome === 'ok' || cs.outcome === 'empty';
			record('certspotter', cs.outcome, cs.siblings.length > 0, answered ? !cs.truncated : undefined);
			if (answered) {
				return withCoverage({
					seedDomain: seedLower,
					coOwnedDomains: cs.siblings,
					certIds: [],
					queryStatus: cs.truncated ? 'partial' : 'ok',
				});
			}
		}
	}
	// Certspotter did not answer (or was not consulted): report crt.sh's own answer —
	// `ok` with no siblings, or its failure; `coverage` names what the rest said.
	return withCoverage(result);
}
