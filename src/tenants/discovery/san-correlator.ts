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
 * Failure modes follow the bv-mcp tool-wrapper convention: this function
 * MUST NOT throw on network/rate-limit/timeout — only on programmer error
 * (invalid input). Callers can interrogate `queryStatus` instead.
 */

import { JSONParser } from '@streamparser/json-whatwg';
import { disposeUnreadResponseBody } from '../../lib/response-body';
import { safeFetch } from '../../lib/safe-fetch';
import { validateDomain } from '../../lib/sanitize';

/** Default request timeout (ms). */
const DEFAULT_TIMEOUT_MS = 15_000;

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
	/** Request timeout in ms (per attempt). Defaults to 15000. */
	timeoutMs?: number;
	/** Cap on the number of crt.sh entries that contribute to the result. Defaults to 200. */
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
	/** crt.sh `id` values of the certs that produced the matches (capped by maxCertsPerDomain). */
	certIds: number[];
	queryStatus: 'ok' | 'partial' | 'rate_limited' | 'timeout' | 'error';
}

/** A single crt.sh JSON response entry (subset we use). */
interface CrtShEntry {
	id?: number;
	name_value?: string;
	entry_timestamp?: string;
}

/**
 * Build the empty/error-shape result.
 */
function emptyResult(seedDomain: string, status: SanCorrelationResult['queryStatus']): SanCorrelationResult {
	return { seedDomain, coOwnedDomains: [], certIds: [], queryStatus: status };
}

/**
 * Extract sibling domains from a single SAN string.
 */
function extractSiblingsFromNameValue(nameValue: string, seedLower: string): string[] {
	const seedSuffix = `.${seedLower}`;
	const out: string[] = [];
	for (const rawSplit of nameValue.split(/[\n,]/)) {
		let host = rawSplit.trim().toLowerCase();
		if (!host) continue;
		if (host.startsWith('*.')) host = host.slice(2);
		if (!host) continue;
		if (host === seedLower) continue;
		if (host.endsWith(seedSuffix)) continue;
		const validation = validateDomain(host);
		if (!validation.valid) continue;
		out.push(host);
	}
	return out;
}

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
): Promise<SanCorrelationResult | null> {
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
	clearTimeout(timeoutId);

	if (!response.ok) {
		await disposeUnreadResponseBody(response);
		return null;
	}

	let data: CertstreamSansResponse;
	try {
		data = (await response.json()) as CertstreamSansResponse;
	} catch {
		return null;
	}
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
): Promise<SanCorrelationResult> {
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
	clearTimeout(timeoutId);

	if (response.status === 429) return emptyResult(seedLower, 'rate_limited');
	if (!response.ok) return emptyResult(seedLower, 'error');

	const body = response.body;
	if (!body) return emptyResult(seedLower, 'ok');

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
				const nameValue = entry.name_value;
				if (typeof nameValue === 'string' && nameValue) {
					for (const sibling of extractSiblingsFromNameValue(nameValue, seedLower)) {
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
			// Per-attempt timeout is min(configured, remaining-budget).
			const perAttemptTimeout = Math.min(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, remaining);
			const subResult = await correlateSans(candidate, {
				...options,
				timeoutMs: perAttemptTimeout,
			});
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

export async function correlateSans(seedDomain: string, options: SanCorrelationOptions = {}): Promise<SanCorrelationResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');

	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const maxCerts = options.maxCertsPerDomain ?? DEFAULT_MAX_CERTS;
	const fetchFn = options.fetchFn ?? safeFetch;
	const maxRetries = Math.max(0, options.maxRetries ?? DEFAULT_MAX_RETRIES);
	const initialBackoffMs = Math.max(0, options.initialBackoffMs ?? DEFAULT_INITIAL_BACKOFF_MS);
	const sleepFn = options.sleepFn ?? defaultSleep;

	// Path A: prefer the bv-certstream service binding when available. Single
	// attempt because the worker has its own cache + crt.sh-side timeout; if
	// it fails we drop straight to direct crt.sh (which has its own retry).
	if (options.certstream) {
		const csResult = await attemptCertstreamSans(seedLower, timeoutMs, options.certstream, options.certstreamAuthToken);
		if (csResult !== null) return csResult;
	}

	// Path B: direct crt.sh with jittered exponential-backoff retry.
	const url = `https://crt.sh/?q=${encodeURIComponent(seedLower)}&output=json`;

	let result: SanCorrelationResult = emptyResult(seedLower, 'error');
	for (let attempt = 0; attempt <= maxRetries; attempt++) {
		if (options.signal?.aborted) return result;
		result = await attemptCorrelation(seedLower, url, timeoutMs, maxCerts, fetchFn, options.signal);
		if (result.queryStatus === 'ok') return result;
		// Caller-abort during the attempt → do not retry, propagate the
		// timeout-shaped empty result.
		if (options.signal?.aborted) return result;
		if (attempt < maxRetries) {
			const base = initialBackoffMs * Math.pow(2, attempt);
			const jitterFactor = 0.5 + Math.random();
			await sleepFn(Math.floor(base * jitterFactor));
		}
	}
	return result;
}
