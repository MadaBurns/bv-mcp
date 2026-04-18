// SPDX-License-Identifier: BUSL-1.1

import { DNS_TIMEOUT_MS, DNS_RETRIES, DNS_CONFIRM_WITH_SECONDARY_ON_EMPTY, DOH_EDGE_CACHE_TTL, DNS_RETRY_BASE_DELAY_MS } from './config';
import { type DohResponse, type DohOutcome, type QueryDnsOptions, RecordType, type RecordTypeName } from './dns-types';
import { DohResponseSchema } from '../schemas/dns';
import { logError } from './log';
import type { Semaphore } from './semaphore';

const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const GOOGLE_DOH_ENDPOINT = 'https://dns.google/resolve';

function buildDohUrl(endpoint: string, domain: string, type: RecordTypeName, dnssecCheck: boolean): string {
	const params = new URLSearchParams({
		name: domain,
		type,
		...(dnssecCheck ? { cd: '0' } : {}),
	});

	return `${endpoint}?${params.toString()}`;
}

function hasTypedAnswers(response: DohResponse, type: RecordTypeName): boolean {
	return (response.Answer ?? []).some((answer) => answer.type === RecordType[type]);
}

function retryDelay(attempt: number): Promise<void> {
	return new Promise((r) => setTimeout(r, DNS_RETRY_BASE_DELAY_MS * (attempt + 1) + Math.random() * 50));
}

/**
 * Fetch a DoH response and classify the outcome. The discriminated return
 * type lets callers distinguish transport-level failures (timeout, network,
 * parse, http) from "no records" results (a valid `ok` with empty Answer[]).
 *
 * @param token - Optional auth token sent as `X-BV-Token` (for custom secondary resolvers).
 * @param useEdgeCache - If true, attaches Cloudflare `cf` cache directive. Omit for external origins.
 */
export async function fetchDohOutcome(
	url: string,
	timeoutMs: number,
	opts?: { token?: string; useEdgeCache?: boolean; semaphore?: Semaphore },
): Promise<DohOutcome> {
	try {
		const headers: Record<string, string> = { Accept: 'application/dns-json' };
		if (opts?.token) headers['X-BV-Token'] = opts.token;
		const doFetch = () =>
			fetch(url, {
				method: 'GET',
				headers,
				signal: AbortSignal.timeout(timeoutMs),
				...(opts?.useEdgeCache ? { cf: { cacheTtl: DOH_EDGE_CACHE_TTL, cacheEverything: true } } : {}),
			});
		const response = opts?.semaphore ? await opts.semaphore.run(doFetch) : await doFetch();
		if (!response.ok) {
			logError('DNS fetch non-2xx', {
				severity: 'warn',
				category: 'dns-transport',
				details: { url: url.replace(/name=[^&]+/, 'name=<domain>'), status: response.status },
			});
			return { kind: 'error', reason: 'http' };
		}
		const data = await response.json();
		const parsed = DohResponseSchema.safeParse(data);
		if (!parsed.success) {
			logError('DNS parse failure', {
				severity: 'warn',
				category: 'dns-transport',
				details: { url: url.replace(/name=[^&]+/, 'name=<domain>') },
			});
			return { kind: 'error', reason: 'parse' };
		}
		return { kind: 'ok', response: parsed.data as DohResponse };
	} catch (err) {
		const isTimeout = err instanceof DOMException && err.name === 'TimeoutError';
		logError(isTimeout ? 'DNS fetch timeout' : 'DNS fetch failed', {
			severity: 'warn',
			category: 'dns-transport',
			details: { url: url.replace(/name=[^&]+/, 'name=<domain>'), errorType: isTimeout ? 'timeout' : 'network' },
		});
		return { kind: 'error', reason: isTimeout ? 'timeout' : 'network' };
	}
}

/** Error thrown when a DNS query fails */
export class DnsQueryError extends Error {
	constructor(
		message: string,
		public readonly domain: string,
		public readonly recordType: string,
		public readonly status?: number,
	) {
		super(message);
		this.name = 'DnsQueryError';
	}
}

/**
 * Query Cloudflare DoH for DNS records.
 *
 * When `opts.queryCache` is provided, deduplicates concurrent and sequential
 * identical queries within a single scan by caching the Promise keyed by
 * `domain:type:dnssecCheck`. Failed queries are evicted so retries can re-attempt.
 *
 * @param domain - The domain name to query
 * @param type - DNS record type name (e.g. "TXT", "MX", "A")
 * @param dnssecCheck - If true, sets the CD=0 flag to request DNSSEC validation
 * @returns The full DoH JSON response
 */
export async function queryDns(domain: string, type: RecordTypeName, dnssecCheck = false, opts?: QueryDnsOptions): Promise<DohResponse> {
	const cache = opts?.queryCache;
	if (!cache) {
		return queryDnsUncached(domain, type, dnssecCheck, opts);
	}

	const cacheKey = `${domain}:${type}:${dnssecCheck}`;
	const existing = cache.get(cacheKey);
	if (existing) {
		return existing;
	}

	const promise = queryDnsUncached(domain, type, dnssecCheck, opts);
	cache.set(cacheKey, promise);
	promise.catch(() => cache.delete(cacheKey));
	return promise;
}

async function queryDnsUncached(domain: string, type: RecordTypeName, dnssecCheck = false, opts?: QueryDnsOptions): Promise<DohResponse> {
	const timeoutMs = opts?.timeoutMs ?? DNS_TIMEOUT_MS;
	const retries = opts?.retries ?? DNS_RETRIES;
	const confirmWithSecondaryOnEmpty = opts?.confirmWithSecondaryOnEmpty ?? DNS_CONFIRM_WITH_SECONDARY_ON_EMPTY;
	const sem = opts?.dnsSemaphore;
	const url = buildDohUrl(DOH_ENDPOINT, domain, type, dnssecCheck);

	/** Optionally run a fetch through the semaphore when one is provided. */
	const guardedFetch = (input: string | Request, init?: RequestInit & { cf?: Record<string, unknown> }): Promise<Response> =>
		sem ? sem.run(() => fetch(input, init)) : fetch(input, init);

	for (let attempt = 0; attempt <= retries; attempt++) {
		let response: Response;

		try {
			response = await guardedFetch(url, {
				method: 'GET',
				headers: { Accept: 'application/dns-json' },
				signal: AbortSignal.timeout(timeoutMs),
				cf: { cacheTtl: DOH_EDGE_CACHE_TTL, cacheEverything: true },
			});
		} catch (err) {
			if (err instanceof DOMException && err.name === 'AbortError') {
				if (attempt < retries) {
					await retryDelay(attempt);
					continue;
				}
				throw new DnsQueryError(`DNS query timed out after ${timeoutMs}ms`, domain, type);
			}
			if (attempt < retries) {
				await retryDelay(attempt);
				continue;
			}
			throw new DnsQueryError(`DNS query failed: ${err instanceof Error ? err.message : String(err)}`, domain, type);
		}

		if (!response.ok) {
			if (attempt < retries && response.status >= 500) {
				await retryDelay(attempt);
				continue;
			}
			throw new DnsQueryError(`DoH returned HTTP ${response.status}`, domain, type, response.status);
		}

		const raw = await response.json();
		const validated = DohResponseSchema.safeParse(raw);
		if (!validated.success) {
			throw new DnsQueryError('Invalid DoH response format', domain, type);
		}
		const data = validated.data as DohResponse;

		if (confirmWithSecondaryOnEmpty && !opts?.skipSecondaryConfirmation && !hasTypedAnswers(data, type)) {
			const secondaryOpts = opts?.secondaryDoh
				? { secondaryDoh: { url: opts.secondaryDoh.endpoint, token: opts.secondaryDoh.token } }
				: undefined;
			const secondaryResult = await confirmWithSecondaryResolvers(domain, type, dnssecCheck, timeoutMs, sem, secondaryOpts);
			if ('kind' in secondaryResult && secondaryResult.kind === 'unconfirmed') {
				// Secondary confirmation unavailable — keep the primary result as-is.
				// (Do NOT change primary to empty; primary is authoritative when we can't verify.)
				return data;
			}
			// secondaryResult is DohResponse here
			const confirmedResponse = secondaryResult as DohResponse;
			return confirmedResponse;
		}

		return data;
	}

	throw new DnsQueryError('DNS query failed after retries', domain, type);
}

/**
 * Confirm empty primary results with secondary resolvers.
 * Races bv-dns (when configured) and Google DoH in parallel — first responder
 * with a successful response wins. Returns `{ kind: 'unconfirmed' }` when all
 * secondaries fail, so callers can distinguish "both resolvers down" from
 * "confirmed absent."
 */
export async function confirmWithSecondaryResolvers(
	domain: string,
	type: RecordTypeName,
	dnssecCheck: boolean,
	timeoutMs: number,
	sem?: Semaphore,
	opts?: { secondaryDoh?: { url: string; token?: string } },
): Promise<DohResponse | { kind: 'unconfirmed' }> {
	const bvDnsUrl = opts?.secondaryDoh ? buildDohUrl(opts.secondaryDoh.url, domain, type, dnssecCheck) : null;
	const googleUrl = buildDohUrl(GOOGLE_DOH_ENDPOINT, domain, type, dnssecCheck);
	const candidates = [
		bvDnsUrl
			? fetchDohOutcome(bvDnsUrl, timeoutMs, { token: opts!.secondaryDoh!.token, semaphore: sem })
			: Promise.resolve({ kind: 'error', reason: 'network' } as const),
		fetchDohOutcome(googleUrl, timeoutMs, { useEdgeCache: true, semaphore: sem }),
	];
	const results = await Promise.allSettled(candidates);
	for (const r of results) {
		if (r.status === 'fulfilled' && r.value.kind === 'ok' && hasTypedAnswers(r.value.response, type)) return r.value.response;
	}
	// No secondary returned typed answers — return the first successful response if any,
	// so callers get a valid (possibly empty) DohResponse instead of unconfirmed.
	for (const r of results) {
		if (r.status === 'fulfilled' && r.value.kind === 'ok') return r.value.response;
	}
	logError('All secondary resolvers failed', {
		severity: 'warn',
		category: 'dns-transport',
		details: { type },
	});
	return { kind: 'unconfirmed' };
}
