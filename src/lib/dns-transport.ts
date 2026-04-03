// SPDX-License-Identifier: BUSL-1.1

import { DNS_TIMEOUT_MS, DNS_RETRIES, DNS_CONFIRM_WITH_SECONDARY_ON_EMPTY, DOH_EDGE_CACHE_TTL, DNS_RETRY_BASE_DELAY_MS } from './config';
import { type DohResponse, type QueryDnsOptions, RecordType, type RecordTypeName } from './dns-types';
import { DohResponseSchema } from '../schemas/dns';

const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const GOOGLE_DOH_ENDPOINT = 'https://dns.google/resolve';
/** Quad9 unfiltered — no RPZ/malware blocking, used as last-resort fallback. */
const QUAD9_UNFILTERED_ENDPOINT = 'https://dns9.quad9.net/dns-query';

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

async function fetchDohResponse(url: string, timeoutMs: number): Promise<DohResponse | null> {
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), timeoutMs);

	try {
		const response = await fetch(url, {
			method: 'GET',
			headers: { Accept: 'application/dns-json' },
			signal: controller.signal,
			cf: { cacheTtl: DOH_EDGE_CACHE_TTL, cacheEverything: true },
		});
		if (!response.ok) return null;
		const data = await response.json();
		const parsed = DohResponseSchema.safeParse(data);
		if (!parsed.success) return null;
		return parsed.data as DohResponse;
	} catch {
		return null;
	} finally {
		clearTimeout(timeout);
	}
}

async function queryDnsFromEndpoint(
	endpoint: string,
	domain: string,
	type: RecordTypeName,
	dnssecCheck: boolean,
	timeoutMs: number,
): Promise<DohResponse | null> {
	return fetchDohResponse(buildDohUrl(endpoint, domain, type, dnssecCheck), timeoutMs);
}

/**
 * Fetch a DoH response from an endpoint with optional auth header.
 * Used for custom secondary resolvers (e.g., bv-dns) that may require authentication.
 * Does NOT use Cloudflare edge cache (`cf` directive) since the target is an external origin.
 */
async function fetchDohWithAuth(url: string, timeoutMs: number, token?: string): Promise<DohResponse | null> {
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const headers: Record<string, string> = { Accept: 'application/dns-json' };
		if (token) headers['X-BV-Token'] = token;
		const response = await fetch(url, {
			method: 'GET',
			headers,
			signal: controller.signal,
		});
		if (!response.ok) return null;
		const data = await response.json();
		const parsed = DohResponseSchema.safeParse(data);
		if (!parsed.success) return null;
		return parsed.data as DohResponse;
	} catch {
		return null;
	} finally {
		clearTimeout(timeout);
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
	const url = buildDohUrl(DOH_ENDPOINT, domain, type, dnssecCheck);

	for (let attempt = 0; attempt <= retries; attempt++) {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), timeoutMs);
		let response: Response;

		try {
			response = await fetch(url, {
				method: 'GET',
				headers: { Accept: 'application/dns-json' },
				signal: controller.signal,
				cf: { cacheTtl: DOH_EDGE_CACHE_TTL, cacheEverything: true },
			});
		} catch (err) {
			clearTimeout(timeout);
			if (err instanceof DOMException && err.name === 'AbortError') {
				if (attempt < retries) {
					await new Promise((r) => setTimeout(r, DNS_RETRY_BASE_DELAY_MS * (attempt + 1) + Math.random() * 50));
					continue;
				}
				throw new DnsQueryError(`DNS query timed out after ${timeoutMs}ms`, domain, type);
			}
			if (attempt < retries) {
				await new Promise((r) => setTimeout(r, DNS_RETRY_BASE_DELAY_MS * (attempt + 1) + Math.random() * 50));
				continue;
			}
			throw new DnsQueryError(`DNS query failed: ${err instanceof Error ? err.message : String(err)}`, domain, type);
		}

		clearTimeout(timeout);

		if (!response.ok) {
			if (attempt < retries && response.status >= 500) {
				await new Promise((r) => setTimeout(r, DNS_RETRY_BASE_DELAY_MS * (attempt + 1) + Math.random() * 50));
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
			// Try custom secondary (bv-dns) first if configured
			if (opts?.secondaryDoh?.endpoint) {
				const bvDns = await fetchDohWithAuth(
					buildDohUrl(opts.secondaryDoh.endpoint, domain, type, dnssecCheck),
					timeoutMs,
					opts.secondaryDoh.token,
				);
				if (bvDns && hasTypedAnswers(bvDns, type)) {
					return bvDns;
				}
			}
			// Google DoH as secondary fallback
			const google = await queryDnsFromEndpoint(GOOGLE_DOH_ENDPOINT, domain, type, dnssecCheck, timeoutMs);
			if (google && hasTypedAnswers(google, type)) {
				return google;
			}
			// Quad9 unfiltered as final fallback (no RPZ — bypasses DNS firewall blocks)
			const quad9 = await queryDnsFromEndpoint(QUAD9_UNFILTERED_ENDPOINT, domain, type, dnssecCheck, timeoutMs);
			if (quad9 && hasTypedAnswers(quad9, type)) {
				return quad9;
			}
		}

		return data;
	}

	throw new DnsQueryError('DNS query failed after retries', domain, type);
}