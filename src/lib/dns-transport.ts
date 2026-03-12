// SPDX-License-Identifier: MIT

import { DNS_TIMEOUT_MS, DNS_RETRIES, DNS_CONFIRM_WITH_SECONDARY_ON_EMPTY, DOH_EDGE_CACHE_TTL, DNS_RETRY_BASE_DELAY_MS } from './config';
import { type DohResponse, type QueryDnsOptions, RecordType, type RecordTypeName } from './dns-types';

const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const SECONDARY_DOH_ENDPOINT = 'https://dns.google/resolve';

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
		return (await response.json()) as DohResponse; // DoH JSON API returns a well-defined schema
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
 * @param domain - The domain name to query
 * @param type - DNS record type name (e.g. "TXT", "MX", "A")
 * @param dnssecCheck - If true, sets the CD=0 flag to request DNSSEC validation
 * @returns The full DoH JSON response
 */
export async function queryDns(domain: string, type: RecordTypeName, dnssecCheck = false, opts?: QueryDnsOptions): Promise<DohResponse> {
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

		const data = (await response.json()) as DohResponse; // DoH JSON API returns a well-defined schema

		if (confirmWithSecondaryOnEmpty && !opts?.skipSecondaryConfirmation && !hasTypedAnswers(data, type)) {
			const secondary = await queryDnsFromEndpoint(SECONDARY_DOH_ENDPOINT, domain, type, dnssecCheck, timeoutMs);
			if (secondary && hasTypedAnswers(secondary, type)) {
				return secondary;
			}
		}

		return data;
	}

	throw new DnsQueryError('DNS query failed after retries', domain, type);
}