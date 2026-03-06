/**
 * DNS query library using Cloudflare DNS-over-HTTPS (DoH).
 * All queries go through https://cloudflare-dns.com/dns-query
 * using the JSON wire format (application/dns-json).
 *
 * Workers-compatible: uses only fetch API, no Node.js APIs.
 */

import { DNS_TIMEOUT_MS, DNS_RETRIES, DNS_CONFIRM_WITH_SECONDARY_ON_EMPTY } from './config';

const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';
const SECONDARY_DOH_ENDPOINT = 'https://dns.google/resolve';

/** Standard DNS record type codes */
export const RecordType = {
	A: 1,
	AAAA: 28,
	CNAME: 5,
	MX: 15,
	TXT: 16,
	NS: 2,
	SOA: 6,
	CAA: 257,
	TLSA: 52,
	DNSKEY: 48,
	DS: 43,
	RRSIG: 46,
} as const;

export type RecordTypeName = keyof typeof RecordType;

/** A single DNS answer record from the DoH JSON response */
export interface DnsAnswer {
	name: string;
	type: number;
	TTL: number;
	data: string;
}

/** A single DNS authority record */
interface DnsAuthority {
	name: string;
	type: number;
	TTL: number;
	data: string;
}

/** Cloudflare DoH JSON wire-format response */
interface DohResponse {
	Status: number;
	TC: boolean;
	RD: boolean;
	RA: boolean;
	AD: boolean; // Authenticated Data - true if DNSSEC validated
	CD: boolean;
	Question: Array<{ name: string; type: number }>;
	Answer?: DnsAnswer[];
	Authority?: DnsAuthority[];
}

interface QueryDnsOptions {
	timeoutMs?: number;
	retries?: number;
	confirmWithSecondaryOnEmpty?: boolean;
}

function hasTypedAnswers(response: DohResponse, type: RecordTypeName): boolean {
	return (response.Answer ?? []).some((answer) => answer.type === RecordType[type]);
}

async function queryDnsFromEndpoint(
	endpoint: string,
	domain: string,
	type: RecordTypeName,
	dnssecCheck: boolean,
	timeoutMs: number,
): Promise<DohResponse | null> {
	const params = new URLSearchParams({
		name: domain,
		type,
		...(dnssecCheck ? { cd: '0' } : {}),
	});
	const url = `${endpoint}?${params.toString()}`;

	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const response = await fetch(url, {
			method: 'GET',
			headers: { Accept: 'application/dns-json' },
			signal: controller.signal,
		});
		if (!response.ok) return null;
		const data: DohResponse = await response.json();
		return data;
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
 * @param domain - The domain name to query
 * @param type - DNS record type name (e.g. "TXT", "MX", "A")
 * @param dnssecCheck - If true, sets the CD=0 flag to request DNSSEC validation
 * @returns The full DoH JSON response
 */
export async function queryDns(domain: string, type: RecordTypeName, dnssecCheck = false, opts?: QueryDnsOptions): Promise<DohResponse> {
       const params = new URLSearchParams({
	       name: domain,
	       type,
	       ...(dnssecCheck ? { cd: '0' } : {}),
       });

       const url = `${DOH_ENDPOINT}?${params.toString()}`;
	const timeoutMs = opts?.timeoutMs ?? DNS_TIMEOUT_MS;
	const retries = opts?.retries ?? DNS_RETRIES;
	const confirmWithSecondaryOnEmpty = opts?.confirmWithSecondaryOnEmpty ?? DNS_CONFIRM_WITH_SECONDARY_ON_EMPTY;

       for (let attempt = 0; attempt <= retries; attempt++) {
	       const controller = new AbortController();
	       const timeout = setTimeout(() => controller.abort(), timeoutMs);
	       let response: Response;
	       try {
		       response = await fetch(url, {
			       method: 'GET',
			       headers: { Accept: 'application/dns-json' },
			       // cf: { cacheEverything: true }, // Uncomment to customize Cloudflare fetch
			       signal: controller.signal,
		       });
	       } catch (err) {
		       clearTimeout(timeout);
		       if (err instanceof DOMException && err.name === 'AbortError') {
			       if (attempt < retries) continue;
			       throw new DnsQueryError(`DNS query timed out after ${timeoutMs}ms`, domain, type);
		       }
		       if (attempt < retries) continue;
		       throw new DnsQueryError(`DNS query failed: ${err instanceof Error ? err.message : String(err)}`, domain, type);
	       }
	       clearTimeout(timeout);

	       if (!response.ok) {
		       if (attempt < retries && response.status >= 500) continue;
		       throw new DnsQueryError(`DoH returned HTTP ${response.status}`, domain, type, response.status);
	       }

	       const data: DohResponse = await response.json();

	       if (confirmWithSecondaryOnEmpty && !hasTypedAnswers(data, type)) {
		       const secondary = await queryDnsFromEndpoint(SECONDARY_DOH_ENDPOINT, domain, type, dnssecCheck, timeoutMs);
		       if (secondary && hasTypedAnswers(secondary, type)) {
			       return secondary;
		       }
	       }

	       return data;
       }
       // Should never reach here
       throw new DnsQueryError('DNS query failed after retries', domain, type);
}

/**
 * Query DNS and return just the answer data strings.
 * Returns an empty array if no answers are found.
 */
export async function queryDnsRecords(domain: string, type: RecordTypeName): Promise<string[]> {
	const resp = await queryDns(domain, type);
	return (resp.Answer ?? []).filter((a) => a.type === RecordType[type]).map((a) => a.data);
}

/**
 * Query TXT records and strip surrounding quotes from values.
 * Cloudflare DoH returns TXT data with surrounding quotes.
 */
export async function queryTxtRecords(domain: string): Promise<string[]> {
	const records = await queryDnsRecords(domain, 'TXT');
	return records.map((r) =>
		r
			.replace(/" "/g, ' ')
			.replace(/^"|"$/g, ''),
	);
}

/**
 * Check if a domain has valid DNSSEC by examining the AD (Authenticated Data) flag.
 * Returns true if the response was DNSSEC-validated.
 */
export async function checkDnssec(domain: string): Promise<boolean> {
	const resp = await queryDns(domain, 'A', true);
	return resp.AD === true;
}

/** Parsed CAA record with flags, tag, and value */
export interface CaaRecord {
	flags: number;
	tag: string;
	value: string;
}

/**
 * Parse a single CAA record data string.
 * Handles both human-readable format (e.g. `0 issue "letsencrypt.org"`)
 * and Cloudflare DoH hex wire format (e.g. `\# 19 00 05 69 73 73 75 65...`).
 *
 * Wire format bytes: flags(1) + tag_length(1) + tag(tag_length) + value(rest)
 */
export function parseCaaRecord(data: string): CaaRecord | null {
	// Hex wire format: \# NN HH HH HH ...
	if (data.startsWith('\\#') || data.startsWith('#')) {
		const parts = data.trim().split(/\s+/);
		// parts[0] = "\#", parts[1] = byte count, parts[2..] = hex bytes
		const hexStart = parts[0] === '\\#' || parts[0] === '#' ? 2 : 1;
		const hexBytes = parts.slice(hexStart);
		if (hexBytes.length < 3) return null;

		const flags = parseInt(hexBytes[0], 16);
		const tagLen = parseInt(hexBytes[1], 16);
		if (isNaN(flags) || isNaN(tagLen) || hexBytes.length < 2 + tagLen) return null;

		const tag = hexBytes
			.slice(2, 2 + tagLen)
			.map((h) => String.fromCharCode(parseInt(h, 16)))
			.join('');
		const value = hexBytes
			.slice(2 + tagLen)
			.map((h) => String.fromCharCode(parseInt(h, 16)))
			.join('');

		return { flags, tag: tag.toLowerCase(), value };
	}

	// Human-readable format: flags tag "value" or flags tag value
	const match = data.match(/^(\d+)\s+(\S+)\s+"?([^"]*)"?\s*$/);
	if (match) {
		return {
			flags: parseInt(match[1], 10),
			tag: match[2].toLowerCase(),
			value: match[3],
		};
	}

	return null;
}

/**
 * Query CAA records and parse them into structured objects.
 * Handles both human-readable and hex wire format from DoH.
 */
export async function queryCaaRecords(domain: string): Promise<CaaRecord[]> {
	const records = await queryDnsRecords(domain, 'CAA');
	return records.map(parseCaaRecord).filter((r): r is CaaRecord => r !== null);
}

/**
 * Query MX records and parse them into priority + exchange pairs.
 */
export async function queryMxRecords(domain: string): Promise<Array<{ priority: number; exchange: string }>> {
	const records = await queryDnsRecords(domain, 'MX');
	return records.map((r) => {
		const parts = r.split(' ');
		return {
			priority: parseInt(parts[0], 10),
			exchange: parts.slice(1).join(' ').replace(/\.$/, ''),
		};
	});
}
