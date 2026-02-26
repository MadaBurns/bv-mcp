/**
 * DNS query library using Cloudflare DNS-over-HTTPS (DoH).
 * All queries go through https://cloudflare-dns.com/dns-query
 * using the JSON wire format (application/dns-json).
 * Compatible with fetch API (works in Node.js, Workers, browsers).
 */

export const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';

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

export interface DnsAnswer {
	name: string;
	type: number;
	TTL: number;
	data: string;
}

export interface DnsAuthority {
	name: string;
	type: number;
	TTL: number;
	data: string;
}

export interface DohResponse {
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
 * @param domain - The domain name to query
 * @param type - DNS record type name (e.g. "TXT", "MX", "A")
 * @param dnssecCheck - If true, sets the CD=0 flag to request DNSSEC validation
 * @returns The full DoH JSON response
 */
export async function queryDns(domain: string, type: RecordTypeName, dnssecCheck = false, opts?: { timeoutMs?: number; retries?: number }): Promise<DohResponse> {
	const params = new URLSearchParams({
		type: String(RecordType[type]),
		name: domain,
		cd: dnssecCheck ? '0' : '1',
	});
	const url = `${DOH_ENDPOINT}?${params.toString()}`;
	const response = await fetch(url, {
		method: 'GET',
		headers: { 'accept': 'application/dns-json' },
	});
	if (!response.ok) {
		throw new DnsQueryError(`DNS query failed: ${response.statusText}`, domain, type, response.status);
	}
	return await response.json();
}

/**
 * Query TXT records for a domain.
 */
export async function queryTxtRecords(domain: string): Promise<string[]> {
	const resp = await queryDns(domain, 'TXT');
	return (resp.Answer ?? []).map((a) => a.data.replace(/^"|"$/g, ''));
}

/**
 * Query DNS records for a domain and record type.
 */
export async function queryDnsRecords(domain: string, type: RecordTypeName): Promise<string[]> {
	const resp = await queryDns(domain, type);
	return (resp.Answer ?? []).map((a) => a.data);
}
