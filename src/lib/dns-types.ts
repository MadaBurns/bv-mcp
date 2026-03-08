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
export interface DnsAuthority {
	name: string;
	type: number;
	TTL: number;
	data: string;
}

/** Cloudflare DoH JSON wire-format response */
export interface DohResponse {
	Status: number;
	TC: boolean;
	RD: boolean;
	RA: boolean;
	AD: boolean;
	CD: boolean;
	Question: Array<{ name: string; type: number }>;
	Answer?: DnsAnswer[];
	Authority?: DnsAuthority[];
}

export interface QueryDnsOptions {
	timeoutMs?: number;
	retries?: number;
	confirmWithSecondaryOnEmpty?: boolean;
}