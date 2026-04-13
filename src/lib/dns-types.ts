// SPDX-License-Identifier: BUSL-1.1

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
	NSEC3PARAM: 51,
	PTR: 12,
	SRV: 33,
	HTTPS: 65,
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

/** Configuration for a custom secondary DoH resolver (e.g., bv-dns on Oracle Cloud). */
export interface SecondaryDohConfig {
	/** DoH endpoint URL (e.g. https://doh.example.com/dns-query) */
	endpoint: string;
	/** Optional auth token sent as X-BV-Token header */
	token?: string;
}

export interface QueryDnsOptions {
	timeoutMs?: number;
	retries?: number;
	confirmWithSecondaryOnEmpty?: boolean;
	/** When true, skip secondary resolver confirmation on empty results. Used in scan context for speed. */
	skipSecondaryConfirmation?: boolean;
	/** Scan-scoped DNS query cache. Stores Promises keyed by `domain:type:dnssecCheck` to deduplicate concurrent and sequential identical queries within a single scan. */
	queryCache?: Map<string, Promise<DohResponse>>;
	/** Custom secondary DoH resolver. When set, used instead of Google DoH for empty-result confirmation. Falls back to Google if this resolver fails. */
	secondaryDoh?: SecondaryDohConfig;
	/** Semaphore for capping concurrent outbound DoH fetches per isolate. */
	dnsSemaphore?: import('./semaphore').Semaphore;
}