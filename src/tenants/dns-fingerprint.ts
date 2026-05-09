// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS fingerprint primitive for Tenant continuous-monitoring (Phase-3 foundation).
 *
 * Source of truth: `tenant-Scalable-Architecture-Design.md` §4.2 — the weekly
 * monitoring cron computes a stable hash of a domain's DNS posture so the
 * full `scan_domain` can be skipped when nothing has changed. Empirically
 * ~80% of weekly re-scans on stable portfolios hit this fast path.
 *
 * Module is intentionally **runtime-agnostic**: no `cloudflare:workers`, no
 * Node.js APIs. Hashing uses Web Crypto's `crypto.subtle.digest`, the DNS
 * facade is injected by the caller. Mirrors the pattern in
 * `src/tenants/discovery/san-correlator.ts`.
 *
 * Wiring into the cron itself is Wave D — this module is foundation only.
 */

import { RecordType, type DohResponse, type QueryDnsOptions, type RecordTypeName } from '../lib/dns-types';
import { queryDns } from '../lib/dns-transport';
import { unescapeDnsTxt } from '../lib/dns-records';
import { validateDomain } from '../lib/sanitize';

/**
 * Injected DNS query function. Matches the signature of `queryDns` from
 * `src/lib/dns-transport.ts` — we depend on the low-level form so we can
 * canonicalize raw rdata ourselves.
 */
export type DnsQueryFn = (
	domain: string,
	type: RecordTypeName,
	dnssecCheck?: boolean,
	opts?: QueryDnsOptions,
) => Promise<DohResponse>;

/** Length, in raw bytes, of the truncated SHA-256 fingerprint prefix. */
const FINGERPRINT_BYTES = 16;

/** Records captured for fingerprint computation (canonicalized). */
export interface FingerprintRecords {
	/** First TXT record matching `v=spf1` (case-insensitive), trimmed. `null` when absent. */
	spf: string | null;
	/** First TXT record at `_dmarc.<domain>` matching `v=DMARC1` (case-insensitive), trimmed. `null` when absent. */
	dmarc: string | null;
	/** MX rdata as `"<priority>:<host>"` strings, hosts lowercased + trailing dot stripped, sorted ascending. */
	mx: string[];
	/** NS rdata as hostnames, lowercased + trailing dot stripped, sorted ascending. */
	ns: string[];
	/** CAA rdata as raw text, trimmed, sorted ascending. */
	caa: string[];
}

/** Result of `computeFingerprint`. */
export type DnsFingerprintResult =
	| {
			kind: 'ok';
			domain: string;
			/** SHA-256 hex, truncated to the first 16 bytes (32 hex chars). */
			fingerprint: string;
			capturedAt: number;
			records: FingerprintRecords;
		}
	| {
			kind: 'error';
			domain: string;
			reason: 'dns_failure' | 'invalid_domain';
		};

/** Options for `computeFingerprint`. */
export interface ComputeFingerprintOptions {
	/** Override the underlying DNS query implementation (used for testing). Defaults to `queryDns`. */
	dnsQuery?: DnsQueryFn;
	/** Forwarded to each `dnsQuery` call. */
	dnsOptions?: QueryDnsOptions;
}

/**
 * Lower-case a hostname and strip a single trailing dot if present.
 * Matches DNS canonicalization: `Mail.Example.COM.` and `mail.example.com`
 * compare equal.
 */
function canonicalizeHost(host: string): string {
	const lower = host.trim().toLowerCase();
	return lower.endsWith('.') ? lower.slice(0, -1) : lower;
}

/**
 * Cloudflare DoH returns TXT rdata as one or more quoted strings separated
 * by `" "`. RFC 7208 §3.3 says these MUST be concatenated without any
 * intervening characters. We also strip leading/trailing quotes and
 * unescape RFC 1035 §5.1 backslash sequences (capped at 2 passes — same
 * defence-in-depth bound used by `unescapeDnsTxt` callers elsewhere).
 */
function decodeTxtRdata(raw: string): string {
	return unescapeDnsTxt(raw.replace(/" "/g, '').replace(/^"|"$/g, ''));
}

/**
 * Pull the first TXT record whose decoded payload starts with the given
 * case-insensitive prefix (e.g. `'v=spf1'`, `'v=DMARC1'`). Returns the
 * trimmed payload, or `null` when no record matches.
 */
function firstTxtMatching(answers: DohResponse['Answer'], prefixLower: string): string | null {
	if (!answers) return null;
	for (const answer of answers) {
		if (answer.type !== RecordType.TXT) continue;
		const decoded = decodeTxtRdata(answer.data).trim();
		if (decoded.toLowerCase().startsWith(prefixLower)) {
			return decoded;
		}
	}
	return null;
}

/**
 * Parse MX rdata of the form `"10 mail.example.com."` into a canonical
 * `"<priority>:<host>"` string. Returns `null` for malformed entries
 * (missing priority, missing host, non-numeric priority) so the caller
 * can drop them rather than poisoning the fingerprint with garbage.
 */
function canonicalizeMxRdata(data: string): string | null {
	const trimmed = data.trim();
	if (!trimmed) return null;
	const spaceIdx = trimmed.indexOf(' ');
	if (spaceIdx <= 0) return null;
	const priority = Number.parseInt(trimmed.slice(0, spaceIdx), 10);
	if (!Number.isFinite(priority)) return null;
	const host = canonicalizeHost(trimmed.slice(spaceIdx + 1));
	if (!host) return null;
	return `${priority}:${host}`;
}

/** Map MX answers to canonical strings + sort ascending. */
function extractMx(answers: DohResponse['Answer']): string[] {
	if (!answers) return [];
	const out: string[] = [];
	for (const answer of answers) {
		if (answer.type !== RecordType.MX) continue;
		const canon = canonicalizeMxRdata(answer.data);
		if (canon !== null) out.push(canon);
	}
	return out.sort();
}

/** Map NS answers to canonical hostnames + sort ascending. */
function extractNs(answers: DohResponse['Answer']): string[] {
	if (!answers) return [];
	const out: string[] = [];
	for (const answer of answers) {
		if (answer.type !== RecordType.NS) continue;
		const host = canonicalizeHost(answer.data);
		if (host) out.push(host);
	}
	return out.sort();
}

/** Map CAA answers to raw, trimmed text + sort ascending. */
function extractCaa(answers: DohResponse['Answer']): string[] {
	if (!answers) return [];
	const out: string[] = [];
	for (const answer of answers) {
		if (answer.type !== RecordType.CAA) continue;
		const trimmed = answer.data.trim();
		if (trimmed) out.push(trimmed);
	}
	return out.sort();
}

/**
 * Hex-encode a byte slice. Inlined rather than imported because we only
 * need the trivial form and want zero dependencies.
 */
function bytesToHex(bytes: Uint8Array): string {
	let out = '';
	for (let i = 0; i < bytes.length; i++) {
		out += bytes[i].toString(16).padStart(2, '0');
	}
	return out;
}

/**
 * SHA-256 a UTF-8 string and return the first {@link FINGERPRINT_BYTES}
 * bytes hex-encoded (32 hex chars). Truncation is intentional: per §4.2
 * we just need a stable, low-collision change-detection key, not a
 * cryptographic commitment.
 */
async function shortDigest(input: string): Promise<string> {
	const data = new TextEncoder().encode(input);
	const buf = await crypto.subtle.digest('SHA-256', data);
	const truncated = new Uint8Array(buf).slice(0, FINGERPRINT_BYTES);
	return bytesToHex(truncated);
}

/** Settled outcome shape the canonicalizer needs from each parallel query. */
type SettledQuery = { ok: true; response: DohResponse } | { ok: false };

/**
 * Run the five DNS queries in parallel and bucket each into ok/failed.
 * `Promise.allSettled` rather than `Promise.all` — one rejection must not
 * collapse the whole result. A `DohResponse` with `Status !== 0` is still
 * a successful query (NXDOMAIN, etc.) and counts as `ok` here; the
 * extractors above already treat missing answers as "no records".
 */
async function runQueries(
	domain: string,
	dnsQuery: DnsQueryFn,
	dnsOptions?: QueryDnsOptions,
): Promise<{
	spf: SettledQuery;
	dmarc: SettledQuery;
	mx: SettledQuery;
	ns: SettledQuery;
	caa: SettledQuery;
}> {
	const settled = await Promise.allSettled([
		dnsQuery(domain, 'TXT', false, dnsOptions),
		dnsQuery(`_dmarc.${domain}`, 'TXT', false, dnsOptions),
		dnsQuery(domain, 'MX', false, dnsOptions),
		dnsQuery(domain, 'NS', false, dnsOptions),
		dnsQuery(domain, 'CAA', false, dnsOptions),
	]);

	const toSettled = (r: PromiseSettledResult<DohResponse>): SettledQuery =>
		r.status === 'fulfilled' ? { ok: true, response: r.value } : { ok: false };

	return {
		spf: toSettled(settled[0]),
		dmarc: toSettled(settled[1]),
		mx: toSettled(settled[2]),
		ns: toSettled(settled[3]),
		caa: toSettled(settled[4]),
	};
}

/**
 * Compute a stable DNS fingerprint for {@link domain}.
 *
 * Algorithm:
 *  1. Validate the domain (SSRF / format / blocklist) — invalid → `error`.
 *  2. In parallel: TXT for SPF, TXT for `_dmarc.<domain>`, MX, NS, CAA.
 *  3. Canonicalize each record (lowercased, sorted, trimmed). Wildcard or
 *     missing records become `null` / empty array.
 *  4. If every query failed → `error: 'dns_failure'`.
 *  5. Otherwise SHA-256 the JSON form, truncate to {@link FINGERPRINT_BYTES}
 *     bytes, hex-encode, return alongside the captured records.
 *
 * Determinism: identical input DNS state always produces an identical
 * fingerprint. Reordering, casing and trailing-dot variation in the DNS
 * answer set are all canonicalized away before hashing.
 */
export async function computeFingerprint(
	domain: string,
	options: ComputeFingerprintOptions = {},
): Promise<DnsFingerprintResult> {
	const validation = validateDomain(domain);
	if (!validation.valid) {
		return { kind: 'error', domain, reason: 'invalid_domain' };
	}
	const lower = domain.trim().toLowerCase().replace(/\.$/, '');

	const dnsQuery = options.dnsQuery ?? queryDns;
	const queries = await runQueries(lower, dnsQuery, options.dnsOptions);

	const allFailed =
		!queries.spf.ok && !queries.dmarc.ok && !queries.mx.ok && !queries.ns.ok && !queries.caa.ok;
	if (allFailed) {
		return { kind: 'error', domain: lower, reason: 'dns_failure' };
	}

	const records: FingerprintRecords = {
		spf: queries.spf.ok ? firstTxtMatching(queries.spf.response.Answer, 'v=spf1') : null,
		dmarc: queries.dmarc.ok ? firstTxtMatching(queries.dmarc.response.Answer, 'v=dmarc1') : null,
		mx: queries.mx.ok ? extractMx(queries.mx.response.Answer) : [],
		ns: queries.ns.ok ? extractNs(queries.ns.response.Answer) : [],
		caa: queries.caa.ok ? extractCaa(queries.caa.response.Answer) : [],
	};

	// Canonical JSON form: keys in fixed order, arrays already sorted by
	// extractors. `JSON.stringify` is deterministic for primitive values
	// when the key insertion order is stable (which it is here — we
	// construct the object with literal keys in fixed order above).
	const canonical = JSON.stringify({
		spf: records.spf,
		dmarc: records.dmarc,
		mx: records.mx,
		ns: records.ns,
		caa: records.caa,
	});

	const fingerprint = await shortDigest(canonical);

	return {
		kind: 'ok',
		domain: lower,
		fingerprint,
		capturedAt: Date.now(),
		records,
	};
}

/**
 * Compare two fingerprint hashes. Returns `true` when the records have
 * meaningfully changed (raw fingerprint hash differs).
 *
 * Convention for monitoring callers:
 *  - `null` on either side ⇒ "differ" (no baseline yet, or current scan
 *    failed). The pre-flight should fall through to a full `scan_domain`
 *    rather than skip on uncertainty.
 *  - Both non-null and equal ⇒ "no change" — safe to skip the rescan.
 */
export function fingerprintsDiffer(a: string | null, b: string | null): boolean {
	if (a === null || b === null) return true;
	return a !== b;
}
