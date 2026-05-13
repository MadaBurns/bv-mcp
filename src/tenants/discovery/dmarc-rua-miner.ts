// SPDX-License-Identifier: BUSL-1.1

/**
 * DMARC rua/ruf miner (Phase-4 brand-discovery, tier-1 signal).
 *
 * Queries `_dmarc.<seed>` TXT, parses the `rua=` and `ruf=` URI lists, and
 * classifies each addressee mailbox's domain as:
 *   - `self` — same as the seed domain
 *   - `processor` — well-known DMARC report processor (dmarcian, valimail, etc.)
 *   - `related` — other domain (potential ownership signal, conf 0.6)
 *
 * Why 0.6: many companies forward DMARC to a SOC mailbox at a parent brand,
 * but it's also common to send to a contractor or a SIEM ingestion address.
 * Strong-but-not-deterministic.
 *
 * Failure modes follow the bv-mcp convention: this function MUST NOT throw on
 * DNS errors — only on programmer error (invalid input). Callers interrogate
 * `queryStatus` instead.
 */

import { queryDns } from '../../lib/dns-transport';
import type { DohResponse } from '../../lib/dns-types';
import { validateDomain, isSubdomainOf } from '../../lib/sanitize';

/** Function signature for an injectable DNS-over-HTTPS query. */
export type DnsQueryFn = (name: string, type: 'TXT' | string) => Promise<DohResponse>;

/**
 * Well-known DMARC report processors. A rua/ruf addressee at one of these
 * domains is operational plumbing, not an ownership signal.
 */
const KNOWN_DMARC_PROCESSORS = new Set<string>([
	'dmarcian.com',
	'valimail.com',
	'agari.com',
	'easydmarc.com',
	'postmarkapp.com',
	'mxtoolbox.com',
]);

export interface DmarcRuaOptions {
	/**
	 * Override the underlying DNS query implementation (used for testing).
	 * Defaults to the project's `queryDns` facade. Always called with type='TXT'.
	 */
	dnsQuery?: DnsQueryFn;
}

export type RuaClassification = 'self' | 'processor' | 'related';

export interface DmarcRuaDomain {
	/** Lowercase addressee domain (everything after `@`). */
	domain: string;
	classification: RuaClassification;
	/** 0.6 for `related`; 0 for `self` and `processor`. */
	confidence: number;
}

export interface DmarcRuaResult {
	seedDomain: string;
	dmarcPresent: boolean;
	/** Original `mailto:user@domain` URIs as found, lowercased and trimmed. */
	ruaUris: string[];
	/** Deduped per-domain classification. */
	ruaDomains: DmarcRuaDomain[];
	/**
	 * `ok` — DMARC found and parsed (may have zero rua/ruf).
	 * `no_dmarc` — TXT response had no DMARC record.
	 * `failed` — DNS query threw.
	 */
	queryStatus: 'ok' | 'no_dmarc' | 'failed';
}

/** Strip surrounding double-quotes and concatenate multi-string TXT chunks. */
function unwrapTxt(data: string): string {
	// DoH returns `"chunk1" "chunk2"` for multi-string TXT. Concat-then-strip.
	const matches = data.match(/"([^"]*)"/g);
	if (matches) return matches.map((m) => m.slice(1, -1)).join('');
	return data;
}

/** Locate the first DMARC TXT record from a list of TXT data values. */
function pickDmarcRecord(txtValues: string[]): string | null {
	for (const raw of txtValues) {
		const value = unwrapTxt(raw).trim();
		if (/^v=DMARC1\b/i.test(value)) return value;
	}
	return null;
}

/**
 * Extract the `rua=` and `ruf=` URI lists from a DMARC record string.
 * Each tag's value is comma-separated; whitespace is allowed around commas.
 */
function extractRuaRufUris(record: string): string[] {
	const out: string[] = [];
	for (const tag of ['rua', 'ruf']) {
		const re = new RegExp(`(?:^|;)\\s*${tag}\\s*=\\s*([^;]+)`, 'i');
		const m = record.match(re);
		if (!m) continue;
		const values = m[1].split(',').map((s) => s.trim()).filter(Boolean);
		out.push(...values);
	}
	return out;
}

/** Parse a single rua/ruf URI of form `mailto:user@domain`. Returns null on malformed. */
function parseMailtoDomain(uri: string): string | null {
	const lower = uri.trim().toLowerCase();
	if (!lower.startsWith('mailto:')) return null;
	const addr = lower.slice('mailto:'.length).trim();
	// Reject empty local part (`@example.com`), missing @, or no domain.
	const at = addr.indexOf('@');
	if (at <= 0 || at === addr.length - 1) return null;
	const domain = addr.slice(at + 1);
	const v = validateDomain(domain);
	if (!v.valid) return null;
	return domain;
}

/**
 * Mine the seed's DMARC record for rua/ruf addressee domains.
 *
 * @throws Error with the `'Domain validation failed:'` prefix when the seed
 *   does not pass `validateDomain`. All other failure modes are returned via
 *   `queryStatus`.
 */
export async function mineDmarcRua(seedDomain: string, options: DmarcRuaOptions = {}): Promise<DmarcRuaResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const dnsQuery = options.dnsQuery ?? (queryDns as unknown as DnsQueryFn);

	let resp: DohResponse;
	try {
		resp = await dnsQuery(`_dmarc.${seedLower}`, 'TXT');
	} catch {
		return { seedDomain: seedLower, dmarcPresent: false, ruaUris: [], ruaDomains: [], queryStatus: 'failed' };
	}

	const txtValues = (resp.Answer ?? []).map((a) => a.data ?? '').filter(Boolean);
	if (txtValues.length === 0) {
		return { seedDomain: seedLower, dmarcPresent: false, ruaUris: [], ruaDomains: [], queryStatus: 'no_dmarc' };
	}

	const dmarcRecord = pickDmarcRecord(txtValues);
	if (!dmarcRecord) {
		return { seedDomain: seedLower, dmarcPresent: false, ruaUris: [], ruaDomains: [], queryStatus: 'no_dmarc' };
	}

	const rawUris = extractRuaRufUris(dmarcRecord);
	const ruaUris: string[] = [];
	const seenDomains = new Set<string>();
	const ruaDomains: DmarcRuaDomain[] = [];

	for (const uri of rawUris) {
		const domain = parseMailtoDomain(uri);
		if (!domain) continue;
		ruaUris.push(uri.trim().toLowerCase());
		if (seenDomains.has(domain)) continue;
		seenDomains.add(domain);
		let classification: RuaClassification;
		let confidence: number;
		if (isSubdomainOf(domain, seedLower)) {
			classification = 'self';
			confidence = 0;
		} else if (KNOWN_DMARC_PROCESSORS.has(domain)) {
			classification = 'processor';
			confidence = 0;
		} else {
			classification = 'related';
			confidence = 0.6;
		}
		ruaDomains.push({ domain, classification, confidence });
	}

	return {
		seedDomain: seedLower,
		dmarcPresent: true,
		ruaUris,
		ruaDomains,
		queryStatus: 'ok',
	};
}
