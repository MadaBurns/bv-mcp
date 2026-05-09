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

import { safeFetch } from '../../lib/safe-fetch';
import { validateDomain } from '../../lib/sanitize';

/** Default request timeout (ms). */
const DEFAULT_TIMEOUT_MS = 8_000;

/** Default cap on certs to consider per seed query. */
const DEFAULT_MAX_CERTS = 50;

/**
 * Cap on the JSON response body before parsing. crt.sh can return MBs of
 * SAN data for large issuers; bound it to keep the Worker out of OOM land.
 */
const MAX_BODY_BYTES = 5 * 1024 * 1024;

export interface SanCorrelationOptions {
	/** Request timeout in ms. Defaults to 8000. */
	timeoutMs?: number;
	/** Cap on the number of crt.sh entries that contribute to the result. Defaults to 50. */
	maxCertsPerDomain?: number;
	/** Override the underlying fetch implementation (used for testing). Defaults to `safeFetch`. */
	fetchFn?: typeof fetch;
}

export interface SanCorrelationResult {
	seedDomain: string;
	/** Deduped, alphabetically sorted, lowercase ASCII sibling domains. */
	coOwnedDomains: string[];
	/** crt.sh `id` values of the certs that produced the matches (capped by maxCertsPerDomain). */
	certIds: number[];
	queryStatus: 'ok' | 'rate_limited' | 'timeout' | 'error';
}

/** A single crt.sh JSON response entry (subset we use). */
interface CrtShEntry {
	id?: number;
	name_value?: string;
	entry_timestamp?: string;
}

/**
 * Build the empty/error-shape result. Centralised so the failure paths can't
 * accidentally diverge on field defaults.
 */
function emptyResult(seedDomain: string, status: SanCorrelationResult['queryStatus']): SanCorrelationResult {
	return { seedDomain, coOwnedDomains: [], certIds: [], queryStatus: status };
}

/**
 * Sort entries newest-first. Entries without `entry_timestamp` are pushed to
 * the end so they don't out-compete dated entries for the cap slots.
 */
function sortEntriesNewestFirst(entries: CrtShEntry[]): CrtShEntry[] {
	const withSortKey = entries.map((entry) => {
		const t = entry.entry_timestamp ? Date.parse(entry.entry_timestamp) : Number.NaN;
		return { entry, sortKey: Number.isFinite(t) ? t : Number.NEGATIVE_INFINITY };
	});
	withSortKey.sort((a, b) => b.sortKey - a.sortKey);
	return withSortKey.map((x) => x.entry);
}

/**
 * Extract sibling domains from a single SAN string.
 *
 * `name_value` is a list of hostnames separated by `\n` or `,` (crt.sh varies
 * by query). Wildcards (`*.example.com`) become the bare apex. Subdomains
 * of the seed are dropped — those are `discover_subdomains`' job. The seed
 * itself is dropped. Hostnames that fail `validateDomain` are silently
 * filtered (SSRF/sentinel guard).
 */
function extractSiblingsFromNameValue(nameValue: string, seedLower: string): string[] {
	const seedSuffix = `.${seedLower}`;
	const out: string[] = [];
	for (const rawSplit of nameValue.split(/[\n,]/)) {
		let host = rawSplit.trim().toLowerCase();
		if (!host) continue;
		// Strip wildcard prefix — the bare apex is what we actually want.
		if (host.startsWith('*.')) host = host.slice(2);
		if (!host) continue;
		// Drop the seed itself.
		if (host === seedLower) continue;
		// Drop subdomains of the seed. `endsWith('.' + seed)` so that
		// `notexample.com` is *not* treated as a subdomain of `example.com`.
		if (host.endsWith(seedSuffix)) continue;
		// SSRF / format guard.
		const validation = validateDomain(host);
		if (!validation.valid) continue;
		out.push(host);
	}
	return out;
}

/**
 * Correlate co-owned sibling domains for a seed via crt.sh SAN clustering.
 *
 * @throws Error with the `'Domain validation failed:'` prefix when the seed
 *   does not pass `validateDomain`. All other failure modes (network error,
 *   429 rate limit, timeout, oversize body, malformed JSON) are returned as
 *   `queryStatus: 'rate_limited' | 'timeout' | 'error'` rather than thrown.
 */
export async function correlateSans(
	seedDomain: string,
	options: SanCorrelationOptions = {},
): Promise<SanCorrelationResult> {
	// Validate FIRST — outside the network try/catch — so a bad seed surfaces
	// to the caller as a thrown error rather than getting swallowed and
	// returned as `queryStatus: 'error'`. The thrown prefix matches the
	// project's `SAFE_ERROR_PREFIXES` allowlist.
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');

	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const maxCerts = options.maxCertsPerDomain ?? DEFAULT_MAX_CERTS;
	const fetchFn = options.fetchFn ?? safeFetch;

	const url = `https://crt.sh/?q=${encodeURIComponent(seedLower)}&output=json`;

	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

	let response: Response;
	try {
		response = await fetchFn(url, { signal: controller.signal, redirect: 'manual' });
	} catch (err) {
		clearTimeout(timeoutId);
		if (err instanceof Error && err.name === 'AbortError') {
			return emptyResult(seedLower, 'timeout');
		}
		return emptyResult(seedLower, 'error');
	}
	clearTimeout(timeoutId);

	if (response.status === 429) {
		return emptyResult(seedLower, 'rate_limited');
	}
	if (!response.ok) {
		return emptyResult(seedLower, 'error');
	}

	// Pre-flight cap via Content-Length when available to short-circuit
	// pathologically large responses before parsing.
	const contentLength = response.headers.get('content-length');
	if (contentLength) {
		const declared = Number.parseInt(contentLength, 10);
		if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
			return emptyResult(seedLower, 'error');
		}
	}

	let entries: CrtShEntry[];
	try {
		const text = await response.text();
		if (text.length > MAX_BODY_BYTES) {
			return emptyResult(seedLower, 'error');
		}
		const parsed = JSON.parse(text);
		if (!Array.isArray(parsed)) {
			return emptyResult(seedLower, 'error');
		}
		entries = parsed as CrtShEntry[];
	} catch (err) {
		if (err instanceof Error && err.name === 'AbortError') {
			return emptyResult(seedLower, 'timeout');
		}
		return emptyResult(seedLower, 'error');
	}

	if (entries.length === 0) {
		return { seedDomain: seedLower, coOwnedDomains: [], certIds: [], queryStatus: 'ok' };
	}

	// Sort newest-first, then cap. Without sorting, the cap silently drops
	// the most-recent (most-relevant) certificate observations.
	const ranked = sortEntriesNewestFirst(entries).slice(0, Math.max(0, maxCerts));

	const siblings = new Set<string>();
	const certIds: number[] = [];
	for (const entry of ranked) {
		if (typeof entry.id === 'number') certIds.push(entry.id);
		const nameValue = entry.name_value;
		if (typeof nameValue !== 'string' || !nameValue) continue;
		for (const sibling of extractSiblingsFromNameValue(nameValue, seedLower)) {
			siblings.add(sibling);
		}
	}

	const coOwnedDomains = Array.from(siblings).sort();
	return { seedDomain: seedLower, coOwnedDomains, certIds, queryStatus: 'ok' };
}
