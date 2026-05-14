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

import { JSONParser } from '@streamparser/json-whatwg';
import { safeFetch } from '../../lib/safe-fetch';
import { validateDomain } from '../../lib/sanitize';

/** Default request timeout (ms). */
const DEFAULT_TIMEOUT_MS = 15_000;

/** Default cap on certs to consider per seed query. */
const DEFAULT_MAX_CERTS = 200;

/**
 * Signal Saturation: If we process this many certificates without discovering
 * a new unique sibling domain, we assume the signal is saturated and abort.
 */
const SATURATION_THRESHOLD = 100;

/**
 * Hard safety cap on the raw stream bytes to prevent runaway resource usage.
 */
const MAX_STREAM_BYTES = 25 * 1024 * 1024;

export interface SanCorrelationOptions {
	/** Request timeout in ms. Defaults to 15000. */
	timeoutMs?: number;
	/** Cap on the number of crt.sh entries that contribute to the result. Defaults to 200. */
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
 * Build the empty/error-shape result.
 */
function emptyResult(seedDomain: string, status: SanCorrelationResult['queryStatus']): SanCorrelationResult {
	return { seedDomain, coOwnedDomains: [], certIds: [], queryStatus: status };
}

/**
 * Extract sibling domains from a single SAN string.
 */
function extractSiblingsFromNameValue(nameValue: string, seedLower: string): string[] {
	const seedSuffix = `.${seedLower}`;
	const out: string[] = [];
	for (const rawSplit of nameValue.split(/[\n,]/)) {
		let host = rawSplit.trim().toLowerCase();
		if (!host) continue;
		if (host.startsWith('*.')) host = host.slice(2);
		if (!host) continue;
		if (host === seedLower) continue;
		if (host.endsWith(seedSuffix)) continue;
		const validation = validateDomain(host);
		if (!validation.valid) continue;
		out.push(host);
	}
	return out;
}

/**
 * Correlate co-owned sibling domains for a seed via crt.sh SAN clustering.
 * Uses a streaming JSON parser to handle large certificate histories (Tier-1 brands).
 */
export async function correlateSans(
	seedDomain: string,
	options: SanCorrelationOptions = {},
): Promise<SanCorrelationResult> {
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
		if (err instanceof Error && err.name === 'AbortError') return emptyResult(seedLower, 'timeout');
		return emptyResult(seedLower, 'error');
	}
	clearTimeout(timeoutId);

	if (response.status === 429) return emptyResult(seedLower, 'rate_limited');
	if (!response.ok) return emptyResult(seedLower, 'error');

	const body = response.body;
	if (!body) return emptyResult(seedLower, 'ok');

	const siblings = new Set<string>();
	const certIds: number[] = [];
	let certsProcessed = 0;
	let certsSinceNewDomain = 0;
	let bytesProcessed = 0;
// Initialize streaming parser for a flat array of objects
const parser = new JSONParser({ paths: ['$.*'] });

// Byte counter to enforce safety cap
const byteCounter = new TransformStream<Uint8Array, Uint8Array>({
	transform(chunk, ctrl) {
		bytesProcessed += chunk.length;
		if (bytesProcessed > MAX_STREAM_BYTES) {
			ctrl.error(new Error('Stream size limit exceeded'));
		} else {
			ctrl.enqueue(chunk);
		}
	},
});

const reader = body.pipeThrough(byteCounter).pipeThrough(parser).getReader();

try {
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;

		// value is a StackElement from @streamparser/json
		// Handle both individual objects and arrays (just in case)
		const entries = Array.isArray(value.value) ? value.value : [value.value];

		for (const entryRaw of entries) {
			const entry = entryRaw as CrtShEntry;
			if (!entry) continue;
			certsProcessed++;

			let foundNew = false;
			if (typeof entry.id === 'number') certIds.push(entry.id);
			const nameValue = entry.name_value;
			if (typeof nameValue === 'string' && nameValue) {
				for (const sibling of extractSiblingsFromNameValue(nameValue, seedLower)) {
					if (!siblings.has(sibling)) {
						siblings.add(sibling);
						foundNew = true;
					}
				}
			}

			if (foundNew) {
				certsSinceNewDomain = 0;
			} else {
				certsSinceNewDomain++;
			}

			// Stop if we hit the hard cap or signal saturation
			if (certsProcessed >= maxCerts || certsSinceNewDomain >= SATURATION_THRESHOLD) {
				await reader.cancel();
				break;
			}
		}
	}
} catch (err) {
		// If it's the stream limit error, we return what we have so far as partial success
		if (err instanceof Error && err.message === 'Stream size limit exceeded') {
			return {
				seedDomain: seedLower,
				coOwnedDomains: Array.from(siblings).sort(),
				certIds,
				queryStatus: 'ok',
			};
		}
		// Any other error (malformed JSON, network drop mid-stream)
		return emptyResult(seedLower, 'error');
	}

	return {
		seedDomain: seedLower,
		coOwnedDomains: Array.from(siblings).sort(),
		certIds,
		queryStatus: 'ok',
	};
}
