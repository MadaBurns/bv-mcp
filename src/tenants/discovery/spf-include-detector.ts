// SPDX-License-Identifier: BUSL-1.1

/**
 * SPF-include ownership detector.
 *
 * Checks whether a candidate's SPF record (recursively, RFC 7208 §4.6.4
 * 10-lookup cap) includes the seed domain or any subdomain of the seed.
 * Including the seed's SPF policy requires the seed's operator to authorize
 * the candidate's mail egress — near-deterministic ownership evidence.
 *
 * Shared-provider includes (e.g. `_spf.google.com`, `_spf.salesforce.com`)
 * are filtered out — those indicate SaaS usage, not ownership. The seed
 * itself is exempt from the "shared provider" filter (so when seed IS
 * google.com, an include of `_spf.google.com` is real evidence).
 */

import { validateDomain } from '../../lib/sanitize';
import { safeFetch } from '../../lib/safe-fetch';

const DEFAULT_DOH_URL = 'https://cloudflare-dns.com/dns-query';
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_LOOKUPS = 10; // RFC 7208 §4.6.4

/** Public SPF providers — includes of these are not ownership evidence (unless seed IS the provider). */
const SHARED_SPF_PROVIDERS = new Set([
	'_spf.google.com',
	'spf.protection.outlook.com',
	'amazonses.com',
	'_spf.salesforce.com',
	'sendgrid.net',
	'mailgun.org',
	'_spf.mailgun.org',
	'spf.mandrillapp.com',
	'_spf.mtasv.net',
	'_spf.intermedia.net',
	'mailchimp.com',
	'_spf.brevo.com',
]);

export interface SpfIncludeOptions {
	candidateDomains: string[];
	dohFn?: typeof fetch;
	dohUrl?: string;
	timeoutMs?: number;
}

export interface SpfIncludeResult {
	coOwnedDomains: Array<{
		domain: string;
		confidence: number;
		evidence: { include: string };
	}>;
	queryStatus: 'ok' | 'error';
}

interface DohResponse {
	Status: number;
	Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

async function queryTxt(name: string, dohFn: typeof fetch, dohUrl: string, timeoutMs: number): Promise<string[]> {
	const url = `${dohUrl}?name=${encodeURIComponent(name)}&type=TXT`;
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const resp = await dohFn(url, {
			headers: { Accept: 'application/dns-json' },
			signal: controller.signal,
		});
		clearTimeout(timeoutId);
		if (!resp.ok) return [];
		const json = (await resp.json()) as DohResponse;
		if (json.Status !== 0 || !json.Answer) return [];
		// TXT data comes as quoted, possibly multi-string ("a" "b") → concatenate.
		return json.Answer.map((a) =>
			a.data
				.replace(/(?:^|\s)"([^"]*)"/g, (_, s: string) => s)
				.trim(),
		);
	} catch {
		clearTimeout(timeoutId);
		return [];
	}
}

/** Find SPF record from a TXT list. RFC 7208: only one SPF record per domain. */
function pickSpfRecord(txts: string[]): string | null {
	for (const txt of txts) {
		if (/^v=spf1\b/i.test(txt)) return txt;
	}
	return null;
}

/** Parse `include:host` mechanisms from an SPF record. */
function parseIncludes(spf: string): string[] {
	const out: string[] = [];
	for (const tok of spf.split(/\s+/)) {
		const m = tok.match(/^include:([^\s]+)$/i);
		if (m) out.push(m[1].toLowerCase().replace(/\.$/, ''));
	}
	return out;
}

/** True if `host` is the seed apex or any subdomain of the seed. */
function isSeedRooted(host: string, seed: string): boolean {
	const h = host.toLowerCase().replace(/\.$/, '');
	const s = seed.toLowerCase().replace(/\.$/, '');
	return h === s || h.endsWith('.' + s);
}

/**
 * Walk a candidate's SPF include graph, bounded by MAX_LOOKUPS. Returns the
 * first seed-rooted include found (excluding shared providers), or null.
 */
async function findSeedRootedInclude(
	candidate: string,
	seed: string,
	dohFn: typeof fetch,
	dohUrl: string,
	timeoutMs: number,
): Promise<string | null> {
	const visited = new Set<string>();
	const queue: string[] = [candidate];
	let lookups = 0;

	while (queue.length > 0 && lookups < MAX_LOOKUPS) {
		const target = queue.shift()!;
		if (visited.has(target)) continue;
		visited.add(target);
		lookups++;

		const txts = await queryTxt(target, dohFn, dohUrl, timeoutMs);
		const spf = pickSpfRecord(txts);
		if (!spf) continue;

		const includes = parseIncludes(spf);
		for (const inc of includes) {
			if (isSeedRooted(inc, seed) && !SHARED_SPF_PROVIDERS.has(inc)) {
				// Allow `_spf.seed.com` even though it looks like a "provider" — it's seed-rooted.
				return inc;
			}
			// Don't descend into known shared providers — bounded recursion saves lookups.
			if (!SHARED_SPF_PROVIDERS.has(inc)) {
				queue.push(inc);
			}
		}
	}

	return null;
}

export async function detectSpfInclude(seedDomain: string, options: SpfIncludeOptions): Promise<SpfIncludeResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const dohFn = options.dohFn ?? safeFetch;
	const dohUrl = options.dohUrl ?? DEFAULT_DOH_URL;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

	if (options.candidateDomains.length === 0) {
		return { coOwnedDomains: [], queryStatus: 'ok' };
	}

	const settled = await Promise.allSettled(
		options.candidateDomains.map(async (cand) => {
			const candLower = cand.trim().toLowerCase().replace(/\.$/, '');
			if (!validateDomain(candLower).valid) return null;
			const include = await findSeedRootedInclude(candLower, seedLower, dohFn, dohUrl, timeoutMs);
			if (!include) return null;
			return {
				domain: candLower,
				confidence: 0.85,
				evidence: { include },
			};
		}),
	);

	const coOwnedDomains = settled
		.filter((r): r is PromiseFulfilledResult<NonNullable<Awaited<typeof settled[number] extends PromiseSettledResult<infer T> ? T : never>>> => r.status === 'fulfilled' && r.value !== null)
		.map((r) => r.value);

	return { coOwnedDomains, queryStatus: 'ok' };
}
