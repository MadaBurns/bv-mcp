// SPDX-License-Identifier: BUSL-1.1

/**
 * CNAME-alignment ownership detector.
 *
 * Walks the CNAME chain starting at each candidate's apex (bounded by
 * MAX_CHAIN_LENGTH) and checks whether any step lands on the seed apex,
 * a subdomain of the seed, or a CDN edge alias that matches a seed-rooted
 * pattern (e.g. `brand-zeta.example.com.akadns.net` for `brand-zeta.example.com`'s Akamai tenant).
 */

import { validateDomain } from '../../lib/sanitize';
import { mapConcurrent } from '../../lib/map-concurrent';
import { safeFetch } from '../../lib/safe-fetch';
import type { DiscoveryDnsContext } from './dns-context';

const DEFAULT_DOH_URL = 'https://cloudflare-dns.com/dns-query';
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_CHAIN_LENGTH = 5;

/** Known CDN edge suffixes — a CNAME to `<seed>.<suffix>` is a strong tenant signal. */
const EDGE_SUFFIXES = [
	'akadns.net',
	'edgesuite.net',
	'edgekey.net',
	'akamaiedge.net',
	'cloudfront.net',
	'fastly.net',
	'azureedge.net',
	'azurewebsites.net',
	'cdn.cloudflare.net',
	'b-cdn.net',
];

export interface CnameAlignmentOptions {
	candidateDomains: string[];
	dohFn?: typeof fetch;
	dohUrl?: string;
	timeoutMs?: number;
	dnsContext?: DiscoveryDnsContext;
}

export interface CnameAlignmentResult {
	coOwnedDomains: Array<{
		domain: string;
		confidence: number;
		evidence: { chain: string[]; matchType: 'seed-rooted' | 'edge-alias' };
	}>;
	queryStatus: 'ok' | 'error';
}

type CnameAlignmentCandidate = CnameAlignmentResult['coOwnedDomains'][number];

interface DohResponse {
	Status: number;
	Answer?: Array<{ name: string; type: number; TTL: number; data: string }>;
}

async function queryCname(name: string, dohFn: typeof fetch, dohUrl: string, timeoutMs: number): Promise<string | null> {
	const url = `${dohUrl}?name=${encodeURIComponent(name)}&type=CNAME`;
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const resp = await dohFn(url, {
			headers: { Accept: 'application/dns-json' },
			signal: controller.signal,
		});
		clearTimeout(timeoutId);
		if (!resp.ok) return null;
		const json = (await resp.json()) as DohResponse;
		if (json.Status !== 0 || !json.Answer || json.Answer.length === 0) return null;
		const cname = json.Answer[0]?.data;
		if (!cname) return null;
		return cname.toLowerCase().replace(/\.$/, '');
	} catch {
		clearTimeout(timeoutId);
		return null;
	}
}

async function queryCnameWithContext(name: string, dnsContext: DiscoveryDnsContext): Promise<string | null> {
	try {
		const json = await dnsContext.query(name, 'CNAME');
		if (json.Status !== 0 || !json.Answer || json.Answer.length === 0) return null;
		const cname = json.Answer[0]?.data;
		if (!cname) return null;
		return cname.toLowerCase().replace(/\.$/, '');
	} catch {
		return null;
	}
}

function isSeedRooted(host: string, seed: string): boolean {
	const h = host.toLowerCase().replace(/\.$/, '');
	const s = seed.toLowerCase().replace(/\.$/, '');
	return h === s || h.endsWith('.' + s);
}

/** True if host is `<seed>.<edge-suffix>` — a per-tenant edge alias. */
function isSeedEdgeAlias(host: string, seed: string): boolean {
	const h = host.toLowerCase().replace(/\.$/, '');
	const s = seed.toLowerCase().replace(/\.$/, '');
	for (const suffix of EDGE_SUFFIXES) {
		if (h === `${s}.${suffix}`) return true;
	}
	return false;
}

/**
 * Walk CNAMEs from `start`, bounded by MAX_CHAIN_LENGTH and a visited set.
 * Returns either a seed-rooted/edge match (with chain + matchType) or null.
 */
async function walkChain(
	start: string,
	seed: string,
	queryCnameRecord: (name: string) => Promise<string | null>,
): Promise<{ chain: string[]; matchType: 'seed-rooted' | 'edge-alias' } | null> {
	const visited = new Set<string>();
	const chain: string[] = [start];
	let current = start;

	while (chain.length <= MAX_CHAIN_LENGTH) {
		if (visited.has(current)) return null;
		visited.add(current);

		const next = await queryCnameRecord(current);
		if (!next) {
			// Terminal — last hop is `current`. Check if it qualifies.
			if (chain.length > 1) {
				const last = chain[chain.length - 1];
				if (isSeedRooted(last, seed)) return { chain, matchType: 'seed-rooted' };
				if (isSeedEdgeAlias(last, seed)) return { chain, matchType: 'edge-alias' };
			}
			return null;
		}

		chain.push(next);
		if (isSeedRooted(next, seed)) return { chain, matchType: 'seed-rooted' };
		if (isSeedEdgeAlias(next, seed)) return { chain, matchType: 'edge-alias' };
		current = next;
	}

	return null;
}

export async function detectCnameAlignment(
	seedDomain: string,
	options: CnameAlignmentOptions,
): Promise<CnameAlignmentResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = seedDomain.trim().toLowerCase().replace(/\.$/, '');
	const dohFn = options.dohFn ?? safeFetch;
	const dohUrl = options.dohUrl ?? DEFAULT_DOH_URL;
	const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
	const dnsContext = options.dnsContext;
	const queryCnameRecord = dnsContext
		? (name: string) => queryCnameWithContext(name, dnsContext)
		: (name: string) => queryCname(name, dohFn, dohUrl, timeoutMs);

	if (options.candidateDomains.length === 0) {
		return { coOwnedDomains: [], queryStatus: 'ok' };
	}

	const settled = await mapConcurrent(options.candidateDomains, 6, async (cand): Promise<PromiseSettledResult<CnameAlignmentCandidate | null>> => {
		try {
			const candLower = cand.trim().toLowerCase().replace(/\.$/, '');
			if (!validateDomain(candLower).valid) return { status: 'fulfilled', value: null };
			const match = await walkChain(candLower, seedLower, queryCnameRecord);
			if (!match) return { status: 'fulfilled', value: null };
			const confidence = match.matchType === 'seed-rooted' ? 0.9 : 0.6;
			return {
				status: 'fulfilled',
				value: {
					domain: candLower,
					confidence,
					evidence: { chain: match.chain, matchType: match.matchType },
				},
			};
		} catch (reason) {
			return { status: 'rejected', reason };
		}
	});

	const coOwnedDomains = settled
		.filter((r): r is PromiseFulfilledResult<CnameAlignmentCandidate> => r.status === 'fulfilled' && r.value !== null)
		.map((r) => r.value);

	return { coOwnedDomains, queryStatus: 'ok' };
}
