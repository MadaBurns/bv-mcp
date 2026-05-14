// SPDX-License-Identifier: BUSL-1.1

/**
 * NS-correlator (Phase-4 brand-discovery, tier-1 signal).
 *
 * Correlates a seed domain to a set of candidate domains by NS-record overlap.
 * A perfect overlap (confidence 1.0) is a near-deterministic ownership signal:
 * two domains delegating to the *exact* same nameserver hostnames are typically
 * managed in the same DNS account. Partial overlap (>=0.5) flags a shared
 * infrastructure cluster — could be same owner OR same managed DNS provider
 * (Cloudflare, Route 53, AWS, etc.) with different accounts; downstream code
 * should weigh accordingly.
 *
 * Failure modes follow the bv-mcp convention: this function MUST NOT throw on
 * DNS errors — only on programmer error (invalid input). Callers interrogate
 * `queryStatus` instead.
 */

import { queryDns } from '../../lib/dns-transport';
import type { DohResponse } from '../../lib/dns-types';
import { validateDomain } from '../../lib/sanitize';
import { isSharedNsHost } from './shared-ns-hosts';

/** Function signature for an injectable DNS-over-HTTPS query. */
export type DnsQueryFn = (name: string, type: 'NS' | 'TXT' | string) => Promise<DohResponse>;

export interface NsCorrelationOptions {
	/**
	 * Override the underlying DNS query implementation (used for testing).
	 * Defaults to the project's `queryDns` facade. Always called with type='NS'.
	 */
	dnsQuery?: DnsQueryFn;
	/** Optional candidate domains to test for NS overlap with the seed. */
	candidateDomains?: string[];
}

export interface NsCoOwnedCandidate {
	/** Lowercase, trailing-dot-stripped candidate domain. */
	domain: string;
	/** Lowercase nameserver hostnames shared with the seed. */
	sharedNs: string[];
	/** |intersection| / |seed_NS_set|, rounded to 2 decimals. 1.0 = full overlap. */
	confidence: number;
}

export interface NsCorrelationResult {
	seedDomain: string;
	/** Lowercase, deduped, sorted nameservers for the seed (trailing dot stripped). */
	seedNs: string[];
	/** Candidates with at least one NS in common with the seed. Sorted by domain. */
	coOwnedDomains: NsCoOwnedCandidate[];
	/**
	 * `ok` — seed and (if any) all candidates queried successfully.
	 * `partial` — seed succeeded but at least one candidate query failed.
	 * `failed` — seed query failed or returned no NS records.
	 */
	queryStatus: 'ok' | 'partial' | 'failed';
}

/** Normalise a hostname: lowercase, strip trailing dot, trim. */
function normHost(h: string): string {
	return h.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Outcome of an NS lookup:
 *  - `ok` with a populated set when records exist
 *  - `ok` with an empty set when the response was clean but had no answers
 *  - `error` when the DNS query threw / failed
 */
type NsOutcome = { kind: 'ok'; set: Set<string> } | { kind: 'error' };

async function fetchNsSet(domain: string, dnsQuery: DnsQueryFn): Promise<NsOutcome> {
	try {
		const resp = await dnsQuery(domain, 'NS');
		const answers = resp.Answer ?? [];
		const set = new Set<string>();
		for (const a of answers) {
			const host = normHost(a.data ?? '');
			if (host) set.add(host);
		}
		return { kind: 'ok', set };
	} catch {
		return { kind: 'error' };
	}
}

/** Round to 2 decimals (avoids float drift creeping into test assertions). */
function round2(n: number): number {
	return Math.round(n * 100) / 100;
}

/**
 * Correlate co-owned domains by NS-record overlap.
 *
 * @throws Error with the `'Domain validation failed:'` prefix when the seed
 *   does not pass `validateDomain`. All other failure modes (network error,
 *   empty NS, transient candidate failures) are returned via `queryStatus`.
 */
export async function correlateNs(
	seedDomain: string,
	options: NsCorrelationOptions = {},
): Promise<NsCorrelationResult> {
	const validation = validateDomain(seedDomain);
	if (!validation.valid) {
		throw new Error(`Domain validation failed: ${validation.error ?? 'invalid domain'}`);
	}
	const seedLower = normHost(seedDomain);
	const dnsQuery = options.dnsQuery ?? (queryDns as unknown as DnsQueryFn);

	const seedOutcome = await fetchNsSet(seedLower, dnsQuery);
	if (seedOutcome.kind === 'error' || seedOutcome.set.size === 0) {
		return { seedDomain: seedLower, seedNs: [], coOwnedDomains: [], queryStatus: 'failed' };
	}
	const seedNsSet = seedOutcome.set;
	const seedNs = Array.from(seedNsSet).sort();

	const candidates = options.candidateDomains ?? [];
	if (candidates.length === 0) {
		return { seedDomain: seedLower, seedNs, coOwnedDomains: [], queryStatus: 'ok' };
	}

	const coOwned: NsCoOwnedCandidate[] = [];
	let anyFailure = false;

	for (const raw of candidates) {
		const v = validateDomain(raw ?? '');
		if (!v.valid) continue;
		const candidate = normHost(raw);
		if (candidate === seedLower) continue;
		const candidateOutcome = await fetchNsSet(candidate, dnsQuery);
		if (candidateOutcome.kind === 'error') {
			anyFailure = true;
			continue;
		}
		const shared: string[] = [];
		for (const ns of candidateOutcome.set) {
			if (seedNsSet.has(ns)) shared.push(ns);
		}
		if (shared.length === 0) continue;

		// Slice 6 — multi-tenant NS filter (LR-2 defense in depth).
		// Parking services / shared-tenant DNS providers publish the same NS
		// hostnames across many unrelated customers. Their overlap is operational
		// plumbing, not ownership evidence — exclude them from the confidence
		// math. Hyperscale managed DNS (Cloudflare, Route 53, GCP) assigns unique
		// NS per account, so those remain ownership-bearing.
		const ownershipBearingShared = shared.filter((ns) => !isSharedNsHost(ns));
		if (ownershipBearingShared.length === 0) continue;

		coOwned.push({
			domain: candidate,
			sharedNs: shared.sort(),
			confidence: round2(ownershipBearingShared.length / seedNsSet.size),
		});
	}

	coOwned.sort((a, b) => a.domain.localeCompare(b.domain));

	return {
		seedDomain: seedLower,
		seedNs,
		coOwnedDomains: coOwned,
		queryStatus: anyFailure ? 'partial' : 'ok',
	};
}
