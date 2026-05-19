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
import type { DohResponse, RecordTypeName } from '../../lib/dns-types';
import { mapConcurrent } from '../../lib/map-concurrent';
import { validateDomain } from '../../lib/sanitize';
import { isSharedNsHost } from './shared-ns-hosts';
import type { DiscoveryDnsContext } from './dns-context';

/** Function signature for an injectable DNS-over-HTTPS query. */
export type DnsQueryFn = (name: string, type: RecordTypeName) => Promise<DohResponse>;

export interface NsCorrelationOptions {
	/**
	 * Override the underlying DNS query implementation (used for testing).
	 * Defaults to the project's `queryDns` facade. Always called with type='NS'.
	 */
	dnsQuery?: DnsQueryFn;
	dnsContext?: DiscoveryDnsContext;
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
	const dnsQuery = options.dnsContext?.query ?? options.dnsQuery ?? (queryDns as unknown as DnsQueryFn);

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

	const probed = await mapConcurrent(candidates, 6, async (raw): Promise<{ candidate: NsCoOwnedCandidate | null; failed: boolean }> => {
		const v = validateDomain(raw ?? '');
		if (!v.valid) return { candidate: null, failed: false };
		const candidate = normHost(raw);
		if (candidate === seedLower) return { candidate: null, failed: false };
		const candidateOutcome = await fetchNsSet(candidate, dnsQuery);
		if (candidateOutcome.kind === 'error') {
			return { candidate: null, failed: true };
		}
		const shared: string[] = [];
		for (const ns of candidateOutcome.set) {
			if (seedNsSet.has(ns)) shared.push(ns);
		}
		if (shared.length === 0) return { candidate: null, failed: false };

		// Slice 6 — multi-tenant NS filter (LR-2 defense in depth).
		// Parking services / shared-tenant DNS providers publish the same NS
		// hostnames across many unrelated customers. Their overlap is operational
		// plumbing, not ownership evidence — exclude them from the confidence
		// math. Hyperscale managed DNS (Cloudflare, Route 53, GCP) assigns unique
		// NS per account, so those remain ownership-bearing.
		const ownershipBearingShared = shared.filter((ns) => !isSharedNsHost(ns));
		if (ownershipBearingShared.length === 0) return { candidate: null, failed: false };

		return {
			candidate: {
				domain: candidate,
				sharedNs: shared.sort(),
				confidence: round2(ownershipBearingShared.length / seedNsSet.size),
			},
			failed: false,
		};
	});

	const anyFailure = probed.some((result) => result.failed);
	coOwned.push(...probed.flatMap((result) => (result.candidate ? [result.candidate] : [])));

	coOwned.sort((a, b) => a.domain.localeCompare(b.domain));

	return {
		seedDomain: seedLower,
		seedNs,
		coOwnedDomains: coOwned,
		queryStatus: anyFailure ? 'partial' : 'ok',
	};
}
