// SPDX-License-Identifier: BUSL-1.1

import type { Finding } from './scoring';
import { mxRoutedIntoSeed } from './ownership-attribution';

/** Describes existing MX prefilter observations; neither result is an ownership verdict. */
export function describeMxOwnershipPredicate(input: {
	seedDomain: string;
	seedMx?: readonly string[];
	candidateMx?: readonly string[];
	candidateProbeDegraded?: boolean;
}): {
	candidatePrefilter: 'satisfied' | 'not_satisfied_external_mx' | 'not_satisfied_no_real_mx' | 'unknown';
	seedMxPlacement: 'inside_seed_bailiwick' | 'outside_seed_bailiwick' | 'mixed' | 'unknown';
} {
	const validHosts = (hosts: readonly string[]) =>
		hosts.every((host) => {
			const normalized = host.replace(/\.$/, '');
			return normalized.length <= 253 && normalized.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
		});
	const candidate = input.candidateMx;
	const candidatePrefilter =
		input.candidateProbeDegraded || !candidate || !validHosts(candidate)
			? 'unknown'
			: candidate.length === 0
				? 'not_satisfied_no_real_mx'
				: mxRoutedIntoSeed(candidate, input.seedDomain)
					? 'satisfied'
					: 'not_satisfied_external_mx';
	// queryPrimaryMx collapses failed and empty queries: an empty set cannot establish absence.
	const seed = input.seedMx;
	let seedMxPlacement: 'inside_seed_bailiwick' | 'outside_seed_bailiwick' | 'mixed' | 'unknown' = 'unknown';
	if (seed && seed.length > 0 && validHosts(seed)) {
		const inside = seed.map((host) => mxRoutedIntoSeed([host], input.seedDomain));
		seedMxPlacement = inside.every(Boolean) ? 'inside_seed_bailiwick' : inside.some(Boolean) ? 'mixed' : 'outside_seed_bailiwick';
	}
	return { candidatePrefilter, seedMxPlacement };
}

/** Attach observations only to findings for candidates actually probed in this run. */
export function attachMxOwnershipPredicateReporting(
	findings: Finding[],
	candidates: readonly { domain: string; mxExchanges: string[]; probeDegraded: boolean }[],
	seedDomain: string,
	seedMx: readonly string[],
): void {
	const measuredByDomain = new Map(candidates.map((candidate) => [candidate.domain, candidate]));
	for (const finding of findings) {
		const domain = finding.metadata?.lookalikeDomain;
		const candidate = typeof domain === 'string' ? measuredByDomain.get(domain) : undefined;
		if (!candidate) continue;
		finding.metadata = {
			...finding.metadata,
			mxOwnershipPredicate: describeMxOwnershipPredicate({
				seedDomain,
				seedMx,
				candidateMx: candidate.mxExchanges,
				candidateProbeDegraded: candidate.probeDegraded,
			}),
		};
	}
}
