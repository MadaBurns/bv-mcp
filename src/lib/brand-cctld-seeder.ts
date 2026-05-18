// SPDX-License-Identifier: BUSL-1.1

/**
 * ccTLD candidate seeder for brand-domain discovery.
 *
 * Given a seed apex (`amazon.com`), emits `<base>.<tld>` for a curated set of
 * common ccTLDs and gTLDs. Feeds the NS-correlator's `candidateDomains` list
 * so big brands whose portfolio is ccTLD-dominated (Amazon, Microsoft, Nike)
 * surface through discovery — Markov-only seeding misses them because it
 * keeps the seed's own TLD.
 *
 * Allowlist is deterministic, brand-agnostic, and intentionally short — the
 * NS correlator filters non-matches via real DNS, so false positives have
 * zero impact beyond a handful of extra queries.
 */

import { buildBrandCandidateUniverse } from './brand-candidate-universe';

/**
 * Emit `<base>.<tld>` for every TLD in the allowlist except the seed itself.
 * Output is deduplicated, lowercase, and trailing-dot-free.
 */
export function generateCctldVariants(seed: string): string[] {
	return buildBrandCandidateUniverse({ seedDomain: seed, depth: 'standard' })
		.candidates
		.filter((candidate) => candidate.sources.includes('tld_sweep'))
		.map((candidate) => candidate.domain);
}
