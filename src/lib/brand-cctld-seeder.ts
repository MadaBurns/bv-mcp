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

/**
 * Common ccTLDs + gTLDs typically registered by global brands. Ordered
 * roughly by likelihood-of-registration; consumers shouldn't depend on order.
 */
const COMMON_TLDS = [
	'com', 'net', 'org', 'co',
	'de', 'fr', 'es', 'it', 'nl', 'be', 'pl', 'se', 'no', 'dk', 'fi', 'ch', 'at',
	'co.uk', 'uk', 'ie',
	'co.jp', 'jp', 'kr', 'cn', 'tw', 'hk', 'sg',
	'com.au', 'au', 'nz',
	'ca', 'mx', 'br', 'ar', 'cl',
	'in', 'ae', 'sa', 'za',
	'ru', 'tr',
] as const;

/**
 * Extract the bare brand base (left-most label) from a seed domain. Handles
 * trailing dots and mixed case. Returns `null` if the input doesn't parse as
 * a domain.
 */
function extractBase(seed: string): string | null {
	const cleaned = seed.trim().toLowerCase().replace(/\.+$/, '');
	if (!cleaned || cleaned.startsWith('.')) return null;
	const first = cleaned.split('.')[0];
	if (!first || first.length === 0 || !/^[a-z0-9-]+$/.test(first)) return null;
	if (!cleaned.includes('.')) return null;
	return first;
}

/**
 * Emit `<base>.<tld>` for every TLD in the allowlist except the seed itself.
 * Output is deduplicated, lowercase, and trailing-dot-free.
 */
export function generateCctldVariants(seed: string): string[] {
	const base = extractBase(seed);
	if (!base) return [];
	const seedNormalized = seed.trim().toLowerCase().replace(/\.+$/, '');
	const out = new Set<string>();
	for (const tld of COMMON_TLDS) {
		const candidate = `${base}.${tld}`;
		if (candidate === seedNormalized) continue;
		out.add(candidate);
	}
	return Array.from(out);
}
