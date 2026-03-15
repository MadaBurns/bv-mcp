// SPDX-License-Identifier: MIT

/**
 * Curated public suffix list subset for multi-level TLD matching.
 * Used to extract the registrable brand name from a domain.
 *
 * Stored as a Set of dot-joined suffixes for O(1) lookup.
 */
const MULTI_LEVEL_SUFFIXES = new Set([
	// NZ
	'co.nz',
	'govt.nz',
	'org.nz',
	'net.nz',
	'ac.nz',
	'school.nz',
	'gen.nz',
	// UK
	'co.uk',
	'org.uk',
	'me.uk',
	'net.uk',
	'gov.uk',
	'ac.uk',
	// AU
	'com.au',
	'org.au',
	'net.au',
	'gov.au',
	'edu.au',
	// JP
	'co.jp',
	'or.jp',
	'ne.jp',
	'go.jp',
	'ac.jp',
	// ZA
	'co.za',
	'org.za',
	'gov.za',
	'net.za',
	// IN
	'co.in',
	'org.in',
	'net.in',
	'gov.in',
	// SG
	'com.sg',
	'org.sg',
	'gov.sg',
]);

/**
 * Determine the effective TLD for a domain by matching against
 * the curated multi-level suffix list.
 *
 * Walk domain labels right-to-left, checking progressively longer
 * suffixes against the PSL set. If a multi-level match is found,
 * that is the effective TLD. Otherwise the rightmost label is the TLD.
 *
 * Returns `null` if the input is empty, single-label, or is itself
 * a TLD suffix (i.e., there is no registrable label to the left).
 */
export function getEffectiveTld(domain: string): string | null {
	if (!domain) return null;

	// Strip trailing dot (e.g., "example.com." → "example.com")
	const normalized = domain.endsWith('.') ? domain.slice(0, -1) : domain;
	if (!normalized) return null;

	const labels = normalized.toLowerCase().split('.');
	if (labels.length < 2) return null;

	// Walk from rightmost label, building candidate suffixes
	// and checking for multi-level matches (longest match wins).
	let effectiveTld: string | null = null;

	for (let i = labels.length - 2; i >= 0; i--) {
		const candidate = labels.slice(i).join('.');
		if (MULTI_LEVEL_SUFFIXES.has(candidate)) {
			effectiveTld = candidate;
			// Keep checking for even longer matches (though unlikely with current data)
		} else {
			// No longer suffix can match if this intermediate one didn't
			break;
		}
	}

	// If no multi-level match, the rightmost label is the TLD
	if (!effectiveTld) {
		effectiveTld = labels[labels.length - 1];
	}

	// The effective TLD must leave at least one label to the left (the brand)
	const tldLabels = effectiveTld.split('.');
	if (tldLabels.length >= labels.length) {
		// The input IS the TLD suffix itself — no registrable domain
		return null;
	}

	return effectiveTld;
}

/**
 * Extract the registrable brand name from a domain.
 *
 * The brand name is the label immediately to the left of the effective TLD.
 * Subdomains further to the left are stripped.
 *
 * @example
 * extractBrandName('tewhatuora.govt.nz') // => 'tewhatuora'
 * extractBrandName('sub.example.co.nz')  // => 'example'
 * extractBrandName('blackveil.nz')       // => 'blackveil'
 * extractBrandName('co.nz')              // => null (bare TLD suffix)
 * extractBrandName('com')                // => null (single label)
 */
export function extractBrandName(domain: string): string | null {
	const tld = getEffectiveTld(domain);
	if (!tld) return null;

	// Strip trailing dot to match getEffectiveTld normalization
	const normalized = domain.endsWith('.') ? domain.slice(0, -1) : domain;
	const labels = normalized.toLowerCase().split('.');
	const tldLabels = tld.split('.');

	// The brand label is at position (total labels - TLD labels - 1)
	const brandIndex = labels.length - tldLabels.length - 1;
	if (brandIndex < 0) return null;

	return labels[brandIndex];
}
