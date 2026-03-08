/**
 * Lookalike domain generation utilities.
 * Generates typosquat/lookalike domain permutations using multiple strategies:
 * adjacent key swaps, character omission, character duplication, dot insertion,
 * common TLD swaps, and homoglyph substitution.
 */

import { LABEL_REGEX, MAX_DOMAIN_LENGTH, MAX_LABEL_LENGTH } from '../lib/config';

/** QWERTY keyboard adjacency map for typosquat detection */
const QWERTY_ADJACENT: Record<string, string[]> = {
	q: ['w', 'a'],
	w: ['q', 'e', 's', 'a'],
	e: ['w', 'r', 'd', 's'],
	r: ['e', 't', 'f', 'd'],
	t: ['r', 'y', 'g', 'f'],
	y: ['t', 'u', 'h', 'g'],
	u: ['y', 'i', 'j', 'h'],
	i: ['u', 'o', 'k', 'j'],
	o: ['i', 'p', 'l', 'k'],
	p: ['o', 'l'],
	a: ['q', 'w', 's', 'z'],
	s: ['a', 'w', 'e', 'd', 'z', 'x'],
	d: ['s', 'e', 'r', 'f', 'x', 'c'],
	f: ['d', 'r', 't', 'g', 'c', 'v'],
	g: ['f', 't', 'y', 'h', 'v', 'b'],
	h: ['g', 'y', 'u', 'j', 'b', 'n'],
	j: ['h', 'u', 'i', 'k', 'n', 'm'],
	k: ['j', 'i', 'o', 'l', 'm'],
	l: ['k', 'o', 'p'],
	z: ['a', 's', 'x'],
	x: ['z', 's', 'd', 'c'],
	c: ['x', 'd', 'f', 'v'],
	v: ['c', 'f', 'g', 'b'],
	b: ['v', 'g', 'h', 'n'],
	n: ['b', 'h', 'j', 'm'],
	m: ['n', 'j', 'k'],
};

/** Homoglyph substitution pairs (one substitution at a time) */
const HOMOGLYPHS: Array<[string, string]> = [
	['o', '0'],
	['0', 'o'],
	['l', '1'],
	['1', 'l'],
	['i', '1'],
	['1', 'i'],
	['l', 'i'],
	['i', 'l'],
	['rn', 'm'],
	['m', 'rn'],
	['vv', 'w'],
	['w', 'vv'],
];

/** Common TLD swap pairs */
const TLD_SWAPS: Array<[string, string]> = [
	['.com', '.co'],
	['.com', '.net'],
	['.com', '.org'],
	['.com', '.io'],
	['.co.nz', '.com'],
	['.com.au', '.com'],
];

/** Maximum number of permutations to return */
const MAX_PERMUTATIONS = 50;

/**
 * Split a domain into base (before TLD) and TLD parts.
 * Handles multi-part TLDs like .co.nz and .com.au.
 */
function splitDomainTld(domain: string): { base: string; tld: string } {
	const multiPartTlds = ['.co.nz', '.com.au', '.co.uk', '.org.uk', '.net.au', '.org.au'];
	for (const multiTld of multiPartTlds) {
		if (domain.endsWith(multiTld)) {
			return { base: domain.slice(0, -multiTld.length), tld: multiTld };
		}
	}
	const lastDot = domain.lastIndexOf('.');
	if (lastDot === -1) return { base: domain, tld: '' };
	return { base: domain.slice(0, lastDot), tld: domain.slice(lastDot) };
}

/**
 * Check whether a domain string is structurally valid.
 * Labels must be 1-63 chars, alphanumeric + hyphens, total <= 253 chars.
 */
function isDomainValid(domain: string): boolean {
	if (domain.length > MAX_DOMAIN_LENGTH) return false;
	const labels = domain.split('.');
	if (labels.length < 2) return false;
	for (const label of labels) {
		if (label.length === 0 || label.length > MAX_LABEL_LENGTH) return false;
		if (!LABEL_REGEX.test(label)) return false;
	}
	return true;
}

/**
 * Generate lookalike/typosquat domain permutations for a given domain.
 * Applies six strategies: adjacent key swaps, character omission, character duplication,
 * dot insertion, common TLD swaps, and homoglyph substitution.
 *
 * Returns up to 50 unique, valid, alphabetically sorted permutations.
 */
export function generateLookalikes(domain: string): string[] {
	const normalizedDomain = domain.toLowerCase();
	const { base, tld } = splitDomainTld(normalizedDomain);
	const candidates = new Set<string>();

	// 1. Adjacent key swaps — swap each char in base with QWERTY adjacent keys
	for (let i = 0; i < base.length; i++) {
		const ch = base[i];
		const adjacent = QWERTY_ADJACENT[ch];
		if (adjacent) {
			for (const adj of adjacent) {
				const permuted = base.slice(0, i) + adj + base.slice(i + 1);
				candidates.add(permuted + tld);
			}
		}
	}

	// 2. Character omission — remove one char at a time from base
	for (let i = 0; i < base.length; i++) {
		const permuted = base.slice(0, i) + base.slice(i + 1);
		if (permuted.length > 0) {
			candidates.add(permuted + tld);
		}
	}

	// 3. Character duplication — double one char at a time in base
	for (let i = 0; i < base.length; i++) {
		const permuted = base.slice(0, i) + base[i] + base[i] + base.slice(i + 1);
		candidates.add(permuted + tld);
	}

	// 4. Dot insertion — insert dots between chars in base (both parts must be >= 2 chars)
	for (let i = 1; i < base.length; i++) {
		const left = base.slice(0, i);
		const right = base.slice(i);
		if (left.length >= 2 && right.length >= 2) {
			candidates.add(left + '.' + right + tld);
		}
	}

	// 5. Common TLD swaps — swap to different TLD if original matches
	for (const [fromTld, toTld] of TLD_SWAPS) {
		if (tld === fromTld) {
			candidates.add(base + toTld);
		} else if (tld === toTld) {
			candidates.add(base + fromTld);
		}
	}

	// 6. Homoglyph substitution — one substitution at a time in base
	for (const [from, to] of HOMOGLYPHS) {
		let searchIdx = 0;
		while (searchIdx <= base.length - from.length) {
			const idx = base.indexOf(from, searchIdx);
			if (idx === -1) break;
			const permuted = base.slice(0, idx) + to + base.slice(idx + from.length);
			candidates.add(permuted + tld);
			searchIdx = idx + 1;
		}
	}

	// Filter, dedup, and cap
	const results = Array.from(candidates)
		.filter((candidate) => candidate !== normalizedDomain && isDomainValid(candidate))
		.sort();

	return results.slice(0, MAX_PERMUTATIONS);
}
