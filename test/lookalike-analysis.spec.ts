import { describe, it, expect } from 'vitest';
import {
	MAX_TLD_VARIANTS,
	generateCombosquats,
	generateLookalikes,
	generateTldVariants,
	generateTranspositions,
} from '../src/tools/lookalike-analysis';

describe('generateLookalikes', () => {
	it('generates expected permutation types for a simple domain', () => {
		const results = generateLookalikes('acme.com');
		expect(results.length).toBeGreaterThan(0);

		// Adjacent key swap: 'scme.com' (a→s)
		expect(results).toContain('scme.com');
		// Character omission: 'cme.com' (remove 'a')
		expect(results).toContain('cme.com');
		// Character duplication: 'aacme.com' (double 'a')
		expect(results).toContain('aacme.com');
		// TLD swap: 'acme.net'
		expect(results).toContain('acme.net');
	});

	it('caps output at 50 permutations', () => {
		const results = generateLookalikes('longdomainname.com');
		expect(results.length).toBeLessThanOrEqual(50);
	});

	it('does not include the original domain in results', () => {
		const results = generateLookalikes('test.com');
		expect(results).not.toContain('test.com');
	});

	it('filters out invalid domain formats', () => {
		const results = generateLookalikes('ab.com');
		for (const domain of results) {
			const labels = domain.split('.');
			expect(labels.length).toBeGreaterThanOrEqual(2);
			for (const label of labels) {
				expect(label.length).toBeGreaterThan(0);
				expect(label.length).toBeLessThanOrEqual(63);
			}
		}
	});

	it('results are deduplicated and deterministic across repeated calls (not alphabetically sorted)', () => {
		// SQ-34: a plain alphabetical sort has no relationship to typo risk and
		// was silently discarding candidates by spelling accident. Ordering is
		// now a fair-share round-robin across the six generation strategies (see
		// the function's docstring), which is NOT alphabetical order in general.
		const results = generateLookalikes('microsoft.com');
		expect(new Set(results).size).toBe(results.length);
		expect(results).toEqual(generateLookalikes('microsoft.com'));
		// The historical alphabetical-sort assertion no longer holds: with 39
		// strategy-1 candidates for this seed, a fair round-robin interleaves in
		// candidates from the smaller lanes long before the alphabet would.
		expect(results).not.toEqual([...results].sort());
	});

	it('gives every generation strategy a fair share of the cap instead of letting the largest lane win by volume', () => {
		// SQ-34: `microsoft.com` has a base long enough (9 chars) that the
		// adjacent-key (motor substitution) strategy alone produces 39 raw
		// candidates — most of MAX_PERMUTATIONS (50). Under the OLD alphabetical
		// `.sort().slice(0, 50)`, `rnicrosoft.com` (the classic 'rn'->'m'
		// homoglyph attack, e.g. against microsoft.com) and `microssoft.com`
		// (character duplication) both sorted past position 50 and were
		// silently dropped — confirmed by running the reverted implementation.
		// The fair-share round-robin recovers both because every lane gets a
		// turn before strategy 1 (keyboard adjacency) gets a second pick.
		const results = generateLookalikes('microsoft.com');
		expect(results.length).toBe(50);
		expect(results).toContain('rnicrosoft.com');
		expect(results).toContain('microssoft.com');

		// `ltmcguinness.co.nz` (12-char base) drives strategy 1 alone to 52 raw
		// candidates — MORE than the entire cap — so a plain concatenate-then-
		// slice would return the TLD-swap and homoglyph lanes as ZERO. Round-
		// robin still gives the sole TLD-swap candidate and the 'm'->'rn'
		// homoglyph a slot.
		const ltmcguinnessResults = generateLookalikes('ltmcguinness.co.nz');
		expect(ltmcguinnessResults.length).toBe(50);
		expect(ltmcguinnessResults).toContain('ltmcguinness.com');
		expect(ltmcguinnessResults).toContain('ltrncguinness.co.nz');
	});

	it('breaks ties stably: identical input always yields the identical order', () => {
		// Cache and snapshot stability requires no run-to-run flapping.
		const seeds = ['anz.com', '[redacted-domain]', 'microsoft.com', 'ltmcguinness.co.nz'];
		for (const seed of seeds) {
			expect(generateLookalikes(seed)).toEqual(generateLookalikes(seed));
		}
	});

	it('handles two-letter domain names gracefully', () => {
		const results = generateLookalikes('ab.com');
		expect(results.length).toBeGreaterThan(0);
		// Should not crash and should produce valid domains
		for (const domain of results) {
			expect(domain).toMatch(/\./);
		}
	});

	it('handles domains with hyphens', () => {
		const results = generateLookalikes('my-site.com');
		expect(results.length).toBeGreaterThan(0);
		expect(results).not.toContain('my-site.com');
	});

	it('generates homoglyph substitutions', () => {
		const results = generateLookalikes('pool.com');
		// o→0 substitution
		expect(results).toContain('p0ol.com');
	});

	it('does NOT generate combosquats (those defeat edit-distance mutators)', () => {
		const results = generateLookalikes('[redacted-domain]');
		expect(results).not.toContain('paypal-login.com');
		expect(results).not.toContain('login-[redacted-domain]');
	});

	// #979 — adjacent character transposition is now its own lane
	// (`generateTranspositions`), not folded into `generateLookalikes`.
	it("does NOT generate adjacent transpositions (that is generateTranspositions' job)", () => {
		expect(generateLookalikes('nzpost.co.nz')).not.toContain('nzpots.co.nz');
	});
});

describe('generateTranspositions', () => {
	// #979 — the permutation generator had no adjacent-transposition rule at
	// all, so a high-frequency real typo class was never generated, let alone
	// probed.
	it('generates adjacent character transpositions for the #979 seeds', () => {
		expect(generateTranspositions('nzpost.co.nz')).toContain('nzpots.co.nz');
		expect(generateTranspositions('microsoft.com')).toContain('mircosoft.com');
		expect(generateTranspositions('google.com')).toContain('gogole.com');
	});

	it('never returns a duplicate or seed-equal entry for the #979 seeds', () => {
		for (const seed of ['nzpost.co.nz', 'microsoft.com', 'google.com']) {
			const results = generateTranspositions(seed);
			expect(results).not.toContain(seed);
			expect(new Set(results).size).toBe(results.length);
		}
	});

	it('does not waste a transposition slot on an identical adjacent-letter swap', () => {
		// 'school.com' has a doubled 'oo': transposing it with itself would
		// reproduce the seed, so that pair must be skipped rather than
		// generated-then-filtered.
		const results = generateTranspositions('school.com');
		expect(results).not.toContain('school.com');
		// The genuine transposition of the adjacent 'ch'/'ho' pairs should still
		// be produced.
		expect(results).toContain('shcool.com');
	});

	it("is kept in its own lane with its own cap, rather than sharing generateLookalikes' MAX_PERMUTATIONS", () => {
		// A domain whose base is long enough to produce many transpositions
		// still returns a bounded, valid, alphabetically sorted list.
		const results = generateTranspositions('longdomainnametranspositiontest.com');
		expect(results.length).toBeGreaterThan(0);
		expect(results).toEqual([...results].sort());
		for (const domain of results) {
			const labels = domain.split('.');
			for (const label of labels) {
				expect(label.length).toBeGreaterThan(0);
				expect(label.length).toBeLessThanOrEqual(63);
			}
		}
	});

	it('does not include the original domain and handles short/edge-case labels', () => {
		expect(generateTranspositions('test.com')).not.toContain('test.com');
		expect(generateTranspositions('ab.com')).toEqual(['ba.com']);
		expect(generateTranspositions('a.com')).toEqual([]);
	});
});

describe('generateCombosquats', () => {
	it('generates brand+affix combos in both positions, hyphen-delimited', () => {
		const results = generateCombosquats('[redacted-domain]');
		expect(results).toContain('paypal-login.com');
		expect(results).toContain('login-[redacted-domain]');
		expect(results).toContain('secure-[redacted-domain]');
		expect(results).toContain('paypal-verify.com');
	});

	it('preserves the original TLD (including multi-part TLDs)', () => {
		expect(generateCombosquats('example.co.uk')).toContain('example-login.co.uk');
	});

	it('caps output and never includes the original domain', () => {
		const results = generateCombosquats('[redacted-domain]');
		expect(results.length).toBeLessThanOrEqual(20);
		expect(results).not.toContain('[redacted-domain]');
	});

	it('produces only structurally valid, alphabetically sorted domains', () => {
		const results = generateCombosquats('my-brand.com');
		expect(results).toEqual([...results].sort());
		for (const domain of results) {
			const labels = domain.split('.');
			expect(labels.length).toBeGreaterThanOrEqual(2);
			for (const label of labels) {
				expect(label.length).toBeGreaterThan(0);
				expect(label.length).toBeLessThanOrEqual(63);
			}
		}
	});

	it('returns [] for input with no resolvable TLD', () => {
		expect(generateCombosquats('localhost')).toEqual([]);
	});
});

describe('generateTldVariants (#974)', () => {
	const COMMON = ['com', 'net', 'org', 'co', 'io', 'ai'];

	it('emits the exact label under the common gTLDs and the .nz family for a .co.nz seed', () => {
		const results = generateTldVariants('example.co.nz');
		for (const tld of COMMON) expect(results).toContain(`example.${tld}`);
		expect(results).toEqual(expect.arrayContaining(['example.nz', 'example.net.nz', 'example.org.nz']));
		expect(results).not.toContain('example.co.nz');
		// Not a registrable .nz second level, so never probed.
		expect(results).not.toContain('example.com.nz');
	});

	it('emits the common gTLDs and the major country forms (co.uk) for a .com seed', () => {
		const results = generateTldVariants('example.com');
		for (const tld of COMMON.filter((t) => t !== 'com')) expect(results).toContain(`example.${tld}`);
		expect(results).toEqual(expect.arrayContaining(['example.co.uk', 'example.com.au', 'example.co.nz']));
		expect(results).not.toContain('example.com');
	});

	it('the motor lane alone never reached them — the reason the lane exists', () => {
		const motor = generateLookalikes('example.co.nz');
		expect(['example.net', 'example.co', 'example.io', 'example.ai'].filter((d) => motor.includes(d))).toEqual([]);
		expect(generateLookalikes('example.com')).not.toContain('example.co.uk');
	});

	it('is capped, deduplicated, never returns the seed apex for a subdomain seed, and returns [] without a suffix', () => {
		for (const seed of ['example.co.nz', 'example.com', 'example.co.uk', 'shop.example.com']) {
			const results = generateTldVariants(seed);
			expect(results.length).toBeLessThanOrEqual(MAX_TLD_VARIANTS);
			expect(new Set(results).size).toBe(results.length);
		}
		expect(generateTldVariants('shop.example.com')).not.toContain('example.com');
		expect(generateTldVariants('localhost')).toEqual([]);
	});
});
