import { describe, it, expect } from 'vitest';
import { generateCombosquats, generateLookalikes } from '../src/tools/lookalike-analysis';

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

	it('results are sorted alphabetically', () => {
		const results = generateLookalikes('test.com');
		const sorted = [...results].sort();
		expect(results).toEqual(sorted);
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
		const results = generateLookalikes('paypal.com');
		expect(results).not.toContain('paypal-login.com');
		expect(results).not.toContain('login-paypal.com');
	});
});

describe('generateCombosquats', () => {
	it('generates brand+affix combos in both positions, hyphen-delimited', () => {
		const results = generateCombosquats('paypal.com');
		expect(results).toContain('paypal-login.com');
		expect(results).toContain('login-paypal.com');
		expect(results).toContain('secure-paypal.com');
		expect(results).toContain('paypal-verify.com');
	});

	it('preserves the original TLD (including multi-part TLDs)', () => {
		expect(generateCombosquats('example.co.uk')).toContain('example-login.co.uk');
	});

	it('caps output and never includes the original domain', () => {
		const results = generateCombosquats('paypal.com');
		expect(results.length).toBeLessThanOrEqual(20);
		expect(results).not.toContain('paypal.com');
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
