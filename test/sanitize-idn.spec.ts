import { describe, it, expect } from 'vitest';

describe('IDN/homoglyph normalization', () => {
	it('canonicalizes an internationalized domain to punycode (xn--)', async () => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		const out = sanitizeDomain('bücher.de');
		expect(out).toMatch(/xn--/);
	});

	it('rejects a label that mixes Latin and Cyrillic scripts (homoglyph)', async () => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		// "paypaі.com" — the last char before .com is Cyrillic small i (U+0456)
		expect(() => sanitizeDomain('paypaі.com')).toThrow();
	});
});
