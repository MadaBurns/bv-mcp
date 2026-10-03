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

	it('rejects Latin + Cyrillic with a Cyrillic "а" (U+0430) in pаypal.com', async () => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		expect(() => sanitizeDomain('pаypal.com')).toThrow(/mixes multiple Unicode scripts/);
	});

	it('rejects Latin + Greek mixes', async () => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		// Greek omicron (U+03BF) inside an otherwise Latin label
		expect(() => sanitizeDomain('goοgle.com')).toThrow(/mixes multiple Unicode scripts/);
	});

	// UTS #39 section 5.2 "Highly Restrictive": Latin + {Han,Hiragana,Katakana} (Japanese),
	// Latin + {Han,Bopomofo} (Chinese), Latin + {Han,Hangul} (Korean) are legitimate.
	it.each([
		['東京ショップ.jp', 'Han + Katakana'],
		['日本語の.jp', 'Han + Hiragana'],
		['mac用户.cn', 'Latin + Han'],
		['한국어abc.kr', 'Hangul + Latin'],
		['日本語ひらがなカタカナ.jp', 'Han + Hiragana + Katakana'],
		['ㄅㄆ中文.cn', 'Bopomofo + Han'],
	])('accepts the legitimate CJK script combination %s (%s)', async (domain) => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		const out = sanitizeDomain(domain);
		expect(out).toMatch(/^xn--/);
	});

	it.each([
		['한국어ひらがな.kr', 'Hangul + Hiragana'],
		['カタカナㄅ.jp', 'Katakana + Bopomofo'],
		['日本語ひらㄅ.jp', 'Han + Hiragana + Bopomofo'],
		['東京шоп.jp', 'Han + Cyrillic'],
		['mac用户α.cn', 'Latin + Han + Greek'],
	])('still rejects the non-permitted script mix %s (%s)', async (domain) => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		expect(() => sanitizeDomain(domain)).toThrow(/mixes multiple Unicode scripts/);
	});
});
