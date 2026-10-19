// SPDX-License-Identifier: BUSL-1.1

/**
 * Branch-complete pin for the mixed-script (homoglyph) guard behind `sanitizeDomain`.
 * `hasMixedScripts` is module-private, so it is exercised through `sanitizeDomain`, which
 * throws `Invalid domain: label "..." mixes multiple Unicode scripts` on a rejected label.
 *
 * One sample per classified script. Samples are lowercase and NFC-stable, so the
 * normalization `sanitizeDomain` applies first does not change which script a char is in.
 */
import { describe, expect, it } from 'vitest';

const SAMPLES: Record<string, string> = {
	Latin: 'a',
	LatinNonAscii: 'é',
	Cyrillic: 'а', // U+0430
	Greek: 'ο', // U+03BF
	Armenian: 'ա', // U+0561
	Georgian: 'ა', // U+10D0
	Han: '東',
	Hiragana: 'あ',
	Katakana: 'ア',
	Hangul: '한',
	Bopomofo: 'ㄅ',
	Arabic: 'ع',
	Hebrew: 'א',
	Devanagari: 'क',
	Thai: 'ก',
};

const MIXED = /mixes multiple Unicode scripts/;

describe('hasMixedScripts via sanitizeDomain', () => {
	it.each(Object.entries(SAMPLES))('accepts a label made of a single script (%s)', async (_name, sample) => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		expect(() => sanitizeDomain(`${sample}${sample}.com`)).not.toThrow();
	});

	it.each(['Cyrillic', 'Greek', 'Armenian', 'Georgian', 'Arabic', 'Hebrew', 'Devanagari', 'Thai'])(
		'rejects Latin mixed with %s',
		async (name) => {
			const { sanitizeDomain } = await import('../src/lib/sanitize');
			expect(() => sanitizeDomain(`a${SAMPLES[name]}.com`)).toThrow(MIXED);
			expect(() => sanitizeDomain(`${SAMPLES[name]}a.com`)).toThrow(MIXED);
		},
	);

	it('treats a non-ASCII Latin letter as Latin (not a mix with ASCII Latin)', async () => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		expect(() => sanitizeDomain('café.com')).not.toThrow();
		expect(() => sanitizeDomain('é.com')).not.toThrow();
	});

	it.each(['Han', 'Hiragana', 'Katakana', 'Hangul', 'Bopomofo'])(
		'permits Latin mixed with the CJK script %s (UTS #39 Highly Restrictive)',
		async (name) => {
			const { sanitizeDomain } = await import('../src/lib/sanitize');
			expect(() => sanitizeDomain(`a${SAMPLES[name]}.com`)).not.toThrow();
		},
	);

	it.each([
		['Han + Hiragana + Katakana', '東あア'],
		['Han + Hiragana', '東あ'],
		['Han + Katakana', '東ア'],
		['Han + Bopomofo', '東ㄅ'],
		['Han + Hangul', '東한'],
		['Latin + Han + Hiragana + Katakana', 'a東あア'],
	])('permits the legitimate CJK combination %s', async (_name, label) => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		expect(() => sanitizeDomain(`${label}.com`)).not.toThrow();
	});

	it.each([
		['Hangul + Hiragana', '한あ'],
		['Hangul + Katakana', '한ア'],
		['Hiragana + Bopomofo', 'あㄅ'],
		['Han + Hangul + Hiragana', '東한あ'],
		['Han + Bopomofo + Hangul', '東ㄅ한'],
		['Han + Arabic', '東ع'],
		['Han + Cyrillic', '東а'],
		['Cyrillic + Greek', 'аο'],
		['Cyrillic + Armenian', 'аա'],
		['Greek + Georgian', 'οა'],
		['Arabic + Hebrew', 'عא'],
		['Devanagari + Thai', 'कก'],
		['Latin + Han + Cyrillic', 'a東а'],
	])('rejects the non-permitted combination %s', async (_name, label) => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		expect(() => sanitizeDomain(`${label}.com`)).toThrow(MIXED);
	});

	it('ignores hyphens and digits when classifying a label', async () => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		expect(() => sanitizeDomain('а-1.com')).not.toThrow(); // Cyrillic + neutral
		expect(() => sanitizeDomain('a-1.com')).not.toThrow();
		expect(() => sanitizeDomain('1-2.com')).not.toThrow(); // no script at all
		expect(() => sanitizeDomain('а-a1.com')).toThrow(MIXED); // neutrals do not rescue a real mix
	});

	it('skips unclassified scripts and symbols rather than counting them', async () => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		expect(() => sanitizeDomain('aአ.com')).not.toThrow(); // Ethiopic: not in the classified set
		expect(() => sanitizeDomain('аአ.com')).not.toThrow();
		expect(() => sanitizeDomain('a€.com')).not.toThrow(); // Common-script symbol
	});

	it('classifies each label independently', async () => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		// A different single script per label is fine; the mix check is per label.
		expect(() => sanitizeDomain('аа.ααα.example.com')).not.toThrow();
		expect(() => sanitizeDomain('example.аa.com')).toThrow(MIXED);
	});

	it('names the offending label (capped at 63 chars) in the error', async () => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		expect(() => sanitizeDomain('pаypal.com')).toThrow('Invalid domain: label "pаypal" mixes multiple Unicode scripts');
	});

	it('returns the punycode form for an accepted single-script IDN', async () => {
		const { sanitizeDomain } = await import('../src/lib/sanitize');
		expect(sanitizeDomain('пример.com')).toBe('xn--e1afmkfd.com');
	});
});
