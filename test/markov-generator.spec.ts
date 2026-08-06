// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { trainTrigramModel, generateFromModel, generateMarkovLookalikes } from '../src/tools/markov-generator';
import {
	COGNITIVE_SUBSTITUTIONS,
	MAX_COGNITIVE_LOOKALIKES,
	QWERTY_ADJACENT,
	generateCognitiveLookalikes,
	generateLookalikes,
} from '../src/tools/lookalike-analysis';

describe('MarkovGenerator', () => {
	describe('trainTrigramModel', () => {
		it('builds a model from samples', () => {
			const model = trainTrigramModel(['abc']);
			// ^abc$ -> ^^a, ^ab, abc, bc$, c$$ (with padding logic)
			// Wait, my implementation:
			// padded = "^abc$"
			// i=0: prefix="^a", next="b"
			// i=1: prefix="ab", next="c"
			// i=2: prefix="bc", next="$"
			expect(model.has('^a')).toBe(true);
			expect(model.get('^a')?.get('b')).toBe(1);
			expect(model.get('ab')?.get('c')).toBe(1);
			expect(model.get('bc')?.get('$')).toBe(1);
		});
	});

	describe('generateFromModel', () => {
		it('generates a string from a model', () => {
			const model = trainTrigramModel(['example']);
			const result = generateFromModel(model, 3, 10);
			expect(result).toBe('example');
		});

		it('handles multiple samples and can generate hybrids', () => {
			const model = trainTrigramModel(['google', 'goggle']);
			const result = generateFromModel(model, 3, 10);
			// Possible: google, goggle, gogle, googgle (if bigram). The
			// generator is non-deterministic — all four outputs occur in
			// practice depending on which trigram transition the RNG picks.
			expect(['google', 'goggle', 'gogle', 'googgle']).toContain(result);
		});
	});

	describe('generateMarkovLookalikes', () => {
		it('generates unique lookalikes for a domain', () => {
			const results = generateMarkovLookalikes('google.com', 5);
			expect(results.length).toBeGreaterThan(0);
			for (const res of results) {
				expect(res).toMatch(/\.com$/);
				expect(res).not.toBe('google.com');
				// Check that it's structurally valid
				expect(res.split('.').length).toBeGreaterThanOrEqual(2);
			}
		});

		it('returns empty for invalid domain', () => {
			expect(generateMarkovLookalikes('invalid', 5)).toEqual([]);
		});
	});
});

/**
 * COGNITIVE-ERROR GENERATION (the "Mandela spelling" defect).
 *
 * Every operation the candidate generators shipped with before this suite —
 * QWERTY-adjacency substitution, character omission, character duplication,
 * dot insertion, TLD swap, homoglyph substitution — models a MOTOR error: a
 * slip of the finger by someone who knows the correct spelling. A
 * Mandela-effect misspelling is a COGNITIVE error: the spelling a large
 * population believes IS correct, and which they will therefore type
 * deliberately, repeatedly, and without noticing. By construction the motor
 * operation set cannot reach one unless the cognitive spelling happens to
 * coincide with a single-character slip.
 *
 * The four brands below are the measured corpus. `jcpenny` is the CONTROL: it
 * is a plain character deletion, so the pre-existing motor generator already
 * emitted it. If the control ever stops being generated, the mechanism itself
 * broke and the other three assertions prove nothing.
 */
describe('cognitive (Mandela-effect) misspelling generation', () => {
	/** [seed domain, the spelling a large population believes is correct]. */
	const MANDELA_CORPUS: ReadonlyArray<readonly [string, string]> = [
		// Insertion of a silent 't' completing the `tch` trigraph.
		['skechers.com', 'sketchers.com'],
		// Non-adjacent a->e substitution; also the `stain`->`stein` morpheme swap.
		['berenstain.com', 'berenstein.com'],
		// Vowel lengthening.
		['febreze.com', 'febreeze.com'],
		// CONTROL — a motor error (character deletion), already covered.
		['jcpenney.com', 'jcpenny.com'],
	];

	it.each(MANDELA_CORPUS)('emits the known Mandela spelling of %s', (seed, mandela) => {
		expect(generateCognitiveLookalikes(seed)).toContain(mandela);
	});

	it('CONTROL: the motor generator still emits jcpenny.com — the mechanism never broke', () => {
		expect(generateLookalikes('jcpenney.com')).toContain('jcpenny.com');
	});

	it('CONTROL: the motor generator alone still cannot reach the cognitive spellings', () => {
		// Pins the defect itself. `febreze`/`jcpenney` are excluded — their
		// Mandela spellings coincide with a single-character motor slip, which
		// is exactly why they were never evidence of the mechanism working.
		expect(generateLookalikes('skechers.com')).not.toContain('sketchers.com');
		expect(generateLookalikes('berenstain.com')).not.toContain('berenstein.com');
	});

	it('the whole candidate universe (motor + cognitive) covers all four brands', () => {
		for (const [seed, mandela] of MANDELA_CORPUS) {
			const universe = new Set([...generateLookalikes(seed), ...generateCognitiveLookalikes(seed)]);
			expect(universe.has(mandela)).toBe(true);
		}
	});

	it('every substitution pair is genuinely NON-adjacent on QWERTY', () => {
		// The whole point of the operation: a pair the keyboard-adjacency pass
		// already covers adds no new reach. Guards against someone "helpfully"
		// padding the table with s/z or f/v.
		for (const [from, to] of COGNITIVE_SUBSTITUTIONS) {
			expect(QWERTY_ADJACENT[from] ?? []).not.toContain(to);
		}
	});

	it('never emits the seed itself, and every candidate is a structurally valid domain', () => {
		for (const seed of ['skechers.com', 'berenstain.com', 'febreze.com', 'jcpenney.com', 'looney.co.nz']) {
			const results = generateCognitiveLookalikes(seed);
			expect(results).not.toContain(seed);
			for (const candidate of results) {
				expect(candidate).toMatch(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/);
				expect(candidate.length).toBeLessThanOrEqual(253);
			}
		}
	});

	it('preserves a multi-part eTLD rather than mutating inside it', () => {
		for (const candidate of generateCognitiveLookalikes('berenstain.co.nz')) {
			expect(candidate.endsWith('.co.nz')).toBe(true);
		}
	});

	it('is deterministic and bounded', () => {
		const first = generateCognitiveLookalikes('berenstain.com');
		expect(generateCognitiveLookalikes('berenstain.com')).toEqual(first);
		expect(first.length).toBeLessThanOrEqual(MAX_COGNITIVE_LOOKALIKES);
	});

	it('returns nothing for input with no TLD', () => {
		expect(generateCognitiveLookalikes('invalid')).toEqual([]);
	});

	it('the discovery lane (generateMarkovLookalikes) surfaces the cognitive spellings too', () => {
		// `discover_brand_domains` builds its candidate universe from this
		// function, so a Mandela spelling that only reached check_lookalikes
		// would still be invisible to brand discovery.
		for (const [seed, mandela] of MANDELA_CORPUS) {
			expect(generateMarkovLookalikes(seed, 20)).toContain(mandela);
		}
	});

	it('CONTROL: the Markov trigram lane still contributes its own candidates', () => {
		// Proves the union above did not simply replace the Markov output.
		const cognitive = new Set(generateCognitiveLookalikes('google.com'));
		const combined = generateMarkovLookalikes('google.com', 20);
		expect(combined.some((candidate) => !cognitive.has(candidate))).toBe(true);
	});
});
