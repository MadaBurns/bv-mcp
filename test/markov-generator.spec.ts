// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { trainTrigramModel, generateFromModel, generateMarkovLookalikes } from '../src/tools/markov-generator';

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
