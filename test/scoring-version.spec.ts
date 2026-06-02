import { describe, expect, it } from 'vitest';
import { SCORING_MODEL_VERSION, computeScoringConfigHash } from '../src/lib/scoring-version';

describe('scoring-version', () => {
	it('exports a semver-shaped SCORING_MODEL_VERSION', () => {
		expect(SCORING_MODEL_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
	});

	it('returns the "default" marker for an unset/undefined config', () => {
		expect(computeScoringConfigHash()).toBe('default');
		expect(computeScoringConfigHash(undefined)).toBe('default');
		expect(computeScoringConfigHash(null)).toBe('default');
	});

	it('produces a non-empty stable hex hash for a populated config', () => {
		const config = { weights: { dmarc: 16, spf: 10 }, thresholds: { pass: 50 } };
		const hash = computeScoringConfigHash(config);
		expect(hash).toMatch(/^[0-9a-f]+$/);
		expect(hash.length).toBeGreaterThan(0);
		// Deterministic across calls.
		expect(computeScoringConfigHash(config)).toBe(hash);
	});

	it('is invariant to object key ordering (recursive, nested)', () => {
		const a = { weights: { dmarc: 16, spf: 10 }, thresholds: { pass: 50, fail: 49 } };
		const b = { thresholds: { fail: 49, pass: 50 }, weights: { spf: 10, dmarc: 16 } };
		expect(computeScoringConfigHash(a)).toBe(computeScoringConfigHash(b));
	});

	it('produces distinct hashes for different config values', () => {
		const a = { weights: { dmarc: 16 } };
		const b = { weights: { dmarc: 12 } };
		expect(computeScoringConfigHash(a)).not.toBe(computeScoringConfigHash(b));
	});
});
