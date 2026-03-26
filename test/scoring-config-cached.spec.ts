import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';

// Reset the cached state between tests
beforeEach(async () => {
	const mod = await import('../src/lib/scoring-config');
	if ('resetScoringConfigCache' in mod) {
		(mod as { resetScoringConfigCache: () => void }).resetScoringConfigCache();
	}
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe('parseScoringConfigCached', () => {
	it('first call parses and returns correct config', async () => {
		const { parseScoringConfigCached, DEFAULT_SCORING_CONFIG } = await import('../src/lib/scoring-config');

		const result = parseScoringConfigCached(undefined);
		expect(result).toEqual(DEFAULT_SCORING_CONFIG);
	});

	it('second call with same input returns cached result without re-parsing', async () => {
		const scoringModule = await import('@blackveil/dns-checks/scoring');
		const parseSpy = vi.spyOn(scoringModule, 'parseScoringConfig');

		const { parseScoringConfigCached } = await import('../src/lib/scoring-config');

		const input = JSON.stringify({ weights: { spf: 15 } });
		const result1 = parseScoringConfigCached(input);
		const result2 = parseScoringConfigCached(input);

		expect(result1).toBe(result2); // Same reference (cached)
		expect(parseSpy).toHaveBeenCalledTimes(1);
	});

	it('different input invalidates cache and re-parses', async () => {
		const scoringModule = await import('@blackveil/dns-checks/scoring');
		const parseSpy = vi.spyOn(scoringModule, 'parseScoringConfig');

		const { parseScoringConfigCached } = await import('../src/lib/scoring-config');

		const input1 = JSON.stringify({ weights: { spf: 15 } });
		const input2 = JSON.stringify({ weights: { spf: 20 } });

		const result1 = parseScoringConfigCached(input1);
		const result2 = parseScoringConfigCached(input2);

		expect(result1).not.toBe(result2);
		expect(parseSpy).toHaveBeenCalledTimes(2);
		expect(result2.weights.spf).toBe(20);
	});

	it('handles undefined input caching correctly', async () => {
		const { parseScoringConfigCached, DEFAULT_SCORING_CONFIG } = await import('../src/lib/scoring-config');

		const result1 = parseScoringConfigCached(undefined);
		const result2 = parseScoringConfigCached(undefined);

		expect(result1).toBe(result2);
		expect(result1).toEqual(DEFAULT_SCORING_CONFIG);
	});
});
