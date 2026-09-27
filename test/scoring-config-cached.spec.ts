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
		const { parseScoringConfigCached } = await import('../src/lib/scoring-config');
		const { DEFAULT_SCORING_CONFIG } = await import('@blackveil/dns-checks/scoring');

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
		const { parseScoringConfigCached } = await import('../src/lib/scoring-config');
		const { DEFAULT_SCORING_CONFIG } = await import('@blackveil/dns-checks/scoring');

		const result1 = parseScoringConfigCached(undefined);
		const result2 = parseScoringConfigCached(undefined);

		expect(result1).toBe(result2);
		expect(result1).toEqual(DEFAULT_SCORING_CONFIG);
	});

	// SQ-203: malformed SCORING_CONFIG JSON used to resolve to defaults with zero
	// trace — parseScoringConfig's JSON.parse catch returned before the warn path
	// ran. It now routes through a structured logEvent (category 'config', result
	// 'scoring_config_invalid_json'), and — same memoization as every other input
	// above — only once per isolate for a repeated identical malformed value.
	it('logs a structured warning exactly once per isolate for malformed JSON, not once per call', async () => {
		const logModule = await import('../src/lib/log');
		const logEventSpy = vi.spyOn(logModule, 'logEvent');
		const { parseScoringConfigCached } = await import('../src/lib/scoring-config');
		const { DEFAULT_SCORING_CONFIG } = await import('@blackveil/dns-checks/scoring');

		const raw = '{not valid json';
		const result1 = parseScoringConfigCached(raw);
		const result2 = parseScoringConfigCached(raw);

		expect(result1).toBe(result2);
		expect(result1).toEqual(DEFAULT_SCORING_CONFIG);
		expect(logEventSpy).toHaveBeenCalledTimes(1);
		const event = logEventSpy.mock.calls[0]?.[0];
		expect(event?.category).toBe('config');
		expect(event?.result).toBe('scoring_config_invalid_json');
		expect(event?.severity).toBe('warn');
	});
});
