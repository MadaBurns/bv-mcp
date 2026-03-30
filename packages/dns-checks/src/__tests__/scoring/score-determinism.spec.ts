// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { computeGenericScore } from '../../scoring/generic';
import type { GenericScoringContext } from '../../scoring/generic';

/**
 * Score determinism tests.
 *
 * The providerModifier is computed and returned as metadata but excluded
 * from the overall score formula. This makes scores fully deterministic:
 * identical category scores always produce identical overall scores,
 * regardless of cache-dependent providerConfidence fluctuations.
 */
describe('score determinism', () => {
	function buildContext(providerConfidence?: Record<string, number>): GenericScoringContext {
		return {
			categoryScores: {
				spf: 95, dmarc: 90, dkim: 85, dnssec: 100, ssl: 100,
				http_security: 70, subdomain_takeover: 100, mta_sts: 100, mx: 100,
			},
			tierMap: {
				spf: 'core', dmarc: 'core', dkim: 'core', dnssec: 'core', ssl: 'core',
				http_security: 'protective', subdomain_takeover: 'protective',
				mta_sts: 'protective', mx: 'protective',
			},
			weights: {
				spf: 10, dmarc: 16, dkim: 10, dnssec: 8, ssl: 8,
				http_security: 3, subdomain_takeover: 4, mta_sts: 3, mx: 2,
			},
			criticalCategories: ['spf', 'dmarc', 'dkim', 'ssl'],
			emailBonusEligible: true,
			missingControls: {},
			hardeningPassed: { tlsrpt: true, bimi: false },
			providerConfidence,
		};
	}

	it('produces identical scores regardless of providerConfidence values', () => {
		const noConfidence = computeGenericScore(buildContext());
		const highConfidence = computeGenericScore(buildContext({ _0: 0.95, _1: 0.95 }));
		const lowConfidence = computeGenericScore(buildContext({ _0: 0.0, _1: 0.0 }));
		const mixedConfidence = computeGenericScore(buildContext({ _0: 0.85, _1: 0.65 }));

		expect(noConfidence.overall).toBe(highConfidence.overall);
		expect(highConfidence.overall).toBe(lowConfidence.overall);
		expect(lowConfidence.overall).toBe(mixedConfidence.overall);
	});

	it('still computes providerModifier as metadata', () => {
		const high = computeGenericScore(buildContext({ _0: 1.0 }));
		const low = computeGenericScore(buildContext({ _0: 0.0 }));

		// Modifier is computed but does not affect overall
		expect(high.providerModifier).toBeGreaterThan(0);
		expect(low.providerModifier).toBeLessThan(0);
		expect(high.overall).toBe(low.overall);
	});

	it('runtime vs stale vs cold cache all produce same score', () => {
		const runtime = computeGenericScore(buildContext({ _0: 0.85 }));
		const stale = computeGenericScore(buildContext({ _0: 0.70 }));
		const cold = computeGenericScore(buildContext({ _0: 0.65 }));

		expect(runtime.overall).toBe(stale.overall);
		expect(stale.overall).toBe(cold.overall);
	});

	it('providerModifier is 0 when no confidence provided', () => {
		const result = computeGenericScore(buildContext());
		expect(result.providerModifier).toBe(0);
	});
});
