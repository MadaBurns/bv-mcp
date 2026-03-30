// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { computeGenericScore } from '../../scoring/generic';
import type { GenericScoringContext } from '../../scoring/generic';

/**
 * Bug: providerConfidence values change between scans due to cache state
 * (runtime=0.85, stale=0.7, cold=0.65). The providerModifier function
 * amplifies these into -5..+5 score changes, causing visible score
 * fluctuation on consecutive scans of the same domain with identical
 * category scores.
 *
 * Fix: cap providerModifier to -2..+2 so cache-dependent confidence
 * changes produce at most ±2 point score variation instead of ±5.
 */
describe('providerModifier stability', () => {
	function buildContext(providerConfidence: Record<string, number>): GenericScoringContext {
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

	it('limits providerModifier to ±2 points maximum', () => {
		// Simulate best-case confidence (all runtime hits)
		const bestCase = computeGenericScore(buildContext({ _0: 0.95, _1: 0.95 }));
		// Simulate worst-case confidence (all cold cache)
		const worstCase = computeGenericScore(buildContext({ _0: 0.0, _1: 0.0 }));

		const swing = Math.abs(bestCase.overall - worstCase.overall);
		expect(swing).toBeLessThanOrEqual(4); // ±2 = max 4pt total swing
	});

	it('produces at most 2-point difference between runtime and stale cache confidence', () => {
		// Runtime: confidence = 0.85
		const runtime = computeGenericScore(buildContext({ _0: 0.85 }));
		// Stale: confidence = 0.70
		const stale = computeGenericScore(buildContext({ _0: 0.70 }));
		// Cold: confidence = 0.65
		const cold = computeGenericScore(buildContext({ _0: 0.65 }));

		expect(Math.abs(runtime.overall - stale.overall)).toBeLessThanOrEqual(2);
		expect(Math.abs(runtime.overall - cold.overall)).toBeLessThanOrEqual(2);
		expect(Math.abs(stale.overall - cold.overall)).toBeLessThanOrEqual(2);
	});

	it('providerModifier never exceeds ±2', () => {
		const maxConfidence = computeGenericScore(buildContext({ _0: 1.0 }));
		const minConfidence = computeGenericScore(buildContext({ _0: 0.0 }));

		expect(maxConfidence.providerModifier).toBeLessThanOrEqual(2);
		expect(maxConfidence.providerModifier).toBeGreaterThanOrEqual(-2);
		expect(minConfidence.providerModifier).toBeLessThanOrEqual(2);
		expect(minConfidence.providerModifier).toBeGreaterThanOrEqual(-2);
	});

	it('providerModifier is 0 when confidence is 0.5 (neutral)', () => {
		const neutral = computeGenericScore(buildContext({ _0: 0.5 }));
		expect(neutral.providerModifier).toBe(0);
	});
});
