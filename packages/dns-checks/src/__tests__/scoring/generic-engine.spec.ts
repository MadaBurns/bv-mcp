// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { computeGenericScore } from '../../scoring/generic';
import type { GenericScoringContext } from '../../scoring/generic';
import { DEFAULT_SCORING_CONFIG } from '../../scoring/config';
import type { ScoringConfig } from '../../scoring/config';

/**
 * The pre-2.0.0 policy as an EXPLICIT override (tier split 70/20/10, email bonus 5/3/2, critical
 * penalty 15). Tests that exercise those mechanisms pass this so they keep proving the engine
 * paths and the published override surface, while the default (2.0.0) behaviour is asserted
 * separately.
 */
const PRE_2_0_POLICY: ScoringConfig = {
	...DEFAULT_SCORING_CONFIG,
	tierSplit: { core: 70, protective: 20, hardening: 10 },
	thresholds: {
		...DEFAULT_SCORING_CONFIG.thresholds,
		emailBonusFull: 5,
		emailBonusMid: 3,
		emailBonusPartial: 2,
		criticalOverallPenalty: 15,
	},
};

/** Helper: build a minimal context with sensible defaults. */
function buildContext(overrides: Partial<GenericScoringContext> = {}): GenericScoringContext {
	return {
		categoryScores: {},
		tierMap: {},
		weights: {},
		criticalCategories: [],
		emailBonusEligible: false,
		missingControls: {},
		hardeningPassed: {},
		...overrides,
	};
}

describe('computeGenericScore', () => {
	describe('perfect score', () => {
		it('returns 100 with grade A+ when all core/protective categories score 100', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 100,
					dmarc: 100,
					dkim: 100,
					dnssec: 100,
					ssl: 100,
					http_security: 100,
					subdomain_takeover: 100,
					mta_sts: 100,
					mx: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					dnssec: 'core',
					ssl: 'core',
					http_security: 'protective',
					subdomain_takeover: 'protective',
					mta_sts: 'protective',
					mx: 'protective',
				},
				weights: {
					spf: 10,
					dmarc: 16,
					dkim: 10,
					dnssec: 8,
					ssl: 8,
					http_security: 3,
					subdomain_takeover: 4,
					mta_sts: 3,
					mx: 2,
				},
				criticalCategories: ['spf', 'dmarc', 'dkim', 'ssl'],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx);
			// 2.0.0 default split: Core=75, Protective=25, Hardening=0, no email bonus.
			// (Was 90/A under the 70/20/10 split, where the empty hardening tier forfeited 10.)
			expect(result.overall).toBe(100);
			expect(result.grade).toBe('A+');
			expect(result.tierBreakdown).toEqual({ core: 75, protective: 25, hardening: 0 });
		});

		it('reaches 100 when hardening also passes and email bonus applies', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 100,
					dmarc: 100,
					dkim: 100,
					dnssec: 100,
					ssl: 100,
					http_security: 100,
					subdomain_takeover: 100,
					mta_sts: 100,
					mx: 100,
					tlsrpt: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					dnssec: 'core',
					ssl: 'core',
					http_security: 'protective',
					subdomain_takeover: 'protective',
					mta_sts: 'protective',
					mx: 'protective',
					tlsrpt: 'hardening',
				},
				weights: {
					spf: 10,
					dmarc: 16,
					dkim: 10,
					dnssec: 8,
					ssl: 8,
					http_security: 3,
					subdomain_takeover: 4,
					mta_sts: 3,
					mx: 2,
					tlsrpt: 1,
				},
				criticalCategories: ['spf', 'dmarc', 'dkim', 'ssl'],
				emailBonusEligible: true,
				missingControls: {},
				hardeningPassed: { tlsrpt: true },
			});

			const result = computeGenericScore(ctx, PRE_2_0_POLICY);
			// Core=70, Protective=20, Hardening=10 (1/1 passed), email bonus=+5
			// Total=100 (clamped)
			expect(result.overall).toBe(100);
			expect(result.grade).toBe('A+');
		});
	});

	describe('critical gap ceiling', () => {
		it('caps score at 64 when a critical category has missingControls=true', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 0,
					dmarc: 100,
					dkim: 100,
					dnssec: 100,
					ssl: 100,
					http_security: 100,
					subdomain_takeover: 100,
					mta_sts: 100,
					mx: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					dnssec: 'core',
					ssl: 'core',
					http_security: 'protective',
					subdomain_takeover: 'protective',
					mta_sts: 'protective',
					mx: 'protective',
				},
				weights: {
					spf: 10,
					dmarc: 16,
					dkim: 10,
					dnssec: 8,
					ssl: 8,
					http_security: 3,
					subdomain_takeover: 4,
					mta_sts: 3,
					mx: 2,
				},
				criticalCategories: ['spf', 'dmarc', 'dkim', 'ssl'],
				emailBonusEligible: false,
				missingControls: { spf: true },
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx);
			expect(result.overall).toBeLessThanOrEqual(64);
			expect(result.criticalGaps).toContain('spf');
		});

		it('does not apply ceiling when missingControls key is not in criticalCategories', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 100,
					dmarc: 100,
					dkim: 100,
					ssl: 100,
					mta_sts: 0,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					ssl: 'core',
					mta_sts: 'protective',
				},
				weights: {
					spf: 10,
					dmarc: 16,
					dkim: 10,
					ssl: 8,
					mta_sts: 3,
				},
				criticalCategories: ['spf', 'dmarc', 'dkim', 'ssl'],
				emailBonusEligible: false,
				missingControls: { mta_sts: true },
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx);
			// mta_sts is not critical, so no ceiling
			expect(result.overall).toBeGreaterThan(64);
			expect(result.criticalGaps).toHaveLength(0);
		});

		it('does not apply ceiling to a key that is simultaneously a transient failure — unmeasured wins over missing', () => {
			// A direct computeGenericScore caller can hand-build a context where the same key is
			// marked both transient and missing. That is a contradiction (a check that was never
			// measured cannot prove absence), and the ceiling must not fire from it. The engine
			// wrapper never produces the combination — its missingControls population is
			// measurement-gated — so this pins the generic engine's own defense-in-depth guard.
			const ctx = buildContext({
				categoryScores: {
					dmarc: 100,
					dkim: 100,
					dnssec: 100,
					ssl: 100,
					http_security: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					dnssec: 'core',
					ssl: 'core',
					http_security: 'protective',
				},
				weights: {
					spf: 10,
					dmarc: 16,
					dkim: 10,
					dnssec: 8,
					ssl: 8,
					http_security: 3,
				},
				criticalCategories: ['spf', 'dmarc', 'dkim', 'ssl'],
				emailBonusEligible: false,
				missingControls: { spf: true },
				transientFailures: { spf: true },
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx);
			expect(result.overall).toBeGreaterThan(64);
			expect(result.criticalGaps).toHaveLength(0);
		});
	});

	describe('custom emailBonusKeys', () => {
		it('uses default email bonus keys (spf, dkim, dmarc) when not specified', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 100,
					dmarc: 95,
					dkim: 100,
					ssl: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					ssl: 'core',
				},
				weights: {
					spf: 10,
					dmarc: 16,
					dkim: 10,
					ssl: 8,
				},
				criticalCategories: [],
				emailBonusEligible: true,
				missingControls: {},
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx, PRE_2_0_POLICY);
			// SPF >= 57, DKIM not missing, DMARC present & score >= 90 → +5 under the explicit override
			expect(result.emailBonus).toBe(5);
			// ...and 0 under the 2.0.0 default, where the bonus is zeroed but its code path remains.
			expect(computeGenericScore(ctx).emailBonus).toBe(0);
		});

		it('uses custom emailBonusKeys when specified', () => {
			const ctx = buildContext({
				categoryScores: {
					my_spf: 100,
					my_dkim: 100,
					my_dmarc: 95,
					ssl: 100,
				},
				tierMap: {
					my_spf: 'core',
					my_dkim: 'core',
					my_dmarc: 'core',
					ssl: 'core',
				},
				weights: {
					my_spf: 10,
					my_dkim: 10,
					my_dmarc: 16,
					ssl: 8,
				},
				criticalCategories: [],
				emailBonusEligible: true,
				missingControls: {},
				hardeningPassed: {},
				emailBonusKeys: { spf: 'my_spf', dkim: 'my_dkim', dmarc: 'my_dmarc' },
			});

			const result = computeGenericScore(ctx, PRE_2_0_POLICY);
			// All conditions met with custom keys → +5
			expect(result.emailBonus).toBe(5);
		});

		it('grants mid-level bonus when DMARC score is 70-89', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 100,
					dmarc: 75,
					dkim: 100,
					ssl: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					ssl: 'core',
				},
				weights: { spf: 10, dmarc: 16, dkim: 10, ssl: 8 },
				criticalCategories: [],
				emailBonusEligible: true,
				missingControls: {},
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx, PRE_2_0_POLICY);
			expect(result.emailBonus).toBe(3);
		});

		it('grants partial bonus when DMARC score is below 70', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 100,
					dmarc: 60,
					dkim: 100,
					ssl: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					ssl: 'core',
				},
				weights: { spf: 10, dmarc: 16, dkim: 10, ssl: 8 },
				criticalCategories: [],
				emailBonusEligible: true,
				missingControls: {},
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx, PRE_2_0_POLICY);
			expect(result.emailBonus).toBe(2);
		});
	});

	describe('transient failures', () => {
		it('excludes transientFailure categories from scoring entirely', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 100,
					dmarc: 100,
					dkim: 100,
					ssl: 100,
					dnssec: 100,
					http_security: 0,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					ssl: 'core',
					dnssec: 'core',
					http_security: 'protective',
				},
				weights: {
					spf: 10,
					dmarc: 16,
					dkim: 10,
					ssl: 8,
					dnssec: 8,
					http_security: 3,
				},
				criticalCategories: ['spf', 'dmarc', 'dkim', 'ssl'],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
				transientFailures: { http_security: true },
			});

			const resultWith = computeGenericScore(ctx);

			// Without the transient failure, http_security would drag protective down
			const ctxWithout = buildContext({
				...ctx,
				transientFailures: undefined,
			});
			const resultWithout = computeGenericScore(ctxWithout);

			// With transient exclusion, http_security is ignored → higher score
			expect(resultWith.overall).toBeGreaterThan(resultWithout.overall);
		});
	});

	describe('hardening bonus', () => {
		it('grants proportional hardening points for passed categories', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 100,
					dmarc: 100,
					dkim: 100,
					ssl: 100,
					dnssec: 100,
					tlsrpt: 100,
					dane: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					ssl: 'core',
					dnssec: 'core',
					tlsrpt: 'hardening',
					dane: 'hardening',
				},
				weights: {
					spf: 10,
					dmarc: 16,
					dkim: 10,
					ssl: 8,
					dnssec: 8,
					tlsrpt: 1,
					dane: 1,
				},
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: { tlsrpt: true, dane: false },
			});

			// The hardening tier is retired from the 2.0.0 defaults (hardening split 0) but the engine
			// path stays for callers that keep a tier map and a split of their own.
			const result = computeGenericScore(ctx, PRE_2_0_POLICY);
			// Only submitted hardening categories count. tlsrpt passes, dane fails.
			// 1 of 2 passed → 10 * (1/2) = 5 points
			// Core=70, Protective=0 (no protective categories), Hardening=5
			// Without protective categories, protectivePct defaults to 1 → 20 pts
			// Actually, no protective keys exist → protectiveMax=0 → pct=1 → 20 pts
			// Total: 70 + 20 + 5 = 95
			expect(result.overall).toBe(95);
		});

		it('only counts submitted hardening keys (absent ones are ignored)', () => {
			const ctxNone = buildContext({
				categoryScores: { spf: 100 },
				tierMap: { spf: 'core', tlsrpt: 'hardening' },
				weights: { spf: 10, tlsrpt: 1 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
			});

			const ctxOne = buildContext({
				categoryScores: { spf: 100 },
				tierMap: { spf: 'core', tlsrpt: 'hardening' },
				weights: { spf: 10, tlsrpt: 1 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: { tlsrpt: true },
			});

			const resultNone = computeGenericScore(ctxNone, PRE_2_0_POLICY);
			const resultOne = computeGenericScore(ctxOne, PRE_2_0_POLICY);
			// hardeningPassed is empty in ctxNone → 0 submitted → 0 hardening points
			// hardeningPassed has tlsrpt:true in ctxOne → 1/1 passed → 10 points
			expect(resultOne.overall - resultNone.overall).toBe(10);
		});

		it('2.0.0 default: a caller-supplied hardening key earns nothing and never yields NaN', () => {
			const ctx = buildContext({
				categoryScores: { spf: 100 },
				tierMap: { spf: 'core', tlsrpt: 'hardening' },
				weights: { spf: 10, tlsrpt: 1 },
				hardeningPassed: { tlsrpt: true },
			});
			const withKey = computeGenericScore(ctx);
			const wholly = computeGenericScore({ ...ctx, hardeningPassed: {} });
			expect(withKey.tierBreakdown.hardening).toBe(0);
			expect(Number.isNaN(withKey.overall)).toBe(false);
			expect(withKey.overall).toBe(wholly.overall);
		});
	});

	describe('email bonus disabled', () => {
		it('does not add email bonus when emailBonusEligible is false', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 100,
					dmarc: 100,
					dkim: 100,
					ssl: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					ssl: 'core',
				},
				weights: { spf: 10, dmarc: 16, dkim: 10, ssl: 8 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx);
			expect(result.emailBonus).toBe(0);
		});

		it('does not add email bonus when SPF score is below threshold', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 50,
					dmarc: 100,
					dkim: 100,
					ssl: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					ssl: 'core',
				},
				weights: { spf: 10, dmarc: 16, dkim: 10, ssl: 8 },
				criticalCategories: [],
				emailBonusEligible: true,
				missingControls: {},
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx);
			// SPF score 50 < 57 threshold → no email bonus
			expect(result.emailBonus).toBe(0);
		});

		it('does not add email bonus when DKIM is missing', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 100,
					dmarc: 100,
					dkim: 0,
					ssl: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					ssl: 'core',
				},
				weights: { spf: 10, dmarc: 16, dkim: 10, ssl: 8 },
				criticalCategories: [],
				emailBonusEligible: true,
				missingControls: { dkim: true },
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx);
			// DKIM is marked as missing → no email bonus
			expect(result.emailBonus).toBe(0);
		});
	});

	describe('summary from findingSeverityCounts', () => {
		it('generates "Excellent" summary when no issues', () => {
			const ctx = buildContext({
				categoryScores: { spf: 100 },
				tierMap: { spf: 'core' },
				weights: { spf: 10 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx);
			expect(result.summary).toContain('Excellent');
		});

		it('highlights critical issues in summary', () => {
			const ctx = buildContext({
				categoryScores: { spf: 0 },
				tierMap: { spf: 'core' },
				weights: { spf: 10 },
				criticalCategories: ['spf'],
				emailBonusEligible: false,
				missingControls: { spf: true },
				hardeningPassed: {},
				findingSeverityCounts: { critical: 2, high: 1, medium: 0, low: 0, info: 0 },
			});

			const result = computeGenericScore(ctx);
			expect(result.summary).toContain('2 critical');
			expect(result.summary).toContain('immediate attention');
		});

		it('highlights high issues when no critical exist', () => {
			const ctx = buildContext({
				categoryScores: { spf: 60 },
				tierMap: { spf: 'core' },
				weights: { spf: 10 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
				findingSeverityCounts: { critical: 0, high: 3, medium: 1, low: 0, info: 2 },
			});

			const result = computeGenericScore(ctx);
			expect(result.summary).toContain('3 high');
		});

		it('shows total non-info issues when only medium/low', () => {
			const ctx = buildContext({
				categoryScores: { spf: 80 },
				tierMap: { spf: 'core' },
				weights: { spf: 10 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
				findingSeverityCounts: { critical: 0, high: 0, medium: 2, low: 3, info: 5 },
			});

			const result = computeGenericScore(ctx);
			// 2 medium + 3 low = 5 non-info issues
			expect(result.summary).toContain('5 issue(s)');
		});
	});

	describe('absent category scores default to 100', () => {
		it('reports an explicit undefined score as unmeasured just like an absent key', () => {
			const options = { tierMap: { spf: 'core' as const }, weights: { spf: 10 } };
			const absent = computeGenericScore(buildContext({ ...options, categoryScores: {} }));
			const undefinedScore = computeGenericScore(buildContext({ ...options, categoryScores: { spf: undefined } }));
			expect(undefinedScore).toEqual(absent);
			expect(undefinedScore.unmeasuredCategories).toEqual(['spf']);
		});

		it('accepts sparse scores and never echoes an undefined extra category', () => {
			const result = computeGenericScore(buildContext({
				categoryScores: { spf: 100, extra: undefined },
				tierMap: { spf: 'core', dmarc: 'core' },
				weights: { spf: 10, dmarc: 16 },
			}));
			expect(result.categoryScores).toEqual({ spf: 100, dmarc: 100 });
			expect(result.unmeasuredCategories).toEqual(['dmarc']);
			expect(Object.values(result.categoryScores).every((score) => typeof score === 'number')).toBe(true);
		});

		it('treats missing core categories as 100%', () => {
			// Only provide spf, rest of core is absent
			const ctx = buildContext({
				categoryScores: { spf: 100 },
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
				},
				weights: { spf: 10, dmarc: 16, dkim: 10 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx);
			// All core at 100 (spf explicit, dmarc/dkim absent → 100)
			// corePct = (10+16+10)/36 = 1.0 → 75
			// Protective: none → 25
			// Total: 100
			expect(result.overall).toBe(100);
		});

		it('treats missing protective categories as 100%', () => {
			const ctx = buildContext({
				categoryScores: {
					http_security: 50,
				},
				tierMap: {
					http_security: 'protective',
					mta_sts: 'protective',
				},
				weights: {
					http_security: 3,
					mta_sts: 3,
				},
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx);
			// Core: no core categories → corePct=1 → 75
			// Protective: http_security=50/100*3=1.5, mta_sts absent=100/100*3=3, total=4.5/6=0.75 → 18.75
			// Total: 75+18.75 = 93.75 → 94
			expect(result.overall).toBe(94);
		});

		it('scoring: reports the filled-100 keys in unmeasuredCategories rather than as a silent pass', () => {
			// SQ-66: the 100 default is correct for the WEIGHTED MATH (a category a direct
			// caller never submitted must not zero or skew a tier it isn't part of), but
			// `categoryScores.dmarc === 100` alone is indistinguishable from a real
			// measured 100 unless the caller also checks `unmeasuredCategories`.
			const ctx = buildContext({
				categoryScores: { spf: 100 },
				tierMap: { spf: 'core', dmarc: 'core', dkim: 'core' },
				weights: { spf: 10, dmarc: 16, dkim: 10 },
			});

			const result = computeGenericScore(ctx);

			expect(result.categoryScores.dmarc).toBe(100);
			expect(result.categoryScores.dkim).toBe(100);
			expect(result.unmeasuredCategories.sort()).toEqual(['dkim', 'dmarc']);
			// The submitted key is echoed back but never reported as unmeasured.
			expect(result.unmeasuredCategories).not.toContain('spf');
		});

		it('scoring: reports no unmeasured categories when every tierMap key was explicitly submitted (control)', () => {
			const ctx = buildContext({
				categoryScores: { spf: 100, dmarc: 100 },
				tierMap: { spf: 'core', dmarc: 'core' },
				weights: { spf: 10, dmarc: 16 },
			});

			const result = computeGenericScore(ctx);

			expect(result.unmeasuredCategories).toEqual([]);
		});
	});

	describe('provider modifier', () => {
		it('computes positive modifier for high confidence (metadata only)', () => {
			const ctx = buildContext({
				categoryScores: { spf: 100 },
				tierMap: { spf: 'core' },
				weights: { spf: 10 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
				providerConfidence: { spf: 1.0 },
			});

			const result = computeGenericScore(ctx);
			// providerModifier computed as metadata but excluded from overall score
			expect(result.providerModifier).toBe(2);
			expect(result.overall).toBe(100); // base only, no modifier applied
		});

		it('computes negative modifier for low confidence (metadata only)', () => {
			const ctx = buildContext({
				categoryScores: { spf: 100 },
				tierMap: { spf: 'core' },
				weights: { spf: 10 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
				providerConfidence: { spf: 0.0 },
			});

			const result = computeGenericScore(ctx);
			// providerModifier computed as metadata but excluded from overall score
			expect(result.providerModifier).toBe(-2);
			expect(result.overall).toBe(100); // same as high confidence — deterministic
		});

		it('returns 0 modifier when no providerConfidence provided', () => {
			const ctx = buildContext({
				categoryScores: { spf: 100 },
				tierMap: { spf: 'core' },
				weights: { spf: 10 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
			});

			const result = computeGenericScore(ctx);
			expect(result.providerModifier).toBe(0);
		});
	});

	describe('critical penalty', () => {
		it('applies -15 penalty when findingSeverityCounts.critical > 0', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 100,
					dmarc: 100,
					dkim: 100,
					ssl: 100,
					dnssec: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					dkim: 'core',
					ssl: 'core',
					dnssec: 'core',
				},
				weights: { spf: 10, dmarc: 16, dkim: 10, ssl: 8, dnssec: 8 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
				findingSeverityCounts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
			});

			// 2.0.0 default: the penalty is zeroed, so a counted critical finding no longer subtracts.
			const byDefault = computeGenericScore(ctx);
			expect(byDefault.criticalPenalty).toBe(0);
			expect(byDefault.overall).toBe(100);

			// An explicit override still applies (published ScoringConfig surface intact).
			const result = computeGenericScore(ctx, PRE_2_0_POLICY);
			expect(result.criticalPenalty).toBe(15);
			// 70 + 20 - 15 = 75
			expect(result.overall).toBe(75);

			// A penalty-only override on the 2.0.0 defaults: 75 + 25 - 15 = 85.
			const penaltyOnly = computeGenericScore(ctx, {
				...DEFAULT_SCORING_CONFIG,
				thresholds: { ...DEFAULT_SCORING_CONFIG.thresholds, criticalOverallPenalty: 15 },
			});
			expect(penaltyOnly.criticalPenalty).toBe(15);
			expect(penaltyOnly.overall).toBe(85);
		});

		it('does not apply penalty when no critical findings', () => {
			const ctx = buildContext({
				categoryScores: { spf: 100 },
				tierMap: { spf: 'core' },
				weights: { spf: 10 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
				findingSeverityCounts: { critical: 0, high: 5, medium: 0, low: 0, info: 0 },
			});

			const result = computeGenericScore(ctx);
			expect(result.criticalPenalty).toBe(0);
		});
	});

	describe('tier breakdown', () => {
		it('returns earned points per tier', () => {
			const ctx = buildContext({
				categoryScores: {
					spf: 80,
					dmarc: 100,
					http_security: 60,
					tlsrpt: 100,
				},
				tierMap: {
					spf: 'core',
					dmarc: 'core',
					http_security: 'protective',
					tlsrpt: 'hardening',
				},
				weights: {
					spf: 10,
					dmarc: 16,
					http_security: 3,
					tlsrpt: 1,
				},
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: { tlsrpt: true },
			});

			// Core: spf=(80/100)*10=8, dmarc=(100/100)*16=16, earned=24/26
			// Protective: http=(60/100)*3=1.8, earned=1.8/3 = 0.6
			// 2.0.0 default split 75/25/0: core 69.23, protective 15, hardening 0.
			const result = computeGenericScore(ctx);
			expect(result.tierBreakdown.core).toBeCloseTo(69.23, 1);
			expect(result.tierBreakdown.protective).toBeCloseTo(15, 1);
			expect(result.tierBreakdown.hardening).toBe(0);

			// Pre-2.0.0 split as an explicit override: core 64.6, protective 12, hardening 1/1 → 10.
			const legacy = computeGenericScore(ctx, PRE_2_0_POLICY);
			expect(legacy.tierBreakdown.core).toBeCloseTo(64.6, 0);
			expect(legacy.tierBreakdown.protective).toBeCloseTo(12, 0);
			expect(legacy.tierBreakdown.hardening).toBe(10);
		});
	});

	describe('config override', () => {
		it('uses custom tier split from config', () => {
			const ctx = buildContext({
				categoryScores: { spf: 100 },
				tierMap: { spf: 'core' },
				weights: { spf: 10 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
			});

			const customConfig = {
				...DEFAULT_SCORING_CONFIG,
				tierSplit: { core: 50, protective: 30, hardening: 20 },
			};

			const result = computeGenericScore(ctx, customConfig);
			// Core=50 (100%), Protective=30 (no protective → 100%), Hardening=0 (none submitted)
			expect(result.overall).toBe(80);
		});

		it('uses custom grade boundaries from config', () => {
			const ctx = buildContext({
				categoryScores: { spf: 100 },
				tierMap: { spf: 'core' },
				weights: { spf: 10 },
				criticalCategories: [],
				emailBonusEligible: false,
				missingControls: {},
				hardeningPassed: {},
			});

			const customConfig = {
				...PRE_2_0_POLICY,
				grades: { ...DEFAULT_SCORING_CONFIG.grades, a: 89 },
			};

			const result = computeGenericScore(ctx, customConfig);
			// Score=90, custom A boundary=89 → A
			expect(result.grade).toBe('A');
		});
	});

	describe('score clamping', () => {
		it('never exceeds 100', () => {
			const ctx = buildContext({
				categoryScores: { spf: 100, dmarc: 100, dkim: 100, ssl: 100, dnssec: 100 },
				tierMap: { spf: 'core', dmarc: 'core', dkim: 'core', ssl: 'core', dnssec: 'core' },
				weights: { spf: 10, dmarc: 16, dkim: 10, ssl: 8, dnssec: 8 },
				criticalCategories: [],
				emailBonusEligible: true,
				missingControls: {},
				hardeningPassed: { tlsrpt: true },
				providerConfidence: { spf: 1.0, dmarc: 1.0 },
			});

			const result = computeGenericScore(ctx);
			expect(result.overall).toBeLessThanOrEqual(100);
		});

		it('never goes below 0', () => {
			const ctx = buildContext({
				categoryScores: { spf: 0, dmarc: 0, dkim: 0, ssl: 0, dnssec: 0 },
				tierMap: { spf: 'core', dmarc: 'core', dkim: 'core', ssl: 'core', dnssec: 'core' },
				weights: { spf: 10, dmarc: 16, dkim: 10, ssl: 8, dnssec: 8 },
				criticalCategories: ['spf', 'dmarc', 'dkim', 'ssl'],
				emailBonusEligible: false,
				missingControls: { spf: true, dmarc: true, dkim: true, ssl: true },
				hardeningPassed: {},
				providerConfidence: { spf: 0.0, dmarc: 0.0 },
				findingSeverityCounts: { critical: 5, high: 0, medium: 0, low: 0, info: 0 },
			});

			const result = computeGenericScore(ctx);
			expect(result.overall).toBeGreaterThanOrEqual(0);
		});
	});
});
