// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import {
	SENSITIVITY,
	MATURITY_THRESHOLD,
	EMA_SPAN,
	EMA_ALPHA,
	SCORING_NOTE_DELTA_THRESHOLD,
	BASELINE_FAILURE_RATES,
	WEIGHT_BOUNDS,
	defaultBounds,
	computeAdaptiveWeight,
	blendWeights,
	adaptiveWeightsToContext,
	generateScoringNote,
} from '../src/lib/adaptive-weights';
// Type-only imports verified to exist: ScanTelemetry, AdaptiveWeightsResponse, WeightBound
import { PROFILE_WEIGHTS } from '../src/lib/context-profiles';
import type { DomainProfile } from '../src/lib/context-profiles';
import type { CheckCategory } from '../src/lib/scoring-model';

describe('adaptive-weights', () => {
	// ─── Task 1: Types and constants ───────────────────────────────────────

	describe('constants', () => {
		it('SENSITIVITY is 0.5', () => {
			expect(SENSITIVITY).toBe(0.5);
		});

		it('MATURITY_THRESHOLD is 200', () => {
			expect(MATURITY_THRESHOLD).toBe(200);
		});

		it('EMA_SPAN is 200 and EMA_ALPHA matches formula', () => {
			expect(EMA_SPAN).toBe(200);
			expect(EMA_ALPHA).toBeCloseTo(2 / (200 + 1), 10);
		});

		it('SCORING_NOTE_DELTA_THRESHOLD is 3', () => {
			expect(SCORING_NOTE_DELTA_THRESHOLD).toBe(3);
		});

		it('BASELINE_FAILURE_RATES has all 13 categories', () => {
			const expected: Record<string, number> = {
				dmarc: 0.4,
				spf: 0.25,
				dkim: 0.35,
				ssl: 0.08,
				mta_sts: 0.85,
				dnssec: 0.8,
				mx: 0.05,
				caa: 0.7,
				ns: 0.03,
				bimi: 0.95,
				tlsrpt: 0.9,
				subdomain_takeover: 0.1,
				lookalikes: 0.0,
			};
			expect(BASELINE_FAILURE_RATES).toEqual(expected);
		});
	});

	describe('defaultBounds', () => {
		it('computes critical mail bounds for high static weight', () => {
			const b = defaultBounds(22, true);
			expect(b.min).toBe(Math.max(5, Math.floor(22 * 0.5))); // 11
			expect(b.max).toBe(Math.ceil(22 * 2) + 3); // 47
		});

		it('computes critical mail bounds for low static weight', () => {
			const b = defaultBounds(2, true);
			expect(b.min).toBe(5); // max(5, floor(1)) = 5
			expect(b.max).toBe(Math.ceil(2 * 2) + 3); // 7
		});

		it('computes non-critical bounds for zero weight', () => {
			const b = defaultBounds(0, false);
			expect(b.min).toBe(0); // max(0, floor(0)) = 0
			expect(b.max).toBe(Math.ceil(0) + 3); // 3
		});

		it('computes non-critical bounds for positive weight', () => {
			const b = defaultBounds(5, false);
			expect(b.min).toBe(Math.max(0, Math.floor(5 * 0.5))); // 2
			expect(b.max).toBe(Math.ceil(5 * 2) + 3); // 13
		});
	});

	describe('WEIGHT_BOUNDS', () => {
		it('has entries for all profiles', () => {
			const profiles: DomainProfile[] = ['mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal'];
			for (const p of profiles) {
				expect(WEIGHT_BOUNDS).toHaveProperty(p);
			}
		});

		it('has all categories for each profile', () => {
			const categories = Object.keys(PROFILE_WEIGHTS.mail_enabled) as CheckCategory[];
			for (const profile of Object.keys(WEIGHT_BOUNDS) as DomainProfile[]) {
				for (const cat of categories) {
					expect(WEIGHT_BOUNDS[profile]).toHaveProperty(cat);
					const bound = WEIGHT_BOUNDS[profile][cat];
					expect(bound.min).toBeLessThanOrEqual(bound.max);
				}
			}
		});

		it('applies critical mail floor for dmarc in mail_enabled', () => {
			const b = WEIGHT_BOUNDS.mail_enabled.dmarc;
			expect(b.min).toBe(Math.max(5, Math.floor(22 * 0.5))); // 11
		});

		it('applies non-critical floor for ns in mail_enabled', () => {
			const b = WEIGHT_BOUNDS.mail_enabled.ns;
			expect(b.min).toBe(0); // max(0, floor(0*0.5)) = 0
		});

		it('treats ssl as critical for mail_enabled and enterprise_mail', () => {
			// ssl importance=5 in mail_enabled → critical → min=max(5,2)=5
			expect(WEIGHT_BOUNDS.mail_enabled.ssl.min).toBe(5);
			// ssl importance=5 in enterprise_mail → critical → min=5
			expect(WEIGHT_BOUNDS.enterprise_mail.ssl.min).toBe(5);
		});

		it('treats ssl as non-critical for non_mail profile', () => {
			// ssl importance=8 in non_mail → not critical mail → min=max(0,4)=4
			expect(WEIGHT_BOUNDS.non_mail.ssl.min).toBe(4);
		});
	});

	// ─── Task 2: Computation functions ─────────────────────────────────────

	describe('computeAdaptiveWeight', () => {
		it('returns static weight when EMA equals baseline', () => {
			const result = computeAdaptiveWeight({
				staticWeight: 22,
				emaFailureRate: 0.4,
				baselineFailureRate: 0.4,
				bounds: { min: 11, max: 47 },
			});
			expect(result.weight).toBe(22);
			expect(result.boundHit).toBeNull();
		});

		it('increases weight when EMA exceeds baseline', () => {
			const result = computeAdaptiveWeight({
				staticWeight: 22,
				emaFailureRate: 0.6,
				baselineFailureRate: 0.4,
				bounds: { min: 11, max: 47 },
			});
			// deviation = 0.2, raw = 0.2 * 0.5 * 22 = 2.2, adaptive = 24.2
			expect(result.weight).toBeCloseTo(24.2, 5);
			expect(result.boundHit).toBeNull();
		});

		it('decreases weight when EMA is below baseline', () => {
			const result = computeAdaptiveWeight({
				staticWeight: 22,
				emaFailureRate: 0.2,
				baselineFailureRate: 0.4,
				bounds: { min: 11, max: 47 },
			});
			// deviation = -0.2, raw = -0.2 * 0.5 * 22 = -2.2, adaptive = 19.8
			expect(result.weight).toBeCloseTo(19.8, 5);
			expect(result.boundHit).toBeNull();
		});

		it('clamps to max and reports bound hit', () => {
			const result = computeAdaptiveWeight({
				staticWeight: 22,
				emaFailureRate: 1.0,
				baselineFailureRate: 0.0,
				bounds: { min: 11, max: 25 },
			});
			// deviation = 1.0, raw = 1.0 * 0.5 * 22 = 11, adaptive = 33 → clamped to 25
			expect(result.weight).toBe(25);
			expect(result.boundHit).toBe('max');
		});

		it('clamps to min and reports bound hit', () => {
			const result = computeAdaptiveWeight({
				staticWeight: 22,
				emaFailureRate: 0.0,
				baselineFailureRate: 1.0,
				bounds: { min: 15, max: 47 },
			});
			// deviation = -1.0, raw = -1.0 * 0.5 * 22 = -11, adaptive = 11 → clamped to 15
			expect(result.weight).toBe(15);
			expect(result.boundHit).toBe('min');
		});
	});

	describe('blendWeights', () => {
		it('returns static weight when sampleCount is 0', () => {
			const result = blendWeights(22, 24, 0);
			expect(result).toBe(22);
		});

		it('returns fully adaptive weight when sampleCount >= MATURITY_THRESHOLD', () => {
			const result = blendWeights(22, 24, 200);
			expect(result).toBe(24);
		});

		it('returns fully adaptive weight when sampleCount exceeds threshold', () => {
			const result = blendWeights(22, 24, 500);
			expect(result).toBe(24);
		});

		it('blends at 50% when sampleCount is half of threshold', () => {
			const result = blendWeights(22, 24, 100);
			// blend = 100/200 = 0.5, result = 0.5*22 + 0.5*24 = 23
			expect(result).toBe(23);
		});

		it('blends proportionally at 25%', () => {
			const result = blendWeights(20, 30, 50);
			// blend = 50/200 = 0.25, result = 0.75*20 + 0.25*30 = 22.5
			expect(result).toBe(22.5);
		});
	});

	// ─── Task 3: Type adapter and scoring note ─────────────────────────────

	describe('adaptiveWeightsToContext', () => {
		it('converts DO response weights to context record', () => {
			const doWeights: Record<string, number> = { dmarc: 24, spf: 12 };
			const result = adaptiveWeightsToContext(doWeights, 'mail_enabled');
			expect(result).not.toBeNull();
			expect(result!.dmarc.importance).toBe(24);
			expect(result!.spf.importance).toBe(12);
			// Falls back to static for missing categories
			expect(result!.dkim.importance).toBe(16);
			expect(result!.ssl.importance).toBe(5);
		});

		it('returns null if any adaptive value is NaN', () => {
			const doWeights: Record<string, number> = { dmarc: NaN };
			const result = adaptiveWeightsToContext(doWeights, 'mail_enabled');
			expect(result).toBeNull();
		});

		it('returns null if any adaptive value is negative', () => {
			const doWeights: Record<string, number> = { dmarc: -1 };
			const result = adaptiveWeightsToContext(doWeights, 'mail_enabled');
			expect(result).toBeNull();
		});

		it('returns null if any adaptive value is Infinity', () => {
			const doWeights: Record<string, number> = { dmarc: Infinity };
			const result = adaptiveWeightsToContext(doWeights, 'mail_enabled');
			expect(result).toBeNull();
		});

		it('uses correct static fallback per profile', () => {
			const doWeights: Record<string, number> = {};
			const result = adaptiveWeightsToContext(doWeights, 'enterprise_mail');
			expect(result).not.toBeNull();
			expect(result!.dmarc.importance).toBe(24); // enterprise_mail static
			expect(result!.mta_sts.importance).toBe(4);
		});
	});

	describe('generateScoringNote', () => {
		it('returns null when score delta is below threshold', () => {
			const note = generateScoringNote({ dmarc: 5 }, 2, null);
			expect(note).toBeNull();
		});

		it('returns null when score delta is exactly at negative threshold boundary', () => {
			const note = generateScoringNote({ dmarc: 5 }, -2, null);
			expect(note).toBeNull();
		});

		it('generates weight_increased note for positive delta', () => {
			const note = generateScoringNote({ dmarc: 5 }, 5, null);
			expect(note).not.toBeNull();
			expect(note).toContain('DMARC');
			expect(note).toContain('common issue across similar domains');
		});

		it('generates weight_increased_provider note when provider is present', () => {
			const note = generateScoringNote({ dmarc: 5 }, 5, 'google workspace');
			expect(note).not.toBeNull();
			expect(note).toContain('DMARC');
			expect(note).toContain('Google Workspace');
			expect(note).toContain('frequently have issues');
		});

		it('generates weight_decreased note for negative top delta', () => {
			const note = generateScoringNote({ mta_sts: -4 }, -4, null);
			expect(note).not.toBeNull();
			expect(note).toContain('MTA_STS');
			expect(note).toContain('rarely have issues');
		});

		it('generates multi_category note when 3+ significant deltas', () => {
			const note = generateScoringNote({ dmarc: 5, spf: 3, dkim: -2 }, 6, null);
			expect(note).not.toBeNull();
			expect(note).toContain('Several checks');
			expect(note).toContain('biggest shift');
			expect(note).toContain('DMARC'); // highest magnitude
		});

		it('capitalizes multi-word provider names', () => {
			const note = generateScoringNote({ spf: 3 }, 4, 'microsoft 365');
			expect(note).not.toBeNull();
			expect(note).toContain('Microsoft 365');
		});

		it('displays category as uppercase', () => {
			const note = generateScoringNote({ subdomain_takeover: 4 }, 5, null);
			expect(note).not.toBeNull();
			expect(note).toContain('SUBDOMAIN_TAKEOVER');
		});
	});
});
