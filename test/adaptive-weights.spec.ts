// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import {
	SENSITIVITY,
	MATURITY_THRESHOLD,
	EMA_SPAN,
	EMA_ALPHA,
	SCORING_NOTE_DELTA_THRESHOLD,
	BASELINE_FAILURE_RATES,
	resolveBaselineFailureRates,
	WEIGHT_BOUNDS,
	defaultBounds,
	computeAdaptiveWeight,
	blendWeights,
	adaptiveWeightsToContext,
	generateScoringNote,
} from '../src/lib/adaptive-weights';
// Type-only imports verified to exist: ScanTelemetry, AdaptiveWeightsResponse, WeightBound
import { DEFAULT_SCORING_CONFIG, PROFILE_WEIGHTS, getProfileWeights, parseScoringConfig } from '@blackveil/dns-checks/scoring';
import type { DomainProfile } from '@blackveil/dns-checks/scoring';
import type { CheckCategory } from '@blackveil/dns-checks/scoring';

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

		// Deliberately asserts the SHAPE of the imported constant, never a restatement of
		// its 13 literals. The table used to be written out a third time right here (once
		// in `src/lib/adaptive-weights.ts`, once in the scoring package's
		// `DEFAULT_SCORING_CONFIG.baselineFailureRates`, once here) — three copies that
		// could drift independently, and a spec that "passed" by agreeing with a copy of
		// itself rather than checking anything.
		it('BASELINE_FAILURE_RATES covers exactly the 13 prior-calibrated categories', () => {
			expect(Object.keys(BASELINE_FAILURE_RATES).sort()).toEqual(
				[
					'bimi',
					'caa',
					'dkim',
					'dmarc',
					'dnssec',
					'lookalikes',
					'mta_sts',
					'mx',
					'ns',
					'spf',
					'ssl',
					'subdomain_takeover',
					'tlsrpt',
				].sort(),
			);
		});

		it('BASELINE_FAILURE_RATES values are all valid probabilities', () => {
			for (const [category, rate] of Object.entries(BASELINE_FAILURE_RATES)) {
				expect(typeof rate, category).toBe('number');
				expect(Number.isFinite(rate), category).toBe(true);
				expect(rate, category).toBeGreaterThanOrEqual(0);
				expect(rate, category).toBeLessThanOrEqual(1);
			}
		});

		// The SSOT lock: the worker's table must not drift from the scoring package's
		// `DEFAULT_SCORING_CONFIG.baselineFailureRates`, which is what a `SCORING_CONFIG`
		// override is merged onto. If these two disagree, an operator setting the override
		// key gets a baseline that silently differs from the one they read in the package.
		it('BASELINE_FAILURE_RATES agrees with the scoring package defaults for every category it covers', () => {
			for (const [category, rate] of Object.entries(BASELINE_FAILURE_RATES)) {
				expect(DEFAULT_SCORING_CONFIG.baselineFailureRates[category], category).toBe(rate);
			}
		});
	});

	// ─── SCORING_CONFIG.baselineFailureRates must actually reach the accumulator ──

	describe('resolveBaselineFailureRates', () => {
		it('returns the static table (same identity) when no config is supplied', () => {
			expect(resolveBaselineFailureRates()).toBe(BASELINE_FAILURE_RATES);
			expect(resolveBaselineFailureRates('')).toBe(BASELINE_FAILURE_RATES);
		});

		it('returns the static table when the config supplies no baseline override', () => {
			const resolved = resolveBaselineFailureRates(JSON.stringify({ coreWeights: { dmarc: 22 } }));
			expect(resolved).toBe(BASELINE_FAILURE_RATES);
		});

		it('fails soft to the static table on an unparseable config', () => {
			expect(resolveBaselineFailureRates('{not json')).toBe(BASELINE_FAILURE_RATES);
		});

		it('overlays only the categories the config actually moves', () => {
			const resolved = resolveBaselineFailureRates(JSON.stringify({ baselineFailureRates: { dmarc: 0.9 } }));

			// The overridden category is live — this is the whole point: before this
			// function existed the key parsed fine and was then read by nobody.
			expect(resolved.dmarc).toBe(0.9);
			// Every other category is untouched, and the static object itself is not mutated.
			expect(resolved.spf).toBe(BASELINE_FAILURE_RATES.spf);
			expect(BASELINE_FAILURE_RATES.dmarc).not.toBe(0.9);
			expect(resolved).not.toBe(BASELINE_FAILURE_RATES);
		});

		it('does not import priors for categories the worker deliberately leaves unset', () => {
			// `http_security` has a 0.35 prior in the PACKAGE table but no worker prior:
			// the accumulator resolves it to 0. Copying the parsed config wholesale would
			// silently switch that on for 15 categories — a behaviour change, not a dedup.
			const resolved = resolveBaselineFailureRates(JSON.stringify({ baselineFailureRates: { dmarc: 0.9 } }));
			expect(resolved.http_security).toBeUndefined();
			expect(DEFAULT_SCORING_CONFIG.baselineFailureRates.http_security).toBe(0.35);
		});

		it('defers to the package sanitizer for junk override values', () => {
			// `parseScoringConfig`'s `mergeWeights` already clamps negatives to 0 and drops
			// non-numeric values, so the resolver inherits exactly those semantics rather
			// than inventing a second, divergent validation policy.
			const resolved = resolveBaselineFailureRates(JSON.stringify({ baselineFailureRates: { dmarc: -1, spf: 'nope' } }));
			expect(resolved.dmarc).toBe(0);
			expect(resolved.spf).toBe(BASELINE_FAILURE_RATES.spf);
		});

		it('drops override keys the package does not recognise as categories', () => {
			const resolved = resolveBaselineFailureRates(JSON.stringify({ baselineFailureRates: { not_a_category: 0.5 } }));
			expect(resolved).toBe(BASELINE_FAILURE_RATES);
		});
	});

	// ─── The adaptive delta's two operands must share a base ──────────────

	describe('adaptiveWeightsToContext — static base', () => {
		it('falls back to the CONFIG-resolved profile weight, not the raw table', () => {
			const config = parseScoringConfig(JSON.stringify({ profileWeights: { mail_enabled: { spf: 30 } } }));
			// Empty DO response ⇒ every category takes the fallback path.
			const resolved = adaptiveWeightsToContext({}, 'mail_enabled', config);

			expect(resolved).not.toBeNull();
			expect(resolved!.spf.importance).toBe(30);
			expect(PROFILE_WEIGHTS.mail_enabled.spf.importance).not.toBe(30);
		});

		it('produces zero deltas against getProfileWeights when the DO has no data (no phantom deltas)', () => {
			// This is the exact computation `scan-domain.ts` performs. Reading the fallback
			// from the raw `PROFILE_WEIGHTS` while the static side came from
			// `getProfileWeights(profile, config)` made every overridden category report a
			// non-zero "adaptive" delta that no adaptation produced — and the customer-visible
			// `scoringNote` fires off exactly those deltas.
			const config = parseScoringConfig(JSON.stringify({ profileWeights: { mail_enabled: { spf: 30, dmarc: 1 } } }));
			const adaptive = adaptiveWeightsToContext({}, 'mail_enabled', config)!;
			const staticWeights = getProfileWeights('mail_enabled', config);

			for (const cat of Object.keys(staticWeights) as CheckCategory[]) {
				expect(adaptive[cat].importance - staticWeights[cat].importance, cat).toBe(0);
			}
		});

		it('still honours a real DO weight over the static base', () => {
			const config = parseScoringConfig(JSON.stringify({ profileWeights: { mail_enabled: { spf: 30 } } }));
			const resolved = adaptiveWeightsToContext({ spf: 12 }, 'mail_enabled', config)!;
			expect(resolved.spf.importance).toBe(12);
		});

		it('omitting the config reproduces the raw-table base', () => {
			const resolved = adaptiveWeightsToContext({}, 'mail_enabled')!;
			expect(resolved.spf.importance).toBe(PROFILE_WEIGHTS.mail_enabled.spf.importance);
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
			expect(b.min).toBe(Math.max(5, Math.floor(16 * 0.5))); // 8
		});

		it('applies non-critical floor for ns in mail_enabled', () => {
			const b = WEIGHT_BOUNDS.mail_enabled.ns;
			expect(b.min).toBe(1); // max(0, floor(2*0.5)) = 1 (ns importance is now 2 in mail_enabled)
		});

		it('treats ssl as critical for mail_enabled and enterprise_mail', () => {
			// ssl importance=5 in mail_enabled → critical → min=max(5,2)=5
			expect(WEIGHT_BOUNDS.mail_enabled.ssl.min).toBe(5);
			// ssl importance=5 in enterprise_mail → critical → min=5
			expect(WEIGHT_BOUNDS.enterprise_mail.ssl.min).toBe(5);
		});

		it('treats ssl as non-critical for non_mail profile', () => {
			// ssl importance=10 in non_mail → not critical mail → min=max(0,5)=5
			expect(WEIGHT_BOUNDS.non_mail.ssl.min).toBe(5);
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
			expect(result!.dkim.importance).toBe(10);
			expect(result!.ssl.importance).toBe(8);
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
			expect(result!.dmarc.importance).toBe(20); // enterprise_mail static
			expect(result!.mta_sts.importance).toBe(4);
		});
	});

	describe('generateScoringNote', () => {
		// Adaptive weighting is telemetry-only: the returned scan score uses static
		// profile weights (scan-domain.ts line ~615 re-runs computeScanScore against
		// scoringContext). The note must therefore NOT claim the score was adjusted,
		// reweighted, or shifted. It may describe observed peer patterns, but must be
		// explicitly framed as a non-scoring / experimental signal.
		const FORBIDDEN_SCORING_CLAIM = /carried (more|less) weight|weighted differently|biggest shift|adjusted the score|changed (the|this) score/i;
		const HONEST_DISCLAIMER = /did not (affect|change)|does not (affect|change)|non-scoring|experimental signal|no effect on (the|this) score/i;

		const expectHonest = (note: string | null) => {
			expect(note).not.toBeNull();
			expect(note!).not.toMatch(FORBIDDEN_SCORING_CLAIM);
			expect(note!).toMatch(HONEST_DISCLAIMER);
		};

		it('returns null when score delta is below threshold', () => {
			const note = generateScoringNote({ dmarc: 5 }, 2, null);
			expect(note).toBeNull();
		});

		it('returns null when score delta is exactly at negative threshold boundary', () => {
			const note = generateScoringNote({ dmarc: 5 }, -2, null);
			expect(note).toBeNull();
		});

		it('generates an honest, non-scoring note for positive delta', () => {
			const note = generateScoringNote({ dmarc: 5 }, 5, null);
			expectHonest(note);
			expect(note).toContain('DMARC');
		});

		it('generates an honest, non-scoring note when provider is present', () => {
			const note = generateScoringNote({ dmarc: 5 }, 5, 'google workspace');
			expectHonest(note);
			expect(note).toContain('DMARC');
			expect(note).toContain('Google Workspace');
		});

		it('generates an honest, non-scoring note for negative top delta', () => {
			const note = generateScoringNote({ mta_sts: -4 }, -4, null);
			expectHonest(note);
			expect(note).toContain('MTA_STS');
		});

		it('generates an honest, non-scoring multi-category note when 3+ significant deltas', () => {
			const note = generateScoringNote({ dmarc: 5, spf: 3, dkim: -2 }, 6, null);
			expectHonest(note);
			expect(note).toContain('DMARC'); // highest magnitude
		});

		it('capitalizes multi-word provider names', () => {
			const note = generateScoringNote({ spf: 3 }, 4, 'microsoft 365');
			expectHonest(note);
			expect(note).toContain('Microsoft 365');
		});

		it('displays category as uppercase', () => {
			const note = generateScoringNote({ subdomain_takeover: 4 }, 5, null);
			expectHonest(note);
			expect(note).toContain('SUBDOMAIN_TAKEOVER');
		});
	});
});

describe('adaptive weight KV convergence', () => {
	function makeKv() {
		const store = new Map<string, string>();
		return {
			kv: {
				async get(key: string) { return store.get(key) ?? null; },
				async put(key: string, value: string, _opts?: { expirationTtl?: number }) { store.set(key, value); },
				async delete(key: string) { store.delete(key); },
			} as unknown as KVNamespace,
			store,
		};
	}

	it('publishAdaptiveWeightSummary + getAdaptiveWeights round-trip via KV', async () => {
		const { kv } = makeKv();
		const { publishAdaptiveWeightSummary, getAdaptiveWeights } = await import('../src/lib/profile-accumulator');
		const weights = { spf: 10.5, dmarc: 16.2 };
		await publishAdaptiveWeightSummary('mail_enabled', 'google', weights, kv);
		const a = await getAdaptiveWeights('mail_enabled', 'google', kv);
		const b = await getAdaptiveWeights('mail_enabled', 'google', kv);
		expect(a).toEqual(b);
		expect(a).toEqual(weights);
	});

	it('getAdaptiveWeights returns null on cache miss (caller falls back to static)', async () => {
		const { kv } = makeKv();
		const { getAdaptiveWeights } = await import('../src/lib/profile-accumulator');
		expect(await getAdaptiveWeights('mail_enabled', 'unknown', kv)).toBeNull();
	});

	it('getAdaptiveWeights returns null on KV error (graceful fallback)', async () => {
		const kv = {
			async get() { throw new Error('KV down'); },
			async put() {},
			async delete() {},
		} as unknown as KVNamespace;
		const { getAdaptiveWeights } = await import('../src/lib/profile-accumulator');
		expect(await getAdaptiveWeights('mail_enabled', 'google', kv)).toBeNull();
	});
});
