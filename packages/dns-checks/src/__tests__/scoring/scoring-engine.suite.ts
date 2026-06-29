// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared scoring-engine test suite — the single source of truth for these tests.
 *
 * Run against BOTH import surfaces so source↔built (dist/DTS) drift is caught:
 *   - packages/dns-checks/src/__tests__/scoring/scoring-engine.spec.ts → source (`../../scoring`)
 *   - test/scoring-engine.spec.ts → built package (`@blackveil/dns-checks/scoring`)
 *
 * The two thin spec files inject their respective module; the assertions live
 * here once, so the trees can't drift apart. NOT a `.spec.ts`/`.test.ts`, so
 * neither vitest run collects it directly.
 */

import { describe, expect, it } from 'vitest';
import type { CheckCategory, CheckResult } from '../../scoring';

/** The scoring module under test — source or built package, injected by the caller. */
type ScoringModule = typeof import('../../scoring');

export function defineScoringEngineSuite(s: ScoringModule): void {
	const {
		scoreToGrade,
		nistScoreToGrade,
		NIST_GRADE_THRESHOLDS,
		computeScanScore,
		IMPORTANCE_WEIGHTS,
		CORE_WEIGHTS,
		PROTECTIVE_WEIGHTS,
		buildCheckResult,
		createFinding,
		CATEGORY_DISPLAY_WEIGHTS,
	} = s;

	describe('scoring-engine', () => {
		it('maps numeric scores to expected grade bands', () => {
			expect(scoreToGrade(92)).toBe('A+');
			expect(scoreToGrade(87)).toBe('A');
			expect(scoreToGrade(49)).toBe('F');
		});

		it('maps numeric scores to the NIST-aligned 6-band DISPLAY grade', () => {
			// Cut-points: A+≥95, A≥90, B≥80, C≥70, D≥60, F<60.
			expect(nistScoreToGrade(100)).toBe('A+');
			expect(nistScoreToGrade(95)).toBe('A+');
			expect(nistScoreToGrade(94)).toBe('A');
			expect(nistScoreToGrade(90)).toBe('A');
			expect(nistScoreToGrade(89)).toBe('B');
			expect(nistScoreToGrade(80)).toBe('B');
			expect(nistScoreToGrade(79)).toBe('C');
			expect(nistScoreToGrade(70)).toBe('C');
			expect(nistScoreToGrade(69)).toBe('D');
			expect(nistScoreToGrade(60)).toBe('D');
			expect(nistScoreToGrade(59)).toBe('F');
			expect(nistScoreToGrade(0)).toBe('F');
		});

		it('NIST 6-band emits no +/- bands (distinct from the 9-band canonical scale)', () => {
			const seen = new Set(
				Array.from({ length: 101 }, (_, score) => nistScoreToGrade(score)),
			);
			expect([...seen].sort()).toEqual(['A', 'A+', 'B', 'C', 'D', 'F']);
			// thresholds are exported + consistent with the mapping
			expect(NIST_GRADE_THRESHOLDS.A_PLUS).toBe(95);
			expect(NIST_GRADE_THRESHOLDS.D).toBe(60);
		});

		it('returns excellent summary when no check results are present', () => {
			const scan = computeScanScore([]);
			expect(scan.overall).toBe(100);
			expect(scan.summary).toContain('Excellent');
		});

		it('surfaces the three-tier breakdown on the scan score', () => {
			const scan = computeScanScore([
				buildCheckResult('http_security', [
					createFinding('http_security', 'No CSP', 'high', 'Missing Content-Security-Policy'),
				]),
			]);
			expect(scan.tierBreakdown).toBeDefined();
			expect(typeof scan.tierBreakdown?.core).toBe('number');
			expect(typeof scan.tierBreakdown?.protective).toBe('number');
			expect(typeof scan.tierBreakdown?.hardening).toBe('number');
			// core tier is the 70-point budget; all core checks absent → 100% → full core points
			expect(scan.tierBreakdown?.core).toBeGreaterThan(0);
		});

		it('omits the tier breakdown for the degenerate no-checks result', () => {
			// The empty-results early return is intentionally minimal (optional field absent).
			expect(computeScanScore([]).tierBreakdown).toBeUndefined();
		});

		it('applies verified critical penalty during aggregate scoring', () => {
			const scan = computeScanScore([
				buildCheckResult('subdomain_takeover', [
					createFinding('subdomain_takeover', 'Verified takeover', 'critical', 'Fingerprint confirmed', {
						verificationStatus: 'verified',
					}),
				]),
			]);

			// Protective tier: subdomain_takeover gets a penalty (score=60, weight=4 out of 20 total protective)
			// Core: all absent → 100% → 70 points
			// Protective earned: (60/100)*4 + (100/100)*16 = 2.4+16 = 18.4/20 = 0.92 → 0.92*20 = 18.4
			// Hardening: 0 (no hardening results)
			// Base: 70 + 18.4 + 0 = 88.4 → 88
			// Then -15 for verified critical penalty = 73
			expect(scan.overall).toBeLessThanOrEqual(75);
			expect(scan.overall).toBeGreaterThanOrEqual(70);
		});

		it('IMPORTANCE_WEIGHTS covers every CheckCategory value', () => {
			const displayKeys = Object.keys(CATEGORY_DISPLAY_WEIGHTS).sort();
			const importanceKeys = Object.keys(IMPORTANCE_WEIGHTS).sort();
			expect(importanceKeys).toEqual(displayKeys);
		});

		it('computeScanScore initialises all category scores even without results', () => {
			const scan = computeScanScore([]);
			const categories: CheckCategory[] = Object.keys(CATEGORY_DISPLAY_WEIGHTS) as CheckCategory[];
			for (const cat of categories) {
				expect(scan.categoryScores[cat]).toBe(100);
			}
		});

		it('exports CORE_WEIGHTS and PROTECTIVE_WEIGHTS', () => {
			expect(CORE_WEIGHTS).toBeDefined();
			expect(PROTECTIVE_WEIGHTS).toBeDefined();
			expect(Object.keys(CORE_WEIGHTS)).toContain('dmarc');
			expect(Object.keys(PROTECTIVE_WEIGHTS)).toContain('subdomain_takeover');
		});
	});

	describe('scoring v2 three-tier', () => {
		describe('confidence gate', () => {
			it('does not zero category for heuristic high findings', () => {
				const findings = [createFinding('dkim', 'No DKIM records found among tested selectors', 'high',
					'No DKIM records were found', { confidence: 'heuristic' })];
				const dkimResult = buildCheckResult('dkim', findings);
				const score = computeScanScore([dkimResult]);
				// DKIM contributes its computed score (75), not zeroed
				expect(score.categoryScores.dkim).toBe(75);
			});

			it('zeros category for deterministic high findings', () => {
				const findings = [createFinding('spf', 'No SPF record found', 'high',
					'No SPF record found for example.com', { confidence: 'deterministic' })];
				const spfResult = buildCheckResult('spf', findings);
				const score = computeScanScore([spfResult]);
				// SPF should be zeroed — triggers critical gap ceiling (64)
				expect(score.overall).toBeLessThanOrEqual(64);
			});
		});

		describe('three-tier formula', () => {
			it('perfect core + default protective yields ~95 with email bonus', () => {
				const results = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const).map(cat =>
					buildCheckResult(cat, [createFinding(cat, `${cat} configured`, 'info', 'All good')])
				);
				const score = computeScanScore(results);
				// Core=70 (all 100%), Protective=20 (all absent → 100%), Hardening=0 (no results)
				// Email bonus: SPF strong + DKIM present + DMARC present → +5 (emailBonusFull)
				// Total: 70 + 20 + 0 + 5 = 95
				expect(score.overall).toBe(95);
			});

			it('hardening categories can only add points', () => {
				const coreResults = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const).map(cat =>
					buildCheckResult(cat, [createFinding(cat, `${cat} ok`, 'info', 'fine')])
				);
				const scoreWithout = computeScanScore(coreResults);
				const hardeningFail = buildCheckResult('dane', [
					createFinding('dane', 'No DANE', 'high', 'No TLSA records found'),
				]);
				const scoreWith = computeScanScore([...coreResults, hardeningFail]);
				// Failed hardening contributes 0 points (score < 50) but never subtracts
				expect(scoreWith.overall).toBeGreaterThanOrEqual(scoreWithout.overall);
			});

			it('hardening pass adds bonus points', () => {
				const coreResults = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const).map(cat =>
					buildCheckResult(cat, [createFinding(cat, `${cat} ok`, 'info', 'fine')])
				);
				const scoreWithout = computeScanScore(coreResults);
				const hardeningPass = buildCheckResult('bimi', [
					createFinding('bimi', 'BIMI record configured', 'info', 'BIMI configured'),
				]);
				const scoreWith = computeScanScore([...coreResults, hardeningPass]);
				expect(scoreWith.overall).toBeGreaterThan(scoreWithout.overall);
			});

			it('new grade boundaries apply', () => {
				expect(scoreToGrade(92)).toBe('A+');
				expect(scoreToGrade(91)).toBe('A');
				expect(scoreToGrade(87)).toBe('A');
				expect(scoreToGrade(86)).toBe('B+');
				expect(scoreToGrade(76)).toBe('B');
				expect(scoreToGrade(75)).toBe('C+');
				expect(scoreToGrade(52)).toBe('D');
				expect(scoreToGrade(49)).toBe('F');
			});

			it('E grade no longer exists', () => {
				// Scores 50-54 should be D, not E
				expect(scoreToGrade(50)).toBe('D');
				expect(scoreToGrade(54)).toBe('D');
			});
		});

		describe('transient check failures are excluded from scoring, not zeroed', () => {
			const passingCore = (): CheckResult[] => [
				{ ...buildCheckResult('spf', []), score: 100, passed: true },
				{ ...buildCheckResult('dmarc', []), score: 100, passed: true },
				{ ...buildCheckResult('dkim', []), score: 100, passed: true },
				{ ...buildCheckResult('dnssec', []), score: 100, passed: true },
				{ ...buildCheckResult('ssl', []), score: 100, passed: true },
			];

			it('a transient http_security failure (checkStatus=timeout) does NOT lower the overall', () => {
				const baseline = computeScanScore(passingCore());
				const httpTimeout: CheckResult = { ...buildCheckResult('http_security', []), score: 0, passed: false, checkStatus: 'timeout' };
				const withTransient = computeScanScore([...passingCore(), httpTimeout]);
				// Excluded & renormalized → identical to the baseline, NOT dragged toward 0.
				expect(withTransient.overall).toBe(baseline.overall);
				expect(withTransient.categoryScores.http_security).toBeUndefined();
			});

			it('a transient failure with checkStatus=error is also excluded', () => {
				const baseline = computeScanScore(passingCore());
				const httpErr: CheckResult = { ...buildCheckResult('http_security', []), score: 0, passed: false, checkStatus: 'error' };
				expect(computeScanScore([...passingCore(), httpErr]).overall).toBe(baseline.overall);
			});

			it('a CONCLUSIVE low score (checkStatus completed) still counts against the overall', () => {
				const baseline = computeScanScore(passingCore());
				const httpBad: CheckResult = { ...buildCheckResult('http_security', [createFinding('http_security', 'No CSP', 'medium', 'missing')]), score: 0, passed: false };
				// Genuinely measured 0 (no transient status) must still drag the score down.
				expect(computeScanScore([...passingCore(), httpBad]).overall).toBeLessThan(baseline.overall);
			});
		});
	});
}
