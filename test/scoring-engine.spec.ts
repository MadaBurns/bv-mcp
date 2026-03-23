import { describe, expect, it } from 'vitest';
import { scoreToGrade, computeScanScore, IMPORTANCE_WEIGHTS, CORE_WEIGHTS, PROTECTIVE_WEIGHTS } from '../src/lib/scoring-engine';
import { buildCheckResult, createFinding, CATEGORY_DISPLAY_WEIGHTS, type CheckCategory } from '../src/lib/scoring-model';

describe('scoring-engine', () => {
	it('maps numeric scores to expected grade bands', () => {
		expect(scoreToGrade(92)).toBe('A+');
		expect(scoreToGrade(87)).toBe('A');
		expect(scoreToGrade(49)).toBe('F');
	});

	it('returns excellent summary when no check results are present', () => {
		const scan = computeScanScore([]);
		expect(scan.overall).toBe(100);
		expect(scan.summary).toContain('Excellent');
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
});
