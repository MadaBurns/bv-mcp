import { describe, expect, it } from 'vitest';
import { scoreToGrade, computeScanScore, IMPORTANCE_WEIGHTS } from '../src/lib/scoring-engine';
import { buildCheckResult, createFinding, CATEGORY_DISPLAY_WEIGHTS, type CheckCategory } from '../src/lib/scoring-model';

describe('scoring-engine', () => {
	it('maps numeric scores to expected grade bands', () => {
		expect(scoreToGrade(90)).toBe('A+');
		expect(scoreToGrade(75)).toBe('B');
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

		expect(scan.overall).toBe(83);
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
});