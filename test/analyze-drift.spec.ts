import { describe, it, expect } from 'vitest';
import type { ScanScore, Finding } from '../src/lib/scoring-model';
import { computeDrift, classifyDrift } from '../src/tools/analyze-drift';

function makeFinding(category: string, title: string, severity: string): Finding {
	return { category, title, severity, detail: 'test detail' } as Finding;
}

function makeScanScore(overall: number, grade: string, categories: Record<string, number>, findings: Finding[]): ScanScore {
	return {
		overall,
		grade,
		categoryScores: categories as Record<string, number>,
		findings,
		summary: '',
	} as ScanScore;
}

describe('analyzeDrift', () => {
	describe('computeDrift', () => {
		it('detects improving drift when score increases', () => {
			const baseline = makeScanScore(60, 'D+', { spf: 100, dmarc: 0 }, [
				makeFinding('dmarc', 'No DMARC record found', 'high'),
			]);
			const current = makeScanScore(80, 'B', { spf: 100, dmarc: 100 }, []);
			const drift = computeDrift('example.com', baseline, current);
			expect(drift.scoreDelta).toBe(20);
			expect(drift.gradeChange).toEqual({ from: 'D+', to: 'B' });
			expect(drift.improvements.length).toBeGreaterThan(0);
		});

		it('detects regressing drift when new critical findings appear', () => {
			const baseline = makeScanScore(85, 'B+', { spf: 100, ssl: 100 }, []);
			const current = makeScanScore(70, 'C+', { spf: 100, ssl: 50 }, [
				makeFinding('ssl', 'Certificate expires in 7 days', 'high'),
			]);
			const drift = computeDrift('example.com', baseline, current);
			expect(drift.scoreDelta).toBe(-15);
			expect(drift.regressions.length).toBeGreaterThan(0);
		});

		it('detects stable drift when score delta is within threshold', () => {
			const baseline = makeScanScore(82, 'B+', { spf: 100 }, []);
			const current = makeScanScore(83, 'B+', { spf: 100 }, []);
			const drift = computeDrift('example.com', baseline, current);
			expect(drift.scoreDelta).toBe(1);
		});

		it('reports category deltas only for changed categories', () => {
			const baseline = makeScanScore(70, 'C+', { spf: 80, dmarc: 60, ssl: 100 }, []);
			const current = makeScanScore(75, 'C+', { spf: 100, dmarc: 60, ssl: 100 }, []);
			const drift = computeDrift('example.com', baseline, current);
			expect(drift.categoryDeltas).toHaveProperty('spf');
			expect(drift.categoryDeltas).not.toHaveProperty('dmarc');
			expect(drift.categoryDeltas).not.toHaveProperty('ssl');
		});

		it('matches findings by category + title', () => {
			const shared = makeFinding('spf', 'SPF record valid', 'info');
			const baseline = makeScanScore(70, 'C+', {}, [shared, makeFinding('dmarc', 'Old finding', 'medium')]);
			const current = makeScanScore(75, 'C+', {}, [shared, makeFinding('ssl', 'New finding', 'high')]);
			const drift = computeDrift('example.com', baseline, current);
			expect(drift.improvements.some((f) => f.title === 'Old finding')).toBe(true);
			expect(drift.regressions.some((f) => f.title === 'New finding')).toBe(true);
		});
	});

	describe('classifyDrift', () => {
		it('classifies as improving', () => {
			expect(classifyDrift(5, 0, 0)).toBe('improving');
		});
		it('classifies as stable', () => {
			expect(classifyDrift(1, 0, 0)).toBe('stable');
		});
		it('classifies as regressing', () => {
			expect(classifyDrift(-5, 0, 0)).toBe('regressing');
		});
		it('classifies as mixed when improving but has new critical findings', () => {
			expect(classifyDrift(5, 1, 2)).toBe('mixed');
		});
	});
});
