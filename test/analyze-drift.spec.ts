import { describe, it, expect } from 'vitest';
import type { ScanScore, Finding } from '@blackveil/dns-checks/scoring';
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

		it('classifies drift as inconclusive when either side is ungraded, never as stable', async () => {
			const { computeDrift } = await import('../src/tools/analyze-drift');
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const graded: any = { overall: 80, grade: 'B', categoryScores: {}, findings: [], summary: 'ok' };
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const ungraded: any = { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'not measured' };

			const currentUngraded = computeDrift('example.com', graded, ungraded);
			expect(currentUngraded.classification).toBe('inconclusive');
			expect(currentUngraded.scoreDelta).toBeNull();

			const baselineUngraded = computeDrift('example.com', ungraded, graded);
			expect(baselineUngraded.classification).toBe('inconclusive');
			expect(baselineUngraded.scoreDelta).toBeNull();
		});

		it('still classifies a fully graded pair exactly as before', async () => {
			const { computeDrift } = await import('../src/tools/analyze-drift');
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const before: any = { overall: 80, grade: 'B', categoryScores: {}, findings: [], summary: 'ok' };
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const after: any = { overall: 90, grade: 'A', categoryScores: {}, findings: [], summary: 'ok' };
			const drift = computeDrift('example.com', before, after);
			expect(drift.scoreDelta).toBe(10);
			expect(drift.classification).toBe('improving');
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
