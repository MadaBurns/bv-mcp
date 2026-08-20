import { describe, it, expect } from 'vitest';
import type { ScanScore, Finding } from '@blackveil/dns-checks/scoring';
import { nistScoreToGrade, scoreToGrade } from '@blackveil/dns-checks/scoring';
import { computeDrift, classifyDrift } from '../src/tools/analyze-drift';
import { displayGradeFor } from '../src/lib/ungraded-display';

function makeFinding(category: string, title: string, severity: string): Finding {
	return { category, title, severity, detail: 'test detail' } as Finding;
}

function makeScanScore(overall: number, grade: string, categories: Record<string, number>, findings: Finding[]): ScanScore {
	// A normal, fully graded scan — every caller passes a real numeric overall/grade
	// (the ungraded/null-score cases in this file use separate `any`-typed literals,
	// not this helper), so full evidence is the honest default. No override param:
	// no caller needs a different value.
	return {
		overall,
		grade,
		categoryScores: categories as Record<string, number>,
		findings,
		summary: '',
		evidence: { attempted: 19, completed: 19, ratio: 1 },
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
			// The DISPLAY (NIST 6-band) letters, derived from the scores — not the 9-band
			// `grade` fields the fixture carries. See the #727 describe block below.
			expect(drift.gradeChange).toEqual({ from: nistScoreToGrade(60), to: nistScoreToGrade(80) });
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

		it('suppresses category deltas and resolved-findings content for an inconclusive comparison, not just the label', async () => {
			const { computeDrift, formatDriftReport } = await import('../src/tools/analyze-drift');
			// A graded baseline that DOES carry real content to diff: a HIGH finding and
			// non-empty categoryScores. Every existing ungraded fixture uses `findings: []`
			// on both sides, which cannot expose a bug where the derived arrays are
			// computed unconditionally — this fixture deliberately can.
			const gradedBaseline = makeScanScore(80, 'B', { spf: 100, dmarc: 60 }, [makeFinding('dmarc', 'No DMARC record found', 'high')]);
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const ungradedCurrent: any = { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'not measured' };

			const drift = computeDrift('example.com', gradedBaseline, ungradedCurrent);
			expect(drift.classification).toBe('inconclusive');
			// The defect: an unconditional diff renders the vanished domain's empty
			// categoryScores/findings as a confident `spf: 100 -> 0 (-100)` and credits
			// the baseline's HIGH finding as RESOLVED — nothing was resolved, there is no
			// current scan to hold it against.
			expect(drift.categoryDeltas).toEqual({});
			expect(drift.improvements).toEqual([]);
			expect(drift.regressions).toEqual([]);
			expect(drift.changed).toEqual([]);

			const text = formatDriftReport(drift, 'full');
			expect(text).not.toContain('Resolved Findings');
			expect(text).not.toContain('No DMARC record found');
			expect(text).not.toContain('Category Changes');
			expect(text).not.toContain('-100');
		});

		it('still reports category deltas and resolved findings for a fully graded pair (control)', async () => {
			const { computeDrift, formatDriftReport } = await import('../src/tools/analyze-drift');
			const gradedBaseline = makeScanScore(80, 'B', { spf: 100, dmarc: 60 }, [makeFinding('dmarc', 'No DMARC record found', 'high')]);
			const gradedCurrent = makeScanScore(90, 'A', { spf: 100, dmarc: 100 }, []);

			const drift = computeDrift('example.com', gradedBaseline, gradedCurrent);
			expect(drift.classification).toBe('improving');
			// Without this control, the suppression above would also pass under a gate
			// that suppressed derived content unconditionally.
			expect(drift.categoryDeltas).toHaveProperty('dmarc');
			expect(drift.improvements.some((f) => f.title === 'No DMARC record found')).toBe(true);

			const text = formatDriftReport(drift, 'full');
			expect(text).toContain('Resolved Findings');
			expect(text).toContain('No DMARC record found');
			expect(text).toContain('Category Changes');
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

	/**
	 * #727: `analyze_drift` handed the engine's raw 9-band `ScanScore.grade` straight
	 * to the customer while every other customer-facing surface renders the 6-band NIST
	 * letter through `displayGradeFor`. Measured on wiz.io at 92: `scan_domain` said
	 * `"grade":"A"`, `analyze_drift` said `"gradeChange":{"from":"A+","to":"A+"}` — same
	 * domain, same score, same session.
	 *
	 * These assert the INVARIANT (the two surfaces agree, for any score) rather than a
	 * hardcoded letter, which would just pin whatever the code currently emits.
	 */
	describe('grade scale — one letter per domain across surfaces (#727)', () => {
		// Band edges of BOTH scales plus the scores where they disagree, so a fixture
		// cannot accidentally sit only where the two scales happen to coincide.
		const SCORES = [0, 40, 49, 50, 55, 56, 59, 60, 62, 63, 69, 70, 75, 76, 79, 80, 81, 86, 87, 89, 90, 91, 92, 94, 95, 100];

		it('reports the same letter the customer-facing display chokepoint reports, for every score', () => {
			for (const from of SCORES) {
				for (const to of SCORES) {
					// The fixtures carry the CANONICAL 9-band grade, exactly as the engine writes
					// it into a stored/pasted baseline and into the live scan's ScanScore.
					const baseline = makeScanScore(from, scoreToGrade(from), {}, []);
					const current = makeScanScore(to, scoreToGrade(to), {}, []);
					const drift = computeDrift('example.com', baseline, current);

					// `displayGradeFor` is the SSOT `scan_domain`/`batch_scan`/`compare_domains`
					// and `/badge` all render from — so this IS the cross-surface comparison.
					expect(drift.gradeChange, `score pair ${from} -> ${to}`).toEqual({
						from: displayGradeFor(baseline),
						to: displayGradeFor(current),
					});
					// Independently spelled, so the assertion above cannot pass by both sides
					// calling the same wrong function.
					expect(drift.gradeChange, `score pair ${from} -> ${to}`).toEqual({
						from: nistScoreToGrade(from),
						to: nistScoreToGrade(to),
					});
				}
			}
		});

		it('does not echo the internal 9-band letter where the two scales disagree', () => {
			// The wiz.io case: 92 is A+ on the canonical scale and A on the display scale.
			const divergent = SCORES.filter((s) => scoreToGrade(s) !== nistScoreToGrade(s));
			expect(divergent.length, 'fixture must include scores where the scales disagree').toBeGreaterThan(0);

			for (const score of divergent) {
				const side = makeScanScore(score, scoreToGrade(score), {}, []);
				const drift = computeDrift('example.com', side, side);
				expect(drift.gradeChange.from, `score ${score}`).not.toBe(scoreToGrade(score));
				expect(drift.gradeChange.from, `score ${score}`).toBe(nistScoreToGrade(score));
			}
		});

		it('still abstains on an ungraded side rather than substituting a letter', () => {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const ungraded: any = { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'not measured' };
			const graded = makeScanScore(92, scoreToGrade(92), {}, []);

			// The regression to guard: routing through a display mapper that reads `overall`
			// would map a null score onto `nistScoreToGrade(0)` and print F for a domain that
			// does not resolve.
			expect(computeDrift('example.com', graded, ungraded).gradeChange).toEqual({ from: nistScoreToGrade(92), to: null });
			expect(computeDrift('example.com', ungraded, graded).gradeChange).toEqual({ from: null, to: nistScoreToGrade(92) });
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
