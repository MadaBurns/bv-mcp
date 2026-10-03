// SPDX-License-Identifier: BUSL-1.1

// SQ-291 item 3 — a category missing from one side is not comparable (no drift), and a severity
// escalation counts toward classification.

import { describe, it, expect } from 'vitest';
import type { Finding, ScanScore } from '@blackveil/dns-checks/scoring';

function finding(category: string, title: string, severity: string): Finding {
	return { category, title, severity, detail: `${title} detail` } as Finding;
}

function score(overall: number, categoryScores: Record<string, number>, findings: Finding[]): ScanScore {
	return { overall, grade: 'B', categoryScores, findings, summary: '' } as unknown as ScanScore;
}

describe('SQ-291 computeDrift — missing category is not-comparable', () => {
	it('a category absent from the current scan shows no 100->0 delta and no "Resolved" findings', async () => {
		const { computeDrift } = await import('../src/tools/analyze-drift');
		const baseline = score(80, { spf: 100, dmarc: 100 }, [
			finding('dmarc', 'DMARC policy is none', 'high'),
			finding('spf', 'SPF soft fail', 'low'),
		]);
		// dmarc timed out on the current scan: excluded from categoryScores, no findings.
		const current = score(80, { spf: 100 }, [finding('spf', 'SPF soft fail', 'low')]);
		const report = computeDrift('example.com', baseline, current);
		expect(report.categoryDeltas).toEqual({});
		expect(report.improvements).toEqual([]);
		expect(report.classification).toBe('stable');
	});

	it('a category absent from the baseline is not-comparable too (no fabricated new findings)', async () => {
		const { computeDrift } = await import('../src/tools/analyze-drift');
		const baseline = score(80, { spf: 100 }, []);
		const current = score(80, { spf: 100, dmarc: 40 }, [finding('dmarc', 'DMARC policy is none', 'high')]);
		const report = computeDrift('example.com', baseline, current);
		expect(report.categoryDeltas).toEqual({});
		expect(report.regressions).toEqual([]);
		expect(report.classification).toBe('stable');
	});

	it('control: a category present on both sides still reports its delta and findings', async () => {
		const { computeDrift } = await import('../src/tools/analyze-drift');
		const baseline = score(80, { spf: 100, dmarc: 40 }, [finding('dmarc', 'DMARC policy is none', 'high')]);
		const current = score(90, { spf: 100, dmarc: 100 }, []);
		const report = computeDrift('example.com', baseline, current);
		expect(report.categoryDeltas.dmarc).toEqual({ from: 40, to: 100, delta: 60 });
		expect(report.improvements.map((f) => f.title)).toEqual(['DMARC policy is none']);
		expect(report.classification).toBe('improving');
	});
});

describe('SQ-291 computeDrift — severity escalation counts toward classification', () => {
	it('medium -> critical on the same finding is regressing, not stable', async () => {
		const { computeDrift } = await import('../src/tools/analyze-drift');
		const baseline = score(80, { dmarc: 80 }, [finding('dmarc', 'DMARC weak', 'medium')]);
		const current = score(80, { dmarc: 80 }, [finding('dmarc', 'DMARC weak', 'critical')]);
		const report = computeDrift('example.com', baseline, current);
		expect(report.changed).toHaveLength(1);
		expect(report.classification).toBe('regressing');
	});

	it('critical -> medium (de-escalation) is not a regression', async () => {
		const { computeDrift } = await import('../src/tools/analyze-drift');
		const baseline = score(80, { dmarc: 80 }, [finding('dmarc', 'DMARC weak', 'critical')]);
		const current = score(80, { dmarc: 80 }, [finding('dmarc', 'DMARC weak', 'medium')]);
		const report = computeDrift('example.com', baseline, current);
		expect(report.changed).toHaveLength(1);
		expect(report.classification).toBe('stable');
	});

	it('low -> medium (escalation below high) does not change classification', async () => {
		const { computeDrift } = await import('../src/tools/analyze-drift');
		const baseline = score(80, { dmarc: 80 }, [finding('dmarc', 'DMARC weak', 'low')]);
		const current = score(80, { dmarc: 80 }, [finding('dmarc', 'DMARC weak', 'medium')]);
		expect(computeDrift('example.com', baseline, current).classification).toBe('stable');
	});
});
