// SPDX-License-Identifier: BUSL-1.1

// SQ-291 item 2 — compare_baseline evaluates measurement per rule category, not once per scan.

import { describe, it, expect } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import type { ScanDomainResult } from '../src/tools/scan-domain';

function completed(category: string, score: number, passed: boolean, findings: CheckResult['findings'] = []): CheckResult {
	return { category, passed, score, findings } as CheckResult;
}

function transient(category: string, status: 'timeout' | 'error'): CheckResult {
	return { category, passed: false, score: 0, findings: [], checkStatus: status, partial: true } as CheckResult;
}

function scanWith(checks: CheckResult[]): ScanDomainResult {
	return {
		domain: 'partial.example',
		score: { overall: 80, grade: 'B', categoryScores: {}, findings: checks.flatMap((c) => c.findings), summary: '' },
		checks,
		maturity: { stage: 2, label: 'x', description: 'x', nextStep: null },
		context: { profile: 'mail_enabled', signals: [] },
		cached: false,
		timestamp: '2026-10-03T00:00:00.000Z',
	} as unknown as ScanDomainResult;
}

describe('SQ-291 compareBaseline — per-category measurement', () => {
	it('a timed-out dnssec check makes require_dnssec INCONCLUSIVE, not a violation', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = scanWith([completed('spf', 90, true), completed('dmarc', 95, true), transient('dnssec', 'timeout')]);
		const result = compareBaseline(scan, { require_dnssec: true, require_spf: true });
		expect(result.violations).toEqual([]);
		expect(result.inconclusiveRules).toEqual(['require_dnssec']);
		expect(result.passed).toBeNull();
		// The spf rule is still evaluated: only the unmeasured category abstains.
		expect(result.checkedRules).toBe(1);
	});

	it('an errored dmarc check makes require_dmarc_enforce INCONCLUSIVE', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = scanWith([completed('spf', 90, true), transient('dmarc', 'error')]);
		const result = compareBaseline(scan, { require_dmarc_enforce: true });
		expect(result.violations).toEqual([]);
		expect(result.inconclusiveRules).toEqual(['require_dmarc_enforce']);
		expect(result.passed).toBeNull();
	});

	it('max_critical_findings that would pass on a partial scan is INCONCLUSIVE', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = scanWith([completed('spf', 90, true), transient('dnssec', 'timeout')]);
		const result = compareBaseline(scan, { max_critical_findings: 0 });
		expect(result.inconclusiveRules).toEqual(['max_critical_findings']);
		expect(result.passed).toBeNull();
	});

	it('max_critical_findings already exceeded on a partial scan is still a violation (lower bound)', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = scanWith([
			completed('spf', 20, false, [{ category: 'spf', title: 'bad', severity: 'critical', detail: '' }] as CheckResult['findings']),
			transient('dnssec', 'timeout'),
		]);
		const result = compareBaseline(scan, { max_critical_findings: 0 });
		expect(result.violations.map((v) => v.rule)).toEqual(['max_critical_findings']);
		expect(result.passed).toBe(false);
	});

	it('control: a COMPLETED, unsatisfied dnssec check is still a violation', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const scan = scanWith([completed('spf', 90, true), completed('dnssec', 0, false)]);
		const result = compareBaseline(scan, { require_dnssec: true });
		expect(result.violations.map((v) => v.rule)).toEqual(['require_dnssec']);
		expect(result.inconclusiveRules).toEqual([]);
		expect(result.passed).toBe(false);
	});
});
