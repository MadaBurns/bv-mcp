import { describe, it, expect } from 'vitest';
import { buildCheckResult, createFinding, computeCategoryScore, computeScanScore, CATEGORY_DEFAULTS } from '../src/lib/scoring';
import type { Finding, CheckResult } from '../src/lib/scoring';

describe('scoring', () => {
	describe('computeCategoryScore', () => {
		it('accumulates penalties from multiple findings', () => {
			const findings: Finding[] = [createFinding('spf', 'a', 'high', 'd'), createFinding('spf', 'b', 'medium', 'd')];
			expect(computeCategoryScore(findings)).toBe(100 - 25 - 15);
		});

		it('clamps score to minimum 0', () => {
			const findings: Finding[] = [
				createFinding('spf', 'a', 'critical', 'd'),
				createFinding('spf', 'b', 'critical', 'd'),
				createFinding('spf', 'c', 'critical', 'd'),
			];
			expect(computeCategoryScore(findings)).toBe(0);
		});
	});

	describe('buildCheckResult', () => {
		it('builds a passing result when score >= 50', () => {
			const findings = [createFinding('spf', 'test', 'low', 'detail')];
			const result = buildCheckResult('spf', findings);
			expect(result.category).toBe('spf');
			expect(result.passed).toBe(true);
			expect(result.score).toBe(95);
			expect(result.findings).toEqual(findings);
		});

		it('builds a failing result when score < 50', () => {
			const findings = [createFinding('dmarc', 'a', 'critical', 'd'), createFinding('dmarc', 'b', 'critical', 'd')];
			const result = buildCheckResult('dmarc', findings);
			expect(result.passed).toBe(false);
			expect(result.score).toBe(20);
		});
	});

	describe('createFinding', () => {
		it('creates a finding with all fields', () => {
			const f = createFinding('caa', 'No CAA', 'medium', 'Missing CAA records');
			expect(f).toEqual({
				category: 'caa',
				title: 'No CAA',
				severity: 'medium',
				detail: 'Missing CAA records',
			});
		});
	});

	describe('computeScanScore', () => {
		it('returns perfect score with no results', () => {
			const scan = computeScanScore([]);
			expect(scan.overall).toBe(100);
			expect(scan.grade).toBe('A+');
			expect(scan.findings).toEqual([]);
			expect(scan.summary).toContain('Excellent');
		});

		it('computes weighted average from check results', () => {
			const results: CheckResult[] = [buildCheckResult('spf', [createFinding('spf', 'x', 'critical', 'd')])];
			const scan = computeScanScore(results);
			// Scanner-aligned importance model: SPF(19) out of total 65.
			// One SPF critical => SPF score 60. Other controls remain perfect by default.
			// Email bonus not earned (no DKIM/DMARC results), so denominator stays at 65.
			expect(scan.overall).toBe(88);
			expect(scan.categoryScores.spf).toBe(60);
		});

		it('heavily penalizes missing DMARC like the scanner model', () => {
			const results: CheckResult[] = [
				buildCheckResult('spf', [createFinding('spf', 'SPF properly configured', 'info', 'ok')]),
				buildCheckResult('dmarc', [createFinding('dmarc', 'No DMARC record found', 'critical', 'missing')]),
				buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'ok')]),
				{
					category: 'dnssec',
					passed: false,
					score: 35,
					findings: [createFinding('dnssec', 'DNSSEC not validated', 'high', 'ad flag missing')],
				},
				{ category: 'ssl', passed: true, score: 100, findings: [createFinding('ssl', 'SSL configured', 'info', 'ok')] },
				{ category: 'mta_sts', passed: true, score: 80, findings: [createFinding('mta_sts', 'MTA-STS testing mode', 'low', 'testing')] },
				{ category: 'ns', passed: true, score: 100, findings: [createFinding('ns', 'NS configured', 'info', 'ok')] },
				{ category: 'caa', passed: true, score: 85, findings: [createFinding('caa', 'No CAA records', 'medium', 'optional hardening')] },
			];

			const scan = computeScanScore(results);
			// Email bonus not earned (DMARC missing), so denominator stays at 65.
			expect(scan.overall).toBe(61);
			expect(scan.grade).toBe('D+');
		});

		it('includes critical count in summary', () => {
			const results: CheckResult[] = [buildCheckResult('spf', [createFinding('spf', 'x', 'critical', 'd')])];
			const scan = computeScanScore(results);
			expect(scan.summary).toContain('critical');
		});

		it('includes high count in summary when no criticals', () => {
			const results: CheckResult[] = [buildCheckResult('spf', [createFinding('spf', 'x', 'high', 'd')])];
			const scan = computeScanScore(results);
			expect(scan.summary).toContain('high-severity');
		});

		it('category weights sum to 1.0', () => {
			const sum = Object.values(CATEGORY_DEFAULTS).reduce((a, b) => a + b, 0);
			expect(sum).toBeCloseTo(1.0);
		});
	});
});
