import { describe, it, expect } from 'vitest';
import {
	scoreToGrade,
	computeCategoryScore,
	buildCheckResult,
	createFinding,
	computeScanScore,
	CATEGORY_WEIGHTS,
	SEVERITY_PENALTIES,
	type Finding,
	type CheckResult,
} from '../src/lib/scoring';

describe('scoring library', () => {
	describe('scoreToGrade', () => {
		it('returns A+ for scores >= 90', () => {
			expect(scoreToGrade(90)).toBe('A+');
			expect(scoreToGrade(100)).toBe('A+');
		});

		it('returns A for scores 85-89', () => {
			expect(scoreToGrade(85)).toBe('A');
			expect(scoreToGrade(89)).toBe('A');
		});

		it('returns F for scores below 50', () => {
			expect(scoreToGrade(49)).toBe('F');
			expect(scoreToGrade(0)).toBe('F');
		});

		it('returns correct grades across the full range', () => {
			expect(scoreToGrade(80)).toBe('B+');
			expect(scoreToGrade(75)).toBe('B');
			expect(scoreToGrade(70)).toBe('C+');
			expect(scoreToGrade(65)).toBe('C');
			expect(scoreToGrade(60)).toBe('D+');
			expect(scoreToGrade(55)).toBe('D');
			expect(scoreToGrade(50)).toBe('E');
		});
	});

	describe('computeCategoryScore', () => {
		it('returns 100 for no findings', () => {
			expect(computeCategoryScore([])).toBe(100);
		});

		it('deducts correct penalty for each severity', () => {
			const critical = createFinding('spf', 'test', 'critical', 'detail');
			expect(computeCategoryScore([critical])).toBe(100 - SEVERITY_PENALTIES.critical);

			const high = createFinding('spf', 'test', 'high', 'detail');
			expect(computeCategoryScore([high])).toBe(100 - SEVERITY_PENALTIES.high);

			const medium = createFinding('spf', 'test', 'medium', 'detail');
			expect(computeCategoryScore([medium])).toBe(100 - SEVERITY_PENALTIES.medium);

			const low = createFinding('spf', 'test', 'low', 'detail');
			expect(computeCategoryScore([low])).toBe(100 - SEVERITY_PENALTIES.low);

			const info = createFinding('spf', 'test', 'info', 'detail');
			expect(computeCategoryScore([info])).toBe(100);
		});

		it('accumulates penalties from multiple findings', () => {
			const findings: Finding[] = [
				createFinding('spf', 'a', 'high', 'd'),
				createFinding('spf', 'b', 'medium', 'd'),
			];
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
			const findings = [
				createFinding('dmarc', 'a', 'critical', 'd'),
				createFinding('dmarc', 'b', 'critical', 'd'),
			];
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
			const results: CheckResult[] = [
				buildCheckResult('spf', [createFinding('spf', 'x', 'critical', 'd')]),
			];
			const scan = computeScanScore(results);
			// Scanner-aligned importance model: SPF(19) out of total 70 (including email bonus).
			// One SPF critical => SPF score 60. Other controls remain perfect by default.
			expect(scan.overall).toBe(82);
			expect(scan.categoryScores.spf).toBe(60);
		});

		it('heavily penalizes missing DMARC like the scanner model', () => {
			const results: CheckResult[] = [
				buildCheckResult('spf', [createFinding('spf', 'SPF properly configured', 'info', 'ok')]),
				buildCheckResult('dmarc', [createFinding('dmarc', 'No DMARC record found', 'critical', 'missing')]),
				buildCheckResult('dkim', [createFinding('dkim', 'DKIM configured', 'info', 'ok')]),
				{ category: 'dnssec', passed: false, score: 35, findings: [createFinding('dnssec', 'DNSSEC not validated', 'high', 'ad flag missing')] },
				{ category: 'ssl', passed: true, score: 100, findings: [createFinding('ssl', 'SSL configured', 'info', 'ok')] },
				{ category: 'mta_sts', passed: true, score: 80, findings: [createFinding('mta_sts', 'MTA-STS testing mode', 'low', 'testing')] },
				{ category: 'ns', passed: true, score: 100, findings: [createFinding('ns', 'NS configured', 'info', 'ok')] },
				{ category: 'caa', passed: true, score: 85, findings: [createFinding('caa', 'No CAA records', 'medium', 'optional hardening')] },
			];

			const scan = computeScanScore(results);
			expect(scan.overall).toBe(56);
			expect(scan.grade).toBe('D');
		});

		it('includes critical count in summary', () => {
			const results: CheckResult[] = [
				buildCheckResult('spf', [createFinding('spf', 'x', 'critical', 'd')]),
			];
			const scan = computeScanScore(results);
			expect(scan.summary).toContain('critical');
		});

		it('includes high count in summary when no criticals', () => {
			const results: CheckResult[] = [
				buildCheckResult('spf', [createFinding('spf', 'x', 'high', 'd')]),
			];
			const scan = computeScanScore(results);
			expect(scan.summary).toContain('high-severity');
		});

		it('category weights sum to 1.0', () => {
			const sum = Object.values(CATEGORY_WEIGHTS).reduce((a, b) => a + b, 0);
			expect(sum).toBeCloseTo(1.0);
		});
	});
});

