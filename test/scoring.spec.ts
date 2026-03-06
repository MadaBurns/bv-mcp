import { describe, it, expect } from 'vitest';
import { buildCheckResult, createFinding, computeCategoryScore, computeScanScore, CATEGORY_DISPLAY_WEIGHTS, inferFindingConfidence } from '../src/lib/scoring';
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
			expect(result.findings[0].metadata?.confidence).toBe('deterministic');
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

		it('creates a finding with metadata when provided', () => {
			const f = createFinding('mx', 'Managed email provider detected', 'info', 'Detected provider.', {
				providerConfidence: 0.9,
			});
			expect(f.metadata).toEqual({ providerConfidence: 0.9 });
		});
	});

	describe('inferFindingConfidence', () => {
		it('returns heuristic for selector-probing DKIM misses', () => {
			const finding = createFinding(
				'dkim',
				'No DKIM records found among tested selectors',
				'high',
				'No DKIM records were found among tested selector set.',
			);
			expect(inferFindingConfidence(finding)).toBe('heuristic');
		});

		it('returns verified for takeover findings with verified metadata', () => {
			const finding = createFinding('subdomain_takeover', 'Dangling CNAME', 'critical', 'Verified takeover signal', {
				verificationStatus: 'verified',
			});
			expect(inferFindingConfidence(finding)).toBe('verified');
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
			// Scanner-aligned importance model: SPF(19) out of total 72.
			// One SPF critical => SPF score 60. Other controls remain perfect by default.
			// A critical finding also applies a global penalty.
			// Email bonus not earned (no DKIM/DMARC results), so denominator stays at 72.
			expect(scan.overall).toBe(74);
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
			// Email bonus not earned (DMARC missing), so denominator stays at 72.
			// NS(3) and CAA(2) and SUBDOMAIN_TAKEOVER(2) now contribute to the total.
			expect(scan.overall).toBe(49);
			expect(scan.grade).toBe('F');
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
			const sum = Object.values(CATEGORY_DISPLAY_WEIGHTS).reduce((a, b) => a + b, 0);
			expect(sum).toBeCloseTo(1.0);
		});

		it('applies positive modifier for high provider confidence findings', () => {
			const results: CheckResult[] = [
				buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
				buildCheckResult('mx', [
					createFinding('mx', 'Managed email provider detected', 'info', 'Inbound provider detected.', { providerConfidence: 0.95 }),
				]),
			];

			const scan = computeScanScore(results);
			expect(scan.overall).toBeGreaterThan(95);
		});

		it('applies negative modifier for low provider confidence findings', () => {
			const results: CheckResult[] = [
				buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
				buildCheckResult('mx', [
					createFinding('mx', 'Provider signature source unavailable', 'info', 'Fallback signatures used.', { providerConfidence: 0.2 }),
				]),
			];

			const scan = computeScanScore(results);
			expect(scan.overall).toBeLessThan(100);
		});
	});
});
