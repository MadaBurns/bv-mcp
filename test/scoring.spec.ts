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
			// ONLY spf ran (score 60, core weight 10). Every other core + protective category was
			// never measured, so it is EXCLUDED (renormalized), NOT padded to a phantom 100 — the
			// composite must reflect only what it measured.
			// Core: renormalized over spf alone → 0.6 → 70 * 0.6 = 42pts.
			// Protective: nothing ran → empty tier renormalizes to 100% → 20pts. Hardening: 0.
			// Base = 62. No email bonus (no DKIM/DMARC). No verified-critical penalty (deterministic,
			// not verified). No missing-control ceiling. Overall = 62.
			expect(scan.overall).toBe(62);
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
			// Three-tier scoring: DMARC missing-control → effectiveScore 0 (core, weight 16).
			// DNSSEC "ad flag missing" matches MISSING_CONTROL_REGEX + severity high + deterministic → effectiveScore 0.
			// Core (all 5 ran; weights dmarc=16, dkim=10, spf=10, dnssec=10, ssl=8, max=54):
			//   earned = 10(spf) + 0(dmarc) + 10(dkim) + 0(dnssec) + 8(ssl) = 28 → corePct=28/54≈0.519 → 36.3pts
			// Protective: only MTA-STS=80(3), NS=100(2), CAA=85(2) ran; every other protective
			//   category was never measured and is EXCLUDED (not padded to 100), so protective
			//   renormalizes over max=7: earned=6.1/7≈0.871 → 17.4pts.
			// Hardening: 0 passed of 7 → 0pts. Base≈53.7 → round=54.
			// Critical gap ceiling applies (DMARC missing) → capped at 64, but base 54 < 64.
			expect(scan.overall).toBe(54);
			expect(scan.grade).toBe('D');
		});

		it('applies global critical penalty when critical finding is verified', () => {
			const results: CheckResult[] = [
				buildCheckResult('subdomain_takeover', [
					createFinding('subdomain_takeover', 'Verified takeover', 'critical', 'Provider fingerprint confirms deprovisioned host', {
						verificationStatus: 'verified',
					}),
				]),
			];

			const scan = computeScanScore(results);
			// ONLY subdomain_takeover ran (protective, score 60, weight 4). Every other protective
			// category was never measured and is EXCLUDED (not padded to 100), so protective
			// renormalizes over that single category: (60/100)*4 / 4 = 0.6 → 20*0.6 = 12pts.
			// Core: nothing ran → empty tier renormalizes to 100% → 70pts. Hardening: 0.
			// Base = 82. No email bonus (spf/dmarc absent). Verified critical penalty = 15 → 67.
			expect(scan.overall).toBe(67);
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

		it('category display weights sum is reasonable', () => {
			const sum = Object.values(CATEGORY_DISPLAY_WEIGHTS).reduce((a, b) => a + b, 0);
			expect(sum).toBeCloseTo(1.32);
		});

		it('applies positive modifier for high provider confidence findings', () => {
			const baselineResults: CheckResult[] = [
				buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
				buildCheckResult('mx', [createFinding('mx', 'Managed email provider detected', 'info', 'Inbound provider detected.')]),
			];

			const results: CheckResult[] = [
				buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
				buildCheckResult('mx', [
					createFinding('mx', 'Managed email provider detected', 'info', 'Inbound provider detected.', { providerConfidence: 0.95 }),
				]),
			];

			const baseline = computeScanScore(baselineResults);
			const scan = computeScanScore(results);
			// High provider confidence should never lower the baseline score for equivalent findings.
			expect(scan.overall).toBeGreaterThanOrEqual(baseline.overall);
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
