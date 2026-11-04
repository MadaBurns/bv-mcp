import { describe, it, expect } from 'vitest';
import {
	buildCheckResult,
	createFinding,
	computeCategoryScore,
	computeScanScore,
	CATEGORY_DISPLAY_WEIGHTS,
	inferFindingConfidence,
} from '../src/lib/scoring';
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
		it('reads a DECLARED confidence rather than sniffing the DKIM miss wording', () => {
			// Until scoring model 1.35.0 this returned `heuristic` from a literal
			// `text.includes('among tested selectors')` — a prose defence standing between a
			// prose trigger ("No DKIM records found" matches MISSING_CONTROL_REGEX) and a zeroed
			// core category. The literal was deleted: the real emission site in
			// `packages/dns-checks/src/checks/check-dkim.ts` declares `confidence: 'heuristic'`
			// AND `missingControl: false`, so the wording carries no weight either way.
			const declared = createFinding(
				'dkim',
				'No DKIM records found among tested selectors',
				'high',
				'No DKIM records were found among tested selector set.',
				{ confidence: 'heuristic' },
			);
			expect(inferFindingConfidence(declared)).toBe('heuristic');

			const wordingOnly = createFinding(
				'dkim',
				'No DKIM records found among tested selectors',
				'high',
				'No DKIM records were found among tested selector set.',
			);
			expect(inferFindingConfidence(wordingOnly), 'the deleted literal is back — wording must not set confidence').toBe('deterministic');
		});

		it('returns verified for takeover findings with verified metadata', () => {
			const finding = createFinding('subdomain_takeover', 'Dangling CNAME', 'critical', 'Verified takeover signal', {
				verificationStatus: 'verified',
			});
			expect(inferFindingConfidence(finding)).toBe('verified');
		});
	});

	describe('computeScanScore', () => {
		it('withholds the grade with no results (zero evidence, never a fabricated perfect score)', () => {
			// Was: "returns perfect score with no results" — a scan of nothing used to be
			// indistinguishable from a scan that measured a perfectly clean domain. The
			// intent this test pins — "no results is handled and produces findings: []" —
			// survives; only the fabricated grade is gone.
			const scan = computeScanScore([]);
			expect(scan.overall).toBeNull();
			expect(scan.grade).toBeNull();
			expect(scan.findings).toEqual([]);
			expect(scan.evidenceInsufficient).toBe(true);
		});

		it('computes weighted average from check results', () => {
			const results: CheckResult[] = [buildCheckResult('spf', [createFinding('spf', 'x', 'critical', 'd')])];
			const scan = computeScanScore(results);
			// ONLY spf ran (score 60, core weight 10). Every other core + protective category was
			// never measured, so it is EXCLUDED (renormalized), NOT padded to a phantom 100 — the
			// composite must reflect only what it measured.
			// Scoring model 2.0.0: tierSplit 75/25/0 (hardening tier retired).
			// Core: renormalized over spf alone → 0.6 → 75 * 0.6 = 45pts.
			// Protective: nothing ran → empty tier renormalizes to 100% → 25pts.
			// Base = 70. No email bonus (0 in 2.0.0). No verified-critical penalty (0 in 2.0.0).
			// No missing-control ceiling. Overall = 70.
			expect(scan.overall).toBe(70);
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
			//   earned = 10(spf) + 0(dmarc) + 10(dkim) + 0(dnssec) + 8(ssl) = 28 → corePct=28/54≈0.519 → 75 * 0.519 = 38.9pts
			// Protective: only MTA-STS=80(3), NS=100(2), CAA=85(2) ran; every other protective
			//   category was never measured and is EXCLUDED (not padded to 100), so protective
			//   renormalizes over max=7: earned=6.1/7≈0.871 → 25 * 0.871 = 21.8pts.
			// Scoring model 2.0.0: tierSplit 75/25/0 — the hardening tier is retired (0pts, no longer
			// a 0-of-N drag on the base). Base≈60.7 → round=61.
			// Critical gap ceiling applies (DMARC missing) → capped at 64, but base 61 < 64.
			expect(scan.overall).toBe(61);
			expect(scan.grade).toBe('D+');
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
			// renormalizes over that single category: (60/100)*4 / 4 = 0.6 → 25*0.6 = 15pts.
			// Core: nothing ran → empty tier renormalizes to 100% → 75pts (tierSplit 75/25/0).
			// Base = 90. Scoring model 2.0.0 sets criticalOverallPenalty to 0, so a verified
			// critical no longer subtracts a flat 15 from the overall (the finding still drives
			// the category score to 60). Overall = 90.
			expect(scan.overall).toBe(90);
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
			expect(baseline.overall).not.toBeNull();
			if (baseline.overall === null) throw new Error('Expected a graded baseline');
			expect(scan.overall).toBeGreaterThanOrEqual(baseline.overall);
		});

		it('applies negative modifier for low provider confidence findings', () => {
			const results: CheckResult[] = [
				buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
				buildCheckResult('mx', [
					createFinding('mx', 'Provider signature source unavailable', 'info', 'Fallback signatures used.', { providerConfidence: 0.2 }),
				]),
			];

			const baseline = computeScanScore([
				buildCheckResult('spf', [createFinding('spf', 'SPF record configured', 'info', 'ok')]),
				buildCheckResult('mx', [createFinding('mx', 'Provider signature source unavailable', 'info', 'Fallback signatures used.')]),
			]);
			const scan = computeScanScore(results);
			// Was `< 100`, which only held because the unmeasured hardening tier (retired in
			// scoring model 2.0.0) capped every partial scan below 100. The intent — low provider
			// confidence never RAISES the score above the equivalent baseline — is asserted directly.
			expect(baseline.overall).not.toBeNull();
			if (baseline.overall === null) throw new Error('Expected a graded baseline');
			expect(scan.overall).not.toBeNull();
			if (scan.overall === null) throw new Error('Expected a graded score');
			expect(scan.overall).toBeLessThanOrEqual(baseline.overall);
		});
	});
});
