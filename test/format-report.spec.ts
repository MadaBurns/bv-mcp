// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import type { ScanDomainResult, MaturityStage } from '../src/tools/scan-domain';
import type { CheckCategory, CheckResult, ScanScore, DomainContext } from '../src/lib/scoring';
import { computeScanEvidence } from '../src/lib/scoring';
import { buildStructuredScanResult, formatScanReport } from '../src/tools/scan/format-report';

function makeMockScanResult(overrides: Partial<ScanDomainResult> = {}): ScanDomainResult {
	return {
		domain: 'example.com',
		// Default `checks: []` below — nothing attempted, so evidence is honestly zero.
		score: {
			overall: 80,
			grade: 'B',
			categoryScores: {} as Record<CheckCategory, number>,
			findings: [],
			summary: 'ok',
			evidence: { attempted: 0, completed: 0, ratio: 0 },
		} as ScanScore,
		checks: [],
		maturity: null as unknown as MaturityStage,
		context: { profile: 'mail_enabled', signals: [], weights: {}, detectedProvider: null } as DomainContext,
		cached: false,
		timestamp: '2026-04-05T00:00:00Z',
		scoringNote: null,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
		...overrides,
	};
}

describe('buildStructuredScanResult', () => {
	it('populates checkStatuses from check results', () => {
		const result = makeMockScanResult({
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [], checkStatus: 'completed' },
				{ category: 'dmarc', passed: false, score: 0, findings: [], checkStatus: 'timeout' },
				{ category: 'ssl', passed: false, score: 0, findings: [], checkStatus: 'error' },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.checkStatuses).toEqual({ spf: 'completed', dmarc: 'timeout', ssl: 'error' });
	});

	it('defaults missing checkStatus to completed', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'spf', passed: true, score: 100, findings: [] }] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.checkStatuses.spf).toBe('completed');
	});

	it('derives dnssecSource from finding metadata', () => {
		const result = makeMockScanResult({
			checks: [
				{
					category: 'dnssec',
					passed: true,
					score: 100,
					findings: [
						{
							category: 'dnssec',
							title: 'DNSSEC inherited from TLD',
							severity: 'info',
							detail: 'x',
							metadata: { dnssecSource: 'tld_inherited' },
						},
					],
					checkStatus: 'completed',
				},
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBe('tld_inherited');
	});

	it('defaults dnssecSource to domain_configured when dnssec passed with no source finding', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'dnssec', passed: true, score: 100, findings: [], checkStatus: 'completed' }] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBe('domain_configured');
	});

	it('sets dnssecSource to null for an UNSIGNED zone (passed=true at score 60, "DNSSEC not enabled")', () => {
		// Regression: an unsigned zone scores 60 (penaltyOverride −40) and therefore
		// passes (60 ≥ 50, no missingControl). The old passed-only fallback wrongly stamped
		// it "domain_configured". It must report null — the zone is not actually signed.
		const result = makeMockScanResult({
			checks: [
				{
					category: 'dnssec',
					passed: true,
					score: 60,
					findings: [{ category: 'dnssec', title: 'DNSSEC not enabled', severity: 'high', detail: 'unsigned' }],
					checkStatus: 'completed',
				},
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBeNull();
	});

	it('sets dnssecSource to null when dnssec check failed', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'dnssec', passed: false, score: 0, findings: [], checkStatus: 'completed' }] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBeNull();
	});

	it('sets dnssecSource to null when dnssec check not present', () => {
		const result = makeMockScanResult({ checks: [] });
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBeNull();
	});

	it('sets dnssecSource to null when dnssec check timed out (even if passed=true)', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'dnssec', passed: true, score: 100, findings: [], checkStatus: 'timeout' }] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBeNull();
	});

	/**
	 * The `'timeout'` case above and this `'error'` case are DELIBERATELY separate
	 * tests, not one parameterized over both values: `dnssecSource`'s completed-gate
	 * (`isCompletedCheck(dnssecCheck)`, `format-report.ts`) is a boolean over the
	 * FULL three-member `CheckStatus` union, and a mutation that widens the gate to
	 * also accept ONE of the two transient values (e.g. treating 'error' as
	 * completed while still excluding 'timeout') would slip past a suite that only
	 * ever exercised 'timeout' here. Pins the collapse onto `isCompletedCheck`
	 * independently for BOTH transient members.
	 */
	it('sets dnssecSource to null when dnssec check errored (even if passed=true)', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'dnssec', passed: true, score: 100, findings: [], checkStatus: 'error' }] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.dnssecSource).toBeNull();
	});

	it('derives cdnProvider from http_security finding metadata', () => {
		const result = makeMockScanResult({
			checks: [
				{
					category: 'http_security',
					passed: true,
					score: 100,
					findings: [{ category: 'http_security', title: 'CDN', severity: 'info', detail: 'x', metadata: { cdnProvider: 'Cloudflare' } }],
				},
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.cdnProvider).toBe('Cloudflare');
	});

	it('sets cdnProvider to null when no http_security check', () => {
		const result = makeMockScanResult({ checks: [] });
		const s = buildStructuredScanResult(result);
		expect(s.cdnProvider).toBeNull();
	});

	it('sets cdnProvider to null when no cdnProvider metadata in findings', () => {
		const result = makeMockScanResult({
			checks: [
				{
					category: 'http_security',
					passed: true,
					score: 100,
					findings: [{ category: 'http_security', title: 'HSTS', severity: 'info', detail: 'x', metadata: {} }],
				},
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.cdnProvider).toBeNull();
	});

	it('sets notApplicableCategories for web_only profile with all-info email findings', () => {
		const result = makeMockScanResult({
			context: { profile: 'web_only', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{
					category: 'spf',
					passed: true,
					score: 100,
					findings: [{ category: 'spf', title: 'No SPF record found', severity: 'info', detail: 'expected' }],
				},
				{ category: 'dmarc', passed: true, score: 100, findings: [] },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).toContain('spf');
		expect(s.notApplicableCategories).toContain('dmarc');
	});

	it('sets notApplicableCategories for non_mail profile', () => {
		const result = makeMockScanResult({
			context: { profile: 'non_mail', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{ category: 'dkim', passed: true, score: 100, findings: [] },
				{
					category: 'mta_sts',
					passed: true,
					score: 100,
					findings: [{ category: 'mta_sts', title: 'No MTA-STS', severity: 'info', detail: 'N/A' }],
				},
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).toContain('dkim');
		expect(s.notApplicableCategories).toContain('mta_sts');
	});

	it('does not set notApplicableCategories for mail_enabled profile', () => {
		const result = makeMockScanResult({
			context: { profile: 'mail_enabled', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [{ category: 'spf', passed: true, score: 100, findings: [] }] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).toEqual([]);
	});

	it('does not mark email category as N/A when it has non-info findings', () => {
		const result = makeMockScanResult({
			context: { profile: 'web_only', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{
					category: 'spf',
					passed: false,
					score: 50,
					findings: [{ category: 'spf', title: 'Weak SPF', severity: 'medium', detail: 'some issue' }],
				},
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).not.toContain('spf');
	});

	it('separates inconclusive (errored/timed-out) categories from genuine N/A (awswaf.com regression)', () => {
		// web_only domain (no MX): dkim is a genuine non-applicable mail-only category,
		// while http_security ERRORED (e.g. a WAF endpoint) and dnssec TIMED OUT — those
		// two are "could not measure", not "does not apply".
		const result = makeMockScanResult({
			context: { profile: 'web_only', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			score: {
				overall: 70,
				grade: 'C+',
				categoryScores: { ssl: 70 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
				// Matches the real checks array below: 4 attempted, 2 completed
				// (ssl, dkim), 2 not (http_security errored, dnssec timed out).
				evidence: computeScanEvidence([
					{ category: 'ssl', passed: true, score: 70, findings: [], checkStatus: 'completed' },
					{ category: 'dkim', passed: false, score: 0, findings: [], checkStatus: 'completed' },
					{ category: 'http_security', passed: false, score: 0, findings: [], checkStatus: 'error' },
					{ category: 'dnssec', passed: false, score: 0, findings: [], checkStatus: 'timeout' },
				]),
			} as ScanScore,
			checks: [
				{
					category: 'ssl',
					passed: true,
					score: 70,
					findings: [{ category: 'ssl', title: 'Valid cert', severity: 'info', detail: 'x' }],
					checkStatus: 'completed',
				},
				{
					category: 'dkim',
					passed: false,
					score: 0,
					findings: [{ category: 'dkim', title: 'No DKIM', severity: 'info', detail: 'x' }],
					checkStatus: 'completed',
				},
				{ category: 'http_security', passed: false, score: 0, findings: [], checkStatus: 'error' },
				{ category: 'dnssec', passed: false, score: 0, findings: [], checkStatus: 'timeout' },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);

		// inconclusive = errored/timed-out checks only
		expect(s.inconclusiveCategories).toContain('http_security');
		expect(s.inconclusiveCategories).toContain('dnssec');
		expect(s.inconclusiveCategories).not.toContain('dkim'); // genuine N/A, measured fine
		expect(s.inconclusiveCategories).not.toContain('ssl'); // applicable, measured fine

		// DISJOINT (spec D2.7): an inconclusive category is "we could not measure it" and
		// must NEVER be filed as "we measured, and it does not apply". The previous
		// subset/superset relationship conflated the two.
		for (const cat of s.inconclusiveCategories) {
			expect(s.notApplicableCategories, `${cat} is inconclusive and must not also be listed not-applicable`).not.toContain(cat);
		}
		// Non-empty guard: without it the loop above is vacuous if inconclusiveCategories empties.
		expect(s.inconclusiveCategories.length).toBeGreaterThan(0);
		expect(s.notApplicableCategories).toContain('dkim'); // genuine N/A stays
		expect(s.notApplicableCategories).not.toContain('ssl'); // applicable web category
		expect(s.notApplicableCategories).not.toContain('http_security'); // errored → inconclusive only
		expect(s.notApplicableCategories).not.toContain('dnssec'); // timed out → inconclusive only

		// reconciliation invariant holds for both buckets: score is null
		expect(s.categoryScores.http_security).toBeNull();
		expect(s.categoryScores.dnssec).toBeNull();
		expect(s.categoryScores.dkim).toBeNull();
		expect(s.categoryScores.ssl).toBe(70);
	});

	it('never lists a category in BOTH buckets, across mixed profiles', () => {
		for (const profile of ['mail_enabled', 'web_only', 'non_mail'] as const) {
			const checks = [
				{ category: 'ssl', passed: true, score: 70, findings: [], checkStatus: 'completed' },
				{
					category: 'dkim',
					passed: false,
					score: 0,
					findings: [{ category: 'dkim', title: 'No DKIM', severity: 'info', detail: 'x' }],
					checkStatus: 'completed',
				},
				{ category: 'mta_sts', passed: false, score: 0, findings: [], checkStatus: 'error' },
			] as CheckResult[];
			const result = makeMockScanResult({
				context: { profile, signals: [], weights: {}, detectedProvider: null } as DomainContext,
				score: {
					overall: 70,
					grade: 'C+',
					// mta_sts: 0 pins the raw-number-leak path: the engine can still have
					// seeded a numeric score for a category whose check errored (the score
					// and the check outcome are computed independently upstream). The
					// inconclusive short-circuit must win over that raw number, not just
					// over the absence of one.
					categoryScores: { ssl: 70, mta_sts: 0 } as Record<CheckCategory, number>,
					findings: [],
					summary: 'ok',
					evidence: computeScanEvidence(checks),
				} as ScanScore,
				checks,
			});
			const s = buildStructuredScanResult(result);
			const overlap = s.inconclusiveCategories.filter((c) => s.notApplicableCategories.includes(c));
			expect(overlap, `profile ${profile} produced overlap: ${overlap.join(', ')}`).toEqual([]);
			// mta_sts errored: inconclusive in every profile, never not-applicable, always
			// null — even though sourceCategoryScores carries a raw 0 for it.
			expect(s.inconclusiveCategories).toContain('mta_sts');
			expect(s.notApplicableCategories).not.toContain('mta_sts');
			expect(s.categoryScores.mta_sts).toBeNull();
		}
	});

	it('returns empty inconclusiveCategories when all checks completed', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'spf', passed: true, score: 100, findings: [], checkStatus: 'completed' }] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.inconclusiveCategories).toEqual([]);
	});

	it('returns empty checkStatuses when checks array is empty', () => {
		const result = makeMockScanResult({ checks: [] });
		const s = buildStructuredScanResult(result);
		expect(s.checkStatuses).toEqual({});
	});

	it('includes enrichment fields when provided', () => {
		const result = makeMockScanResult();
		const s = buildStructuredScanResult(result, { percentileRank: 75, spoofabilityScore: 30 });
		expect(s.percentileRank).toBe(75);
		expect(s.spoofabilityScore).toBe(30);
	});

	it('surfaces evidence coverage derived from the checks the report is rendering', () => {
		const result = makeMockScanResult({
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [], checkStatus: 'completed' },
				{ category: 'dmarc', passed: true, score: 100, findings: [] }, // absent status === completed
				{ category: 'dnssec', passed: false, score: 0, findings: [], checkStatus: 'timeout' },
				{ category: 'ssl', passed: false, score: 0, findings: [], checkStatus: 'error' },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.evidence).toEqual({ attempted: 4, completed: 2, ratio: 0.5 });
	});

	it('reports evidenceInsufficient and the note from the SCORE, not from a local re-decision', () => {
		const result = makeMockScanResult({
			score: {
				overall: null,
				grade: null,
				categoryScores: {} as Record<CheckCategory, number>,
				findings: [],
				summary: 'Only 1 of 4 checks completed (25%).',
				evidence: { attempted: 4, completed: 1, ratio: 0.25 },
				evidenceInsufficient: true,
				evidenceNote: 'Only 1 of 4 checks completed (25%).',
			} as unknown as ScanScore,
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [], checkStatus: 'completed' },
				{ category: 'dmarc', passed: false, score: 0, findings: [], checkStatus: 'error' },
				{ category: 'dnssec', passed: false, score: 0, findings: [], checkStatus: 'timeout' },
				{ category: 'ssl', passed: false, score: 0, findings: [], checkStatus: 'timeout' },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.evidenceInsufficient).toBe(true);
		expect(s.evidenceNote).toContain('1 of 4');
		expect(s.score).toBeNull();
		expect(s.grade).toBeNull();
	});

	it('defaults evidenceInsufficient to false and the note to null on a graded scan', () => {
		const s = buildStructuredScanResult(
			makeMockScanResult({ checks: [{ category: 'spf', passed: true, score: 100, findings: [] }] as CheckResult[] }),
		);
		expect(s.evidenceInsufficient).toBe(false);
		expect(s.evidenceNote).toBeNull();
	});

	// F1 (fix round 1): these two cases discriminate "reads evidenceInsufficient off the
	// score" from "re-derives it locally from these checks" — a mutation that replaces the
	// populate line with a local re-decision (e.g. `!isEvidenceSufficient(evidence, ...)`)
	// passes every OTHER test in this file but fails one of these two, because each fixture
	// deliberately makes the local checks-derived ratio disagree with the score's own flag.
	it('reads evidenceInsufficient from the SCORE even when the LOCAL checks ratio looks fully covered', () => {
		const result = makeMockScanResult({
			score: {
				overall: null,
				grade: null,
				categoryScores: {} as Record<CheckCategory, number>,
				findings: [],
				summary: 'Evidence insufficient per an upstream policy override.',
				// Honest evidence field matching the checks below (2 attempted, 2 completed,
				// ratio 1) — a LOCAL re-derivation from these checks would conclude "fully
				// sufficient" and compute evidenceInsufficient: false. The score disagrees.
				evidence: { attempted: 2, completed: 2, ratio: 1 },
				evidenceInsufficient: true,
				evidenceNote: 'Evidence insufficient per an upstream policy override.',
			} as unknown as ScanScore,
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [], checkStatus: 'completed' },
				{ category: 'dmarc', passed: true, score: 100, findings: [], checkStatus: 'completed' },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		// A local re-decision (ratio 1 → "sufficient") would say false here; the wire must
		// still say true because the SCORE said true.
		expect(s.evidenceInsufficient).toBe(true);
	});

	it('does NOT raise evidenceInsufficient from a LOW local checks ratio when the score does not flag it', () => {
		const checks: CheckResult[] = [
			{ category: 'spf', passed: true, score: 100, findings: [], checkStatus: 'completed' },
			...Array.from(
				{ length: 9 },
				(_, i) =>
					({ category: `t${i}` as CheckCategory, passed: false, score: 0, findings: [], checkStatus: 'timeout' as const }) as CheckResult,
			),
		];
		const result = makeMockScanResult({
			score: {
				overall: 80,
				grade: 'B',
				categoryScores: { spf: 100 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
				// 1/10 completed locally (ratio 0.1) — well under any sufficiency threshold —
				// but the score carries NO evidenceInsufficient flag at all (graded normally,
				// as if upstream policy exempted this scan from the gate). A local
				// re-derivation from these checks would conclude "insufficient" and compute
				// evidenceInsufficient: true.
				evidence: { attempted: 10, completed: 1, ratio: 0.1 },
			} as ScanScore,
			checks,
		});
		const s = buildStructuredScanResult(result);
		// A local re-decision (ratio 0.1 → "insufficient") would say true here; the wire
		// must still say false because the SCORE never raised the flag.
		expect(s.evidenceInsufficient).toBe(false);
	});

	it('keeps `measured` and `evidenceInsufficient` mutually exclusive against the REAL zero-check producer (slice 2 DD4)', async () => {
		// The engine's own zero-check branch (packages/dns-checks/src/scoring/engine.ts,
		// `results.length === 0`) returns evidenceInsufficient: true for a scan that ran
		// zero checks — which, taken at face value, would violate this interface's
		// documented invariant that `measured: false` and `evidenceInsufficient: true` are
		// mutually exclusive. Pin the real producer's actual (contradictory) shape first,
		// then prove buildStructuredScanResult enforces disjointness itself rather than
		// trusting the producer to honor it.
		const { computeScanScore } = await import('@blackveil/dns-checks/scoring');
		const score = computeScanScore([]);
		expect(score.evidenceInsufficient).toBe(true);
		expect(score.evidence).toEqual({ attempted: 0, completed: 0, ratio: 0 });

		const s = buildStructuredScanResult(makeMockScanResult({ score: score as unknown as ScanScore, checks: [] }));
		expect(s.measured).toBe(false);
		expect(s.evidenceInsufficient).toBe(false);
		expect(s.evidenceNote).toBeNull();
		expect(s.evidence).toEqual({ attempted: 0, completed: 0, ratio: 0 });
	});
});

describe('formatScanReport web-only email categories', () => {
	it('shows N/A for email categories when web_only and findings are all info', () => {
		const result = makeMockScanResult({
			score: {
				overall: 85,
				grade: 'A',
				categoryScores: { spf: 100, dmarc: 100, ssl: 90 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
				// Three CheckResults below, none with checkStatus set → all completed.
				evidence: { attempted: 3, completed: 3, ratio: 1 },
			} as ScanScore,
			context: { profile: 'web_only', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{
					category: 'spf',
					passed: true,
					score: 100,
					findings: [{ category: 'spf', title: 'No SPF record found', severity: 'info', detail: 'expected' }],
				},
				{ category: 'dmarc', passed: true, score: 100, findings: [] },
				{ category: 'ssl', passed: true, score: 90, findings: [] },
			] as CheckResult[],
		});
		const output = formatScanReport(result, 'compact');
		expect(output).toContain('∅ SPF        N/A');
		expect(output).toContain('∅ DMARC      N/A');
		expect(output).not.toContain('SPF        100/100');
		// SSL is not an email category — should still show score
		expect(output).toContain('SSL');
		expect(output).toContain('90/100');
	});

	it('does NOT show N/A for mail_enabled profile even if findings are info', () => {
		const result = makeMockScanResult({
			score: {
				overall: 90,
				grade: 'A',
				categoryScores: { spf: 100 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
				// One CheckResult below, no checkStatus set → completed.
				evidence: { attempted: 1, completed: 1, ratio: 1 },
			} as ScanScore,
			context: { profile: 'mail_enabled', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [{ category: 'spf', title: 'Info', severity: 'info', detail: 'x' }] },
			] as CheckResult[],
		});
		const output = formatScanReport(result, 'compact');
		expect(output).not.toContain('N/A');
		expect(output).toContain('100/100');
	});
});

describe('formatScanReport compact truncation', () => {
	it('does not truncate critical finding detail in compact mode', () => {
		const longDetail = 'A'.repeat(280) + ' END';
		const result = makeMockScanResult({
			score: {
				overall: 50,
				grade: 'D',
				categoryScores: {} as Record<CheckCategory, number>,
				findings: [
					{
						category: 'spf' as CheckCategory,
						title: 'Critical SPF issue',
						severity: 'critical' as const,
						detail: longDetail,
					},
				],
				summary: 'ok',
				// `checks: []` below — nothing attempted, so evidence is honestly zero.
				evidence: { attempted: 0, completed: 0, ratio: 0 },
			} as ScanScore,
			checks: [],
		});
		const output = formatScanReport(result, 'compact');
		expect(output).toContain('END');
	});

	it('truncates medium finding detail at 300 chars in compact mode', () => {
		const longDetail = 'B'.repeat(350);
		const result = makeMockScanResult({
			score: {
				overall: 70,
				grade: 'C',
				categoryScores: {} as Record<CheckCategory, number>,
				findings: [
					{
						category: 'spf' as CheckCategory,
						title: 'Medium SPF issue',
						severity: 'medium' as const,
						detail: longDetail,
					},
				],
				summary: 'ok',
				// `checks: []` below — nothing attempted, so evidence is honestly zero.
				evidence: { attempted: 0, completed: 0, ratio: 0 },
			} as ScanScore,
			checks: [],
		});
		const output = formatScanReport(result, 'compact');
		// Should truncate — the 350-char detail should be cut to 300 + '...'
		expect(output).toContain('...');
		// But should NOT contain the END of the string (chars 301-350)
		// Since it's all B's, just check the total finding line doesn't include all 350 B's
		const bCount = (output.match(/B/g) || []).length;
		expect(bCount).toBeLessThanOrEqual(300);
	});
});

describe('formatScanReport evidence coverage', () => {
	it('names the coverage gap in the text report when checks did not complete', () => {
		const result = makeMockScanResult({
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [], checkStatus: 'completed' },
				{ category: 'dmarc', passed: false, score: 0, findings: [], checkStatus: 'timeout' },
			] as CheckResult[],
		});
		const text = formatScanReport(result, 'full');
		expect(text).toContain('Checks completed: 1/2');
	});

	it('does NOT add a coverage line when every check completed', () => {
		const result = makeMockScanResult({
			checks: [{ category: 'spf', passed: true, score: 100, findings: [], checkStatus: 'completed' }] as CheckResult[],
		});
		expect(formatScanReport(result, 'full')).not.toContain('Checks completed:');
	});

	it('also names the coverage gap in compact mode (F6 — the line is deliberate for interactive clients too)', () => {
		const result = makeMockScanResult({
			checks: [
				{ category: 'spf', passed: true, score: 100, findings: [], checkStatus: 'completed' },
				{ category: 'dmarc', passed: false, score: 0, findings: [], checkStatus: 'timeout' },
			] as CheckResult[],
		});
		expect(formatScanReport(result, 'compact')).toContain('Checks completed: 1/2');
	});

	it('floors the coverage percentage to match buildEvidenceNote — no 57%/58% split for the same measurement (F4)', async () => {
		const {
			buildEvidenceNote,
			EVIDENCE_SUFFICIENCY_THRESHOLD,
			computeScanEvidence: realComputeScanEvidence,
		} = await import('@blackveil/dns-checks/scoring');
		const checks: CheckResult[] = [
			...Array.from(
				{ length: 11 },
				(_, i) =>
					({
						category: `c${i}` as CheckCategory,
						passed: true,
						score: 100,
						findings: [],
						checkStatus: 'completed' as const,
					}) as CheckResult,
			),
			...Array.from(
				{ length: 8 },
				(_, i) =>
					({ category: `t${i}` as CheckCategory, passed: false, score: 0, findings: [], checkStatus: 'timeout' as const }) as CheckResult,
			),
		];
		const evidence = realComputeScanEvidence(checks);
		expect(evidence).toEqual({ attempted: 19, completed: 11, ratio: 11 / 19 });
		const evidenceNote = buildEvidenceNote(evidence, EVIDENCE_SUFFICIENCY_THRESHOLD);
		// Pin the real producer's own percentage first: floor(11/19*100) = 57, not round's 58.
		expect(evidenceNote).toContain('57%');

		const result = makeMockScanResult({
			score: {
				overall: null,
				grade: null,
				categoryScores: {} as Record<CheckCategory, number>,
				findings: [],
				summary: evidenceNote,
				evidence,
				evidenceInsufficient: true,
				evidenceNote,
			} as unknown as ScanScore,
			checks,
		});

		const text = formatScanReport(result, 'full');
		// Both the summary line (buildEvidenceNote's own text) and this report's coverage
		// line describe the SAME measurement — they must agree, and never emit "58%".
		expect(text).toContain('Checks completed: 11/19 (57%)');
		expect(text).not.toContain('58%');
	});
});

/**
 * Issue #639 — `check_dane` declares "SMTP DANE not applicable (no inbound mail)" in its
 * own finding prose and then emits an all-info CheckResult scoring a full 100. The
 * category was absent from `MAIL_ONLY_CATEGORIES_FOR_NON_MAIL_PROFILE`, so on the very
 * same non-mail domain where `dkim`/`mta_sts`/`bimi`/`mx` were correctly nulled, `dane`
 * reported a perfect score for a control the domain had no opportunity to fail.
 *
 * REPORTING ONLY. These tests pin the wire shape; the overall score is produced upstream
 * by `computeScanScore` and is deliberately untouched (DANE still earns its hardening
 * point there) — excluding it from the scoring denominator re-grades every non-mail
 * domain and is an operator decision.
 */
describe('DANE not-applicable reporting (#639)', () => {
	/** The exact CheckResult `check-dane.ts` produces for a no-MX / RFC 7505 null-MX domain. */
	const daneNotApplicableCheck = {
		category: 'dane',
		passed: true,
		score: 100,
		checkStatus: 'completed',
		findings: [
			{
				category: 'dane',
				title: 'SMTP DANE not applicable (no inbound mail)',
				severity: 'info',
				detail: 'example.com publishes no usable MX records, so SMTP DANE (TLSA at _25._tcp) is not applicable.',
			},
		],
	} as unknown as CheckResult;

	function nonMailResult(overrides: Partial<ScanDomainResult> = {}): ScanDomainResult {
		return makeMockScanResult({
			score: {
				overall: 72,
				grade: 'C+',
				categoryScores: { dane: 100, bimi: 100, ssl: 90 } as unknown as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
				evidence: { attempted: 3, completed: 3, ratio: 1 },
			} as ScanScore,
			context: { profile: 'non_mail', signals: ['No MX records'], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				daneNotApplicableCheck,
				{ category: 'bimi', passed: true, score: 100, findings: [] },
				{ category: 'ssl', passed: true, score: 90, findings: [] },
			] as CheckResult[],
			...overrides,
		});
	}

	it('files dane under notApplicableCategories with a null score on a non-mail domain', () => {
		const s = buildStructuredScanResult(nonMailResult());
		expect(s.notApplicableCategories).toContain('dane');
		expect(s.categoryScores.dane).toBeNull();
		// The reconciliation invariant this file already enforces elsewhere.
		expect(s.inconclusiveCategories).not.toContain('dane');
	});

	it('does the same under the web_only profile', () => {
		const s = buildStructuredScanResult(
			nonMailResult({
				context: { profile: 'web_only', signals: ['No MX records'], weights: {}, detectedProvider: null } as DomainContext,
			}),
		);
		expect(s.notApplicableCategories).toContain('dane');
		expect(s.categoryScores.dane).toBeNull();
	});

	it('leaves the overall score, grade and applicable categories untouched (reporting-only fix)', () => {
		const s = buildStructuredScanResult(nonMailResult());
		expect(s.score).toBe(72);
		expect(s.categoryScores.ssl).toBe(90);
	});

	it('keeps dane applicable on a mail-enabled domain', () => {
		const s = buildStructuredScanResult(
			nonMailResult({
				context: { profile: 'mail_enabled', signals: ['MX present'], weights: {}, detectedProvider: null } as DomainContext,
			}),
		);
		expect(s.notApplicableCategories).not.toContain('dane');
		expect(s.categoryScores.dane).toBe(100);
	});

	it('does NOT touch dane_https — HTTPS DANE is not a mail-only control', () => {
		const s = buildStructuredScanResult(
			nonMailResult({
				score: {
					overall: 72,
					grade: 'C+',
					categoryScores: { dane: 100, dane_https: 100 } as unknown as Record<CheckCategory, number>,
					findings: [],
					summary: 'ok',
					evidence: { attempted: 2, completed: 2, ratio: 1 },
				} as ScanScore,
				checks: [daneNotApplicableCheck, { category: 'dane_https', passed: true, score: 100, findings: [] }] as CheckResult[],
			}),
		);
		expect(s.notApplicableCategories).toContain('dane');
		expect(s.notApplicableCategories).not.toContain('dane_https');
		expect(s.categoryScores.dane_https).toBe(100);
	});

	it('reports a timed-out dane as inconclusive, never as not applicable', () => {
		const s = buildStructuredScanResult(
			nonMailResult({
				checks: [{ category: 'dane', passed: false, score: 0, findings: [], checkStatus: 'timeout' }] as CheckResult[],
			}),
		);
		expect(s.inconclusiveCategories).toContain('dane');
		expect(s.notApplicableCategories).not.toContain('dane');
		expect(s.categoryScores.dane).toBeNull();
	});

	/**
	 * The SERVFAIL / lame-delegation case specifically. `check-dane` now abstains
	 * rather than reading an unresolvable zone as "no inbound mail", and the wrapper
	 * converts that to `buildDnsErrorResult`'s shape. This pins the WIRE consequence:
	 * a domain whose MX could not be resolved must be reported "could not measure",
	 * never "does not apply" — the two are disjoint and mean different things, and the
	 * whole bug was collapsing the second into the first.
	 */
	it('reports a SERVFAIL/lame-delegation dane as inconclusive and NEVER as not applicable', () => {
		const daneServfail = {
			category: 'dane',
			passed: false,
			score: 0,
			checkStatus: 'error',
			partial: true,
			findings: [
				{
					category: 'dane',
					title: 'DANE check error',
					severity: 'high',
					detail: 'Check failed: DNS query for MX records of broken.example returned SERVFAIL',
					metadata: { errorKind: 'dns_error' },
				},
			],
		} as unknown as CheckResult;

		const s = buildStructuredScanResult(nonMailResult({ checks: [daneServfail] as CheckResult[] }));
		expect(s.inconclusiveCategories).toContain('dane');
		expect(s.notApplicableCategories).not.toContain('dane');
		expect(s.categoryScores.dane).toBeNull();
		expect(s.checkStatuses.dane).toBe('error');
		// Disjointness is the invariant, in both directions.
		expect(s.inconclusiveCategories.filter((c) => s.notApplicableCategories.includes(c))).toEqual([]);
	});

	it('renders an inconclusive dane as the ungraded token in text, not as N/A', () => {
		const daneServfail = {
			category: 'dane',
			passed: false,
			score: 0,
			checkStatus: 'error',
			partial: true,
			findings: [],
		} as unknown as CheckResult;
		const output = formatScanReport(nonMailResult({ checks: [daneServfail] as CheckResult[] }), 'compact');
		// "not applicable" is a claim about the domain; this scan made no such claim.
		expect(output).not.toContain('∅ DANE');
	});

	it('renders DANE as N/A in the text report instead of 100/100', () => {
		const output = formatScanReport(nonMailResult(), 'compact');
		expect(output).toContain('∅ DANE       N/A');
		expect(output).not.toContain('DANE       100/100');
	});

	it('text table and structuredContent agree on every N/A category (single source)', () => {
		// The prose table used to carry its own ['spf','dmarc','dkim','mta_sts'] copy of the
		// rule, so `bimi` printed 100/100 while structuredContent said null.
		const result = nonMailResult();
		const s = buildStructuredScanResult(result);
		const output = formatScanReport(result, 'compact');
		for (const cat of s.notApplicableCategories) {
			expect(output, `${cat} is N/A in structuredContent but not in the text table`).toContain(`∅ ${cat.toUpperCase().padEnd(10)} N/A`);
		}
		expect(s.notApplicableCategories).toEqual(expect.arrayContaining(['dane', 'bimi']));
	});
});
