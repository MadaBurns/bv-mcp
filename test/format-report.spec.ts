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

	it('keeps `measured` and `evidenceInsufficient` mutually exclusive (slice 2 DD4)', () => {
		// Nothing ran at all: measured false, and the evidence gate did NOT fire.
		const s = buildStructuredScanResult(makeMockScanResult({ checks: [] }));
		expect(s.measured).toBe(false);
		expect(s.evidenceInsufficient).toBe(false);
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
});
