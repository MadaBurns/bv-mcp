// SPDX-License-Identifier: BUSL-1.1
//
// Cluster 3 — Defects G & H
//   G. `notApplicableCategories` and `categoryScores` reconciliation
//      (single source — N/A categories must have null score, not 100).
//   H. `web_only` profile suppresses mail-only categories (dkim, mta_sts, bimi, mx)
//      regardless of the underlying check score.
//
// Reference: docs/plans/2026-05-28-fact-check-defect-remediation-tdd-plan.md §5.1, §5.2

import { describe, it, expect } from 'vitest';
import type { ScanDomainResult, MaturityStage } from '../src/tools/scan-domain';
import type { CheckCategory, CheckResult, ScanScore, DomainContext } from '../src/lib/scoring';
import { buildStructuredScanResult } from '../src/tools/scan/format-report';

function makeMockScanResult(overrides: Partial<ScanDomainResult> = {}): ScanDomainResult {
	return {
		domain: 'example.com',
		score: { overall: 80, grade: 'B', categoryScores: {} as Record<CheckCategory, number>, findings: [], summary: 'ok' } as ScanScore,
		checks: [],
		maturity: null as unknown as MaturityStage,
		context: { profile: 'mail_enabled', signals: [], weights: {}, detectedProvider: null } as DomainContext,
		cached: false,
		timestamp: '2026-05-28T00:00:00Z',
		scoringNote: null,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
		...overrides,
	};
}

describe('Defect G — categoryScores / notApplicableCategories never overlap (single source)', () => {
	it('omits SPF from notApplicableCategories when an SPF record exists (gov.uk pattern)', () => {
		// gov.uk publishes v=spf1 -all (anti-spoof) — SPF IS applicable
		const result = makeMockScanResult({
			score: {
				overall: 85,
				grade: 'A',
				categoryScores: { spf: 100, ssl: 90, dnssec: 100 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
			} as ScanScore,
			context: { profile: 'web_only', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{
					category: 'spf',
					passed: true,
					score: 100,
					findings: [{ category: 'spf', title: 'SPF record found', severity: 'info', detail: 'v=spf1 -all (anti-spoof)' }],
				},
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).not.toContain('spf');
		expect(s.categoryScores.spf).toBe(100);
	});

	it('marks SPF as notApplicable AND nulls its categoryScores entry when SPF absent + web_only', () => {
		const result = makeMockScanResult({
			score: {
				overall: 85,
				grade: 'A',
				categoryScores: { spf: 100 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
			} as ScanScore,
			context: { profile: 'web_only', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{
					category: 'spf',
					passed: true,
					score: 100,
					findings: [{ category: 'spf', title: 'No SPF record found', severity: 'info', detail: 'expected — no MX records' }],
				},
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).toContain('spf');
		expect(s.categoryScores.spf).toBeNull();
	});

	it('invariant: no category appears in both notApplicableCategories AND has a non-null score', () => {
		// Synthetic corpus modelling multiple domains.
		const corpusInputs: Array<{ profile: 'web_only' | 'mail_enabled' | 'non_mail'; checks: CheckResult[] }> = [
			// gov.uk-shape (web_only, no mail)
			{
				profile: 'web_only',
				checks: [
					{
						category: 'spf',
						passed: true,
						score: 100,
						findings: [{ category: 'spf', title: 'SPF record found', severity: 'info', detail: 'v=spf1 -all' }],
					},
					{ category: 'dkim', passed: true, score: 100, findings: [] },
					{ category: 'mta_sts', passed: true, score: 100, findings: [] },
					{ category: 'bimi', passed: true, score: 100, findings: [] },
					{ category: 'mx', passed: true, score: 100, findings: [{ category: 'mx', title: 'No MX records found', severity: 'info', detail: 'web-only domain' }] },
				] as CheckResult[],
			},
			// mail_enabled
			{
				profile: 'mail_enabled',
				checks: [
					{ category: 'spf', passed: true, score: 100, findings: [] },
					{ category: 'dkim', passed: true, score: 100, findings: [] },
				] as CheckResult[],
			},
			// non_mail
			{
				profile: 'non_mail',
				checks: [
					{
						category: 'dkim',
						passed: true,
						score: 100,
						findings: [{ category: 'dkim', title: 'No DKIM records found', severity: 'info', detail: 'no MX' }],
					},
					{
						category: 'mta_sts',
						passed: true,
						score: 100,
						findings: [{ category: 'mta_sts', title: 'No MTA-STS', severity: 'info', detail: 'N/A' }],
					},
				] as CheckResult[],
			},
		];

		for (const input of corpusInputs) {
			const result = makeMockScanResult({
				context: { profile: input.profile, signals: [], weights: {}, detectedProvider: null } as DomainContext,
				checks: input.checks,
				score: {
					overall: 85,
					grade: 'A',
					categoryScores: Object.fromEntries(input.checks.map((c) => [c.category, c.score])) as Record<CheckCategory, number>,
					findings: [],
					summary: 'ok',
				} as ScanScore,
			});
			const s = buildStructuredScanResult(result);
			for (const cat of s.notApplicableCategories) {
				expect(s.categoryScores[cat], `expected ${cat} to be null in categoryScores when listed N/A (profile=${input.profile})`).toBeNull();
			}
		}
	});
});

describe('Defect H — web_only profile suppresses mail-only categories', () => {
	const MAIL_ONLY_CATEGORIES = ['dkim', 'mta_sts', 'bimi', 'mx'] as const;

	for (const category of MAIL_ONLY_CATEGORIES) {
		it(`marks ${category} as notApplicable under web_only profile (gov.uk pattern: ${category}:0 → null)`, () => {
			// Even when the underlying check produced a numeric score of 0 (pre-fix gov.uk behaviour),
			// the structured output should report this as N/A, not 0.
			const result = makeMockScanResult({
				score: {
					overall: 85,
					grade: 'A',
					categoryScores: { [category]: 0 } as Record<CheckCategory, number>,
					findings: [],
					summary: 'ok',
				} as ScanScore,
				context: { profile: 'web_only', signals: [], weights: {}, detectedProvider: null } as DomainContext,
				checks: [
					{
						category,
						passed: false,
						score: 0,
						findings: [{ category, title: `No ${category} record found`, severity: 'info', detail: 'expected — domain has no MX records' }],
					},
				] as CheckResult[],
			});
			const s = buildStructuredScanResult(result);
			expect(s.notApplicableCategories).toContain(category);
			expect(s.categoryScores[category]).toBeNull();
		});
	}

	it('still scores web categories normally under web_only profile (ssl, dnssec, http_security)', () => {
		const result = makeMockScanResult({
			score: {
				overall: 80,
				grade: 'B',
				categoryScores: { ssl: 90, dnssec: 100, http_security: 85 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
			} as ScanScore,
			context: { profile: 'web_only', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{ category: 'ssl', passed: true, score: 90, findings: [] },
				{ category: 'dnssec', passed: true, score: 100, findings: [] },
				{ category: 'http_security', passed: true, score: 85, findings: [] },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.categoryScores.ssl).toBe(90);
		expect(s.categoryScores.dnssec).toBe(100);
		expect(s.categoryScores.http_security).toBe(85);
		expect(s.notApplicableCategories).not.toContain('ssl');
		expect(s.notApplicableCategories).not.toContain('dnssec');
		expect(s.notApplicableCategories).not.toContain('http_security');
	});

	it('does NOT mark mail-only categories N/A under mail_enabled profile', () => {
		const result = makeMockScanResult({
			score: {
				overall: 80,
				grade: 'B',
				categoryScores: { dkim: 75, mta_sts: 60 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
			} as ScanScore,
			context: { profile: 'mail_enabled', signals: [], weights: {}, detectedProvider: null } as DomainContext,
			checks: [
				{ category: 'dkim', passed: true, score: 75, findings: [] },
				{ category: 'mta_sts', passed: false, score: 60, findings: [] },
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).not.toContain('dkim');
		expect(s.notApplicableCategories).not.toContain('mta_sts');
		expect(s.categoryScores.dkim).toBe(75);
		expect(s.categoryScores.mta_sts).toBe(60);
	});
});
