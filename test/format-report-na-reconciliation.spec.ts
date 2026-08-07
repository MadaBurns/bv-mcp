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
import { computeScanEvidence, PROFILE_WEIGHTS } from '../src/lib/scoring';
import { buildStructuredScanResult } from '../src/tools/scan/format-report';

/**
 * A REAL `DomainContext`, not a cast.
 *
 * Every context in this file used to be `{ profile, signals: [], weights: {}, … } as
 * DomainContext`, which TypeScript rejected (TS2352) because `weights` is a
 * `Record<CheckCategory, ImportanceProfile>` and `{}` is not one. Eight suppressed
 * errors in a spec whose entire subject is per-category scoring behaviour is exactly
 * the vacuity risk the `typecheck:tests` ratchet exists to catch — a cast that wide
 * would have hidden a genuinely wrong `profile` value too.
 */
function makeContext(profile: DomainContext['profile']): DomainContext {
	return { profile, signals: [], weights: PROFILE_WEIGHTS[profile], detectedProvider: null };
}

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
		context: makeContext('mail_enabled'),
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
				// One CheckResult below (spf), no checkStatus set → completed.
				evidence: { attempted: 1, completed: 1, ratio: 1 },
			} as ScanScore,
			context: makeContext('web_only'),
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
				// One CheckResult below (spf), no checkStatus set → completed.
				evidence: { attempted: 1, completed: 1, ratio: 1 },
			} as ScanScore,
			context: makeContext('web_only'),
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
				context: makeContext(input.profile),
				checks: input.checks,
				score: {
					overall: 85,
					grade: 'A',
					categoryScores: Object.fromEntries(input.checks.map((c) => [c.category, c.score])) as Record<CheckCategory, number>,
					findings: [],
					summary: 'ok',
					// Matches this iteration's real checks array (varies per corpus entry).
					evidence: computeScanEvidence(input.checks),
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
	const MAIL_ONLY_CATEGORIES = ['dkim', 'mta_sts', 'bimi', 'mx', 'dane'] as const;

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
					// One CheckResult below, no checkStatus set → completed.
					evidence: { attempted: 1, completed: 1, ratio: 1 },
				} as ScanScore,
				context: makeContext('web_only'),
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

	/**
	 * #639 — `dane` self-declared "not applicable (no inbound mail)" in its own finding
	 * text and then took a FULL 100 for the control, while `dkim`/`mta_sts`/`bimi`/`mx`
	 * on the same domain were correctly nulled. Awarding full marks for a control the
	 * domain had no opportunity to fail inflates the overall score.
	 *
	 * The 100 shape is what makes this distinct from the cases above: those pin the
	 * pre-fix gov.uk pattern of a numeric 0 being reported as 0. Rule 2 fires at ANY
	 * score, so both ends need pinning — a regression that re-narrowed Rule 2 to
	 * "only when the score is 0" would pass every case above and still ship #639.
	 */
	it('nulls a self-declared-inapplicable dane scoring 100 under a non-mail profile (#639)', () => {
		const result = makeMockScanResult({
			score: {
				overall: 85,
				grade: 'A',
				categoryScores: { dane: 100 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
				evidence: { attempted: 1, completed: 1, ratio: 1 },
			} as ScanScore,
			context: makeContext('non_mail'),
			checks: [
				{
					category: 'dane',
					passed: true,
					score: 100,
					findings: [
						{
							category: 'dane',
							title: 'SMTP DANE not applicable (no inbound mail)',
							severity: 'info',
							detail: 'Domain publishes no usable MX records; TLSA at _25._tcp is therefore not applicable.',
						},
					],
				},
			] as CheckResult[],
		});
		const s = buildStructuredScanResult(result);
		expect(s.notApplicableCategories).toContain('dane');
		expect(s.categoryScores.dane).toBeNull();
	});

	it('still scores web categories normally under web_only profile (ssl, dnssec, http_security)', () => {
		const result = makeMockScanResult({
			score: {
				overall: 80,
				grade: 'B',
				categoryScores: { ssl: 90, dnssec: 100, http_security: 85 } as Record<CheckCategory, number>,
				findings: [],
				summary: 'ok',
				// Three CheckResults below, none with checkStatus set → all completed.
				evidence: { attempted: 3, completed: 3, ratio: 1 },
			} as ScanScore,
			context: makeContext('web_only'),
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
				// Two CheckResults below, no checkStatus set → completed.
				evidence: { attempted: 2, completed: 2, ratio: 1 },
			} as ScanScore,
			context: makeContext('mail_enabled'),
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

describe('categoryScores never lists a category that never ran (end-to-end engine → format-report)', () => {
	// Reproduces the bnz.co.nz symptom: scan_domain runs a fixed roster that OMITS lookalikes/
	// shadow_domains, yet the composite reported categoryScores.lookalikes = 100 (and
	// shadow_domains = 100) with NO checkStatuses entry — a never-run brand-abuse dimension
	// reading "perfect". Runs the REAL engine so a regression of the 100-seed is caught here too.
	it('a never-run category is absent from categoryScores and every score key has a checkStatus', async () => {
		const { computeProfileAwareScanScore, buildCheckResult, createFinding } = await import('../src/lib/scoring');

		// A realistic scan_domain-style roster: core + several protective ran; lookalikes and
		// shadow_domains were NEVER dispatched (not in CHECK_DISPATCH).
		const ranChecks: CheckResult[] = [
			{ ...buildCheckResult('spf', []), score: 100, passed: true },
			{ ...buildCheckResult('dmarc', []), score: 100, passed: true },
			{ ...buildCheckResult('dkim', []), score: 100, passed: true },
			{ ...buildCheckResult('dnssec', []), score: 100, passed: true },
			{ ...buildCheckResult('ssl', []), score: 100, passed: true },
			{
				...buildCheckResult('subdomain_takeover', [
					createFinding('subdomain_takeover', 'Dangling delegation', 'high', 'takeover risk'),
				]),
				score: 0,
				passed: false,
			},
			{ ...buildCheckResult('http_security', []), score: 90, passed: true },
		];
		const scored = computeProfileAwareScanScore(ranChecks);
		const result = makeMockScanResult({
			score: scored.score,
			context: { ...scored.context },
			checks: ranChecks,
		});

		const s = buildStructuredScanResult(result);

		// The never-run brand-abuse categories must NOT surface as a phantom 100.
		expect(s.categoryScores.lookalikes ?? null).toBeNull();
		expect(s.categoryScores.shadow_domains ?? null).toBeNull();

		// Acceptance invariant: every category carrying a NON-null numeric score must have run
		// (i.e. appear in checkStatuses). A score with no execution status is the exact defect.
		for (const [category, score] of Object.entries(s.categoryScores)) {
			if (score !== null) {
				expect(s.checkStatuses).toHaveProperty(category);
			}
		}
	});
});
