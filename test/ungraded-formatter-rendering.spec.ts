// SPDX-License-Identifier: BUSL-1.1

/**
 * Every customer-visible formatter that renders a `score/grade` pair must render
 * {@link UNGRADED_DISPLAY} when the scan produced no measurement — never
 * `null/100 (null)`.
 *
 * TypeScript does not flag `${null}` under strict, so a `number | null` widening
 * reaches these template literals silently: typecheck, lint and every existing
 * spec stayed green while four tools began printing `null/100 (null)` into client
 * reports. These tests pin the rendered OUTPUT, which is the only place the defect
 * is observable.
 *
 * The corresponding mechanical guard is in
 * `test/audits/ungraded-representation.audit.test.ts` — one rule over the whole
 * corpus, which is worth more than these eight fixtures.
 */

import { describe, it, expect } from 'vitest';
import type { OutputFormat } from '../src/handlers/tool-args';

const FORMATS: OutputFormat[] = ['compact', 'full'];

/** Assertions every ungraded rendering must satisfy, in every format. */
function expectUngraded(text: string, label: string) {
	expect(text, label).toContain('not measured');
	// The regression: `${null}` stringifies to the literal "null".
	expect(text, label).not.toContain('null/100');
	expect(text, label).not.toContain('(null)');
	// And the retired sentinel must not creep back in as a display token either.
	expect(text, label).not.toContain('N/A');
}

describe('formatCompliance — ungraded scan', () => {
	// The two fixtures are the two real states: nothing measured (so nothing
	// assessable, and no percentage to report), and a measured scan whose one
	// control genuinely failed.
	function report(score: number | null, grade: string | null) {
		const assessed = score !== null;
		const summary = assessed
			? { totalControls: 1, passing: 0, failing: 1, partial: 0, notAssessed: 0, assessedControls: 1, percentage: 0, mappings: [] }
			: { totalControls: 1, passing: 0, failing: 0, partial: 0, notAssessed: 1, assessedControls: 0, percentage: null, mappings: [] };
		return {
			domain: 'nxdomain-probe.com',
			score,
			grade,
			assessed,
			caveat: assessed ? null : 'No checks ran for this domain, so the controls below are NOT assessable.',
			frameworks: { nist_800_177: summary, pci_dss_4: summary, soc2: summary, cis_controls: summary },
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} as any;
	}

	it.each(FORMATS)('renders the ungraded token, not null/100 (null) [%s]', async (format) => {
		const { formatCompliance } = await import('../src/tools/map-compliance');
		expectUngraded(formatCompliance(report(null, null), format), `compliance/${format}`);
	});

	it.each(FORMATS)('still renders a real score line for a measured scan [%s] (control)', async (format) => {
		const { formatCompliance } = await import('../src/tools/map-compliance');
		const text = formatCompliance(report(73, 'C+'), format);
		// Without this the assertions above would hold under a formatter that
		// printed the ungraded token unconditionally.
		expect(text).toContain('73/100 (C+)');
		expect(text).not.toContain('not measured');
	});

	// map_compliance was the sharpest case: a control with NO matching check data
	// was marked `fail`, and an unmeasured domain matches nothing — so the body
	// rendered a complete framework-by-framework FAILURE for a domain that was
	// never assessed, directly under a header saying "not measured". The control
	// STATUS itself now abstains (`not_assessed`, see map-compliance.spec.ts); this
	// pins the customer-facing qualifier that must accompany it.
	it.each(FORMATS)('qualifies the per-control results so they cannot read as a real failure verdict [%s]', async (format) => {
		const { formatCompliance } = await import('../src/tools/map-compliance');
		const text = formatCompliance(report(null, null), format);

		expect(text, `compliance/${format}`).toMatch(/not assessable|cannot be assessed/i);
	});

	it.each(FORMATS)('does NOT qualify the results when the domain WAS measured [%s] (control)', async (format) => {
		const { formatCompliance } = await import('../src/tools/map-compliance');
		const text = formatCompliance(report(73, 'C+'), format);

		// Without this the assertion above would hold under a formatter that printed
		// the caveat on every report, which would devalue it to noise.
		expect(text, `compliance/${format}`).not.toMatch(/not assessable|cannot be assessed/i);
	});
});

describe('formatCscProducts — ungraded scan', () => {
	function report(score: number | null, grade: string | null) {
		return {
			domain: 'nxdomain-probe.com',
			score,
			grade,
			lockPosture: null,
			recommendations: [
				{
					product: 'csc_multilock',
					productName: 'CSC MultiLock',
					recommended: true,
					priority: 'high',
					justifyingGap: 'no lock',
					relatedFindings: [],
				},
				{
					product: 'managed_dmarc',
					productName: 'Managed DMARC',
					recommended: false,
					priority: 'none',
					justifyingGap: '',
					relatedFindings: [],
				},
				{
					product: 'digital_certificates',
					productName: 'Digital Certificates',
					recommended: false,
					priority: 'none',
					justifyingGap: '',
					relatedFindings: [],
				},
				{
					product: 'dnssec_management',
					productName: 'DNSSEC Management',
					recommended: false,
					priority: 'none',
					justifyingGap: '',
					relatedFindings: [],
				},
			],
			recommendedCount: 1,
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} as any;
	}

	it.each(FORMATS)('renders the ungraded token, not null/100 (null) [%s]', async (format) => {
		const { formatCscProducts } = await import('../src/tools/map-csc-products');
		expectUngraded(formatCscProducts(report(null, null), format), `csc/${format}`);
	});

	it.each(FORMATS)('still renders a real score line for a measured scan [%s] (control)', async (format) => {
		const { formatCscProducts } = await import('../src/tools/map-csc-products');
		const text = formatCscProducts(report(73, 'C+'), format);
		expect(text).toContain('73/100 (C+)');
		expect(text).not.toContain('not measured');
	});
});

describe('formatFixPlan — ungraded scan', () => {
	function plan(score: number | null, grade: string | null) {
		const assessed = score !== null;
		return {
			domain: 'nxdomain-probe.com',
			score,
			grade,
			// A domain nobody measured has no maturity stage either — stage 0 means
			// "Unprotected", which is a verdict.
			maturityStage: assessed ? 2 : null,
			totalActions: 0,
			actions: [],
			assessed,
			caveat: assessed ? null : 'No checks ran for this domain, so no remediation actions could be planned.',
		};
	}

	it.each(FORMATS)('renders the ungraded token, not null/100 (null) [%s]', async (format) => {
		const { formatFixPlan } = await import('../src/tools/generate-fix-plan');
		expectUngraded(formatFixPlan(plan(null, null), format), `fixplan/${format}`);
	});

	it.each(FORMATS)('still renders a real score line for a measured scan [%s] (control)', async (format) => {
		const { formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const text = formatFixPlan(plan(73, 'C+'), format);
		expect(text).toContain('73/100 (C+)');
		expect(text).not.toContain('not measured');
	});
});

describe('formatCscLeads — ungraded lead', () => {
	// An ungraded lead carries NO gap severity and is excluded from the hot-lead
	// count — a severity of 7 for a domain nobody measured is manufactured by
	// `evaluateCscProducts` recommending every product it could not observe.
	function leadReport(score: number | null, grade: string | null) {
		const graded = score !== null;
		// This fixture stands for the nothing-ran case: no severity, not hot.
		const assessed = graded;
		return {
			brand: 'dead-brand',
			totalDomains: 1,
			rankedLeads: [
				{
					domain: 'dead-brand.com',
					score,
					grade,
					graded,
					assessed,
					ownershipBucket: 'consolidated',
					gapSeverity: graded ? 7 : null,
					priorityRank: 1,
					recommendedCscProducts: [],
					recommendedCount: 0,
					topPriority: 'none',
				},
			],
			portfolioGrade: null,
			caveat: graded ? null : 'No checks ran for this domain.',
			summary: {
				totalRecommendations: 0,
				byProduct: {},
				hotLeads: graded ? 1 : 0,
				unassessedDomains: graded ? 0 : 1,
				unscoredDomains: 0,
				skipped: [],
			},
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} as any;
	}

	it.each(FORMATS)('renders the ungraded token on the lead line, not null/100 (null) [%s]', async (format) => {
		const { formatCscLeads } = await import('../src/tools/prioritize-csc-leads');
		expectUngraded(formatCscLeads(leadReport(null, null), format), `leads/${format}`);
	});

	it.each(FORMATS)('still renders a real score on the lead line for a measured domain [%s] (control)', async (format) => {
		const { formatCscLeads } = await import('../src/tools/prioritize-csc-leads');
		const text = formatCscLeads(leadReport(73, 'C+'), format);
		expect(text).toContain('73/100 (C+)');
	});

	it('renders the SAME ungraded token for an ungradeable portfolio as for an ungraded lead', async () => {
		const { formatCscLeads } = await import('../src/tools/prioritize-csc-leads');
		const { UNGRADED_DISPLAY } = await import('../src/tools/scan/format-report');
		const text = formatCscLeads(leadReport(null, null), 'full');

		// The defect this pins: ONE output carrying three vocabularies for the same
		// state — a lead line saying `null/100 (null)`, a portfolio line saying `N/A`,
		// and the scan surfaces saying `not measured`.
		const portfolioLine = text.split('\n').find((l) => l.includes('Portfolio grade'));
		expect(portfolioLine).toBeDefined();
		expect(portfolioLine).toContain(UNGRADED_DISPLAY);
	});
});
