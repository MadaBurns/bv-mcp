// SPDX-License-Identifier: BUSL-1.1

/**
 * Producer-side wiring for the reporting surfaces.
 *
 * The pure formatter/evaluator specs prove that a report which SAYS it was not
 * assessed renders honestly. They cannot prove the producers ever set that flag —
 * `generateFixPlan` and `mapCompliance` are what turn a scan into the report, and
 * a producer that hardcoded `assessed: true` would leave every formatter test
 * green while shipping the original defect.
 *
 * `scanDomain` is mocked with the exact shape its three degraded builders emit for
 * a domain that cannot be measured (NXDOMAIN / SERVFAIL): `checks: []` and a
 * `null` overall/grade, with the placeholder `maturity.stage = 0` that is NOT a
 * measurement.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';

const mockScanDomain = vi.fn();
const mockCheckRdap = vi.fn();

vi.mock('../src/tools/scan-domain', () => ({
	scanDomain: (...args: unknown[]) => mockScanDomain(...args),
}));

// The leads orchestrator calls RDAP alongside the scan; unmocked it goes to the
// network, throws, and the domain lands in `skipped` — which is why every
// assertion below is preceded by a reachability guard on `rankedLeads`.
vi.mock('../src/tools/check-rdap-lookup', async (importOriginal) => {
	const orig = await importOriginal<typeof import('../src/tools/check-rdap-lookup')>();
	return { ...orig, checkRdapLookup: (...args: unknown[]) => mockCheckRdap(...args) };
});

afterEach(() => {
	mockScanDomain.mockReset();
	mockCheckRdap.mockReset();
});

/** RDAP with no lock posture — MultiLock degrades to "unobservable", the scan-driven products still evaluate. */
function rdapNoPosture(): CheckResult {
	return { category: 'rdap', passed: true, score: 100, findings: [] } as unknown as CheckResult;
}

/** The NXDOMAIN / DNS-broken shape: nothing ran, nothing scored, stage is a placeholder. */
function nonResolvingScan(domain: string) {
	return {
		domain,
		score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'does not resolve' },
		checks: [] as CheckResult[],
		maturity: { stage: 0, label: 'Does not resolve', description: 'x', nextStep: 'y' },
		resolves: false,
	};
}

/** A genuinely measured scan — the discriminating control for every assertion below. */
function measuredScan(domain: string) {
	const checks: CheckResult[] = [
		{ category: 'spf', passed: true, score: 100, findings: [] } as unknown as CheckResult,
		{
			category: 'dmarc',
			passed: false,
			score: 40,
			findings: [{ category: 'dmarc', title: 'DMARC policy is p=none', severity: 'high', detail: '' }],
		} as unknown as CheckResult,
	];
	return {
		domain,
		score: { overall: 73, grade: 'C+', categoryScores: { spf: 100, dmarc: 40 }, findings: [], summary: 'ok' },
		checks,
		maturity: { stage: 2, label: 'Managed', description: 'x', nextStep: 'y' },
		resolves: true,
	};
}

/**
 * The discriminating third state, and the reason `assessed` is NOT spelled
 * `score === null`. `buildUnscoredResult` runs every check successfully and only
 * the scoring bundle fails: `checks` is populated with real findings while
 * `score.overall` is null. "No checks ran for this domain" would be a false
 * statement about this domain, and its findings ARE actionable — but the
 * hardcoded `maturity.stage: 0` placeholder is still not a posture measurement.
 */
function scoringFailedScan(domain: string) {
	const checks: CheckResult[] = [
		{
			category: 'dmarc',
			passed: false,
			score: 40,
			findings: [{ category: 'dmarc', title: 'DMARC policy is p=none', severity: 'high', detail: '' }],
		} as unknown as CheckResult,
	];
	return {
		domain,
		score: { overall: null, grade: null, categoryScores: { dmarc: 40 }, findings: [], summary: 'scoring unavailable' },
		checks,
		maturity: { stage: 0, label: 'Unscored', description: 'x', nextStep: 'y' },
		resolves: true,
	};
}

describe('generateFixPlan — producer wiring for an unmeasured domain', () => {
	it('marks the plan unassessed and abstains on the maturity stage', async () => {
		mockScanDomain.mockResolvedValue(nonResolvingScan('never-measured.example'));
		const { generateFixPlan } = await import('../src/tools/generate-fix-plan');
		const plan = await generateFixPlan('never-measured.example');

		expect(plan.assessed).toBe(false);
		expect(plan.caveat).toMatch(/no checks ran/i);
		expect(plan.maturityStage).toBeNull();
		expect(plan.score).toBeNull();
		expect(plan.grade).toBeNull();
	});

	it('keeps the real stage and marks the plan assessed for a measured domain (control)', async () => {
		mockScanDomain.mockResolvedValue(measuredScan('measured.example'));
		const { generateFixPlan } = await import('../src/tools/generate-fix-plan');
		const plan = await generateFixPlan('measured.example');

		// Without this control the assertions above would hold under a producer that
		// abstained on every plan.
		expect(plan.assessed).toBe(true);
		expect(plan.caveat).toBeNull();
		expect(plan.maturityStage).toBe(2);
		expect(plan.score).toBe(73);
		expect(plan.totalActions).toBe(1);
	});

	it('separates "no checks ran" from "the scan did not score" (discriminator)', async () => {
		mockScanDomain.mockResolvedValue(scoringFailedScan('unscored.example'));
		const { generateFixPlan } = await import('../src/tools/generate-fix-plan');
		const plan = await generateFixPlan('unscored.example');

		// Checks DID run — claiming otherwise would be a false statement, and the
		// findings are genuinely actionable. This is what rules out spelling
		// `assessed` as `score !== null`.
		expect(plan.assessed).toBe(true);
		expect(plan.caveat).toBeNull();
		expect(plan.totalActions).toBe(1);
		// …but the scan produced no overall score, so the stage-0 placeholder is not
		// a posture measurement and must not be rendered as one.
		expect(plan.score).toBeNull();
		expect(plan.maturityStage).toBeNull();
	});
});

/**
 * The leads surface on the SCORING-FAILURE shape.
 *
 * `scoringFailedScan` was modelled here for `map_compliance` and
 * `generate_fix_plan` but never for `prioritize_csc_leads`, whose fixtures only
 * ever used the nothing-ran flavour of ungraded. That gap is exactly why the tool
 * shipped a note claiming "No checks ran for this domain" about a domain whose
 * checks ran and found a critical expired certificate.
 */
describe('prioritizeCscLeads — producer wiring across BOTH ungraded shapes', () => {
	// NOTE: real-shaped `.com` domains — the orchestrator runs `validateDomain`,
	// and `.example` is a BLOCKED TLD, so a reserved-TLD fixture never reaches the
	// scan and lands in `skipped` instead. The reachability guards below caught it.
	/** The full orchestrator path, so the report reaches `rankCscLeads` as production builds it. */
	async function runLeads(domain: string) {
		mockCheckRdap.mockResolvedValue(rdapNoPosture());
		const { prioritizeCscLeads } = await import('../src/tools/prioritize-csc-leads');
		return prioritizeCscLeads({ domains: [domain] });
	}

	it('does not claim "no checks ran" when the checks ran but the scan did not score', async () => {
		mockScanDomain.mockResolvedValue(scoringFailedScan('unscored-scan.com'));
		const { formatCscLeads } = await import('../src/tools/prioritize-csc-leads');
		const report = await runLeads('unscored-scan.com');

		// Reachability guard: the orchestrator really produced a lead from the
		// mocked scan. Without it every assertion below could pass on an empty list.
		expect(report.rankedLeads).toHaveLength(1);
		const lead = report.rankedLeads[0];

		expect(lead.assessed).toBe(true);
		expect(lead.graded).toBe(false);
		expect(report.caveat).not.toMatch(/no checks ran/i);
		expect(formatCscLeads(report, 'full')).not.toMatch(/no checks ran/i);
	});

	it('does not drop the measured findings of a scan that failed to score', async () => {
		mockScanDomain.mockResolvedValue(scoringFailedScan('unscored-scan.com'));
		const report = await runLeads('unscored-scan.com');
		const lead = report.rankedLeads[0];

		// The DMARC failure is real evidence and must survive into the sales rollups.
		expect(lead.gapSeverity).not.toBeNull();
		expect(lead.gapSeverity!).toBeGreaterThan(0);
		expect(lead.recommendedCscProducts).toContain('managed_dmarc');
		expect(report.summary.totalRecommendations).toBeGreaterThan(0);
		expect(report.summary.byProduct.managed_dmarc).toBe(1);
		expect(report.summary.unassessedDomains).toBe(0);
		expect(report.summary.unscoredDomains).toBe(1);
	});

	it('still abstains completely when NO check ran (control — the other ungraded shape)', async () => {
		mockScanDomain.mockResolvedValue(nonResolvingScan('never-measured-domain.com'));
		const report = await runLeads('never-measured-domain.com');
		const lead = report.rankedLeads[0];

		// Without this control the assertions above would hold under an
		// implementation that stopped abstaining altogether.
		expect(lead.assessed).toBe(false);
		expect(lead.gapSeverity).toBeNull();
		expect(report.summary.totalRecommendations).toBe(0);
		expect(report.summary.hotLeads).toBe(0);
		expect(report.summary.unassessedDomains).toBe(1);
		expect(report.caveat).toMatch(/no checks ran/i);
	});
});

describe('mapCompliance — producer wiring for an unmeasured domain', () => {
	it('marks the report unassessed and every control not_assessed', async () => {
		mockScanDomain.mockResolvedValue(nonResolvingScan('never-measured-domain.com'));
		const { mapCompliance } = await import('../src/tools/map-compliance');
		const report = await mapCompliance('never-measured-domain.com');

		expect(report.assessed).toBe(false);
		expect(report.caveat).toMatch(/not assessable/i);
		expect(report.frameworks.soc2.percentage).toBeNull();
		expect(report.frameworks.soc2.mappings.length).toBeGreaterThan(0);
		expect(report.frameworks.soc2.mappings.every((m) => m.status === 'not_assessed')).toBe(true);
	});

	it('grades the controls it has evidence for on a measured domain (control)', async () => {
		mockScanDomain.mockResolvedValue(measuredScan('measured.example'));
		const { mapCompliance } = await import('../src/tools/map-compliance');
		const report = await mapCompliance('measured.example');

		expect(report.assessed).toBe(true);
		expect(report.caveat).toBeNull();
		// spf passes, dmarc fails → NIST §4.3.1 pass, §4.3.3 fail; the categories with
		// no check (mta_sts, dane, …) abstain rather than fabricating a failure.
		const nist = report.frameworks.nist_800_177;
		expect(nist.mappings.find((m) => m.controlId === '§4.3.1')!.status).toBe('pass');
		expect(nist.mappings.find((m) => m.controlId === '§4.3.3')!.status).toBe('fail');
		expect(nist.percentage).not.toBeNull();
		expect(nist.assessedControls).toBeGreaterThan(0);
	});

	it('does not claim "no checks ran" for a scan whose checks ran but did not score (discriminator)', async () => {
		mockScanDomain.mockResolvedValue(scoringFailedScan('unscored-scan.com'));
		const { mapCompliance, formatCompliance } = await import('../src/tools/map-compliance');
		const report = await mapCompliance('unscored-scan.com');

		// The score line abstains, but the control results are real evidence — so the
		// "no checks ran" caveat must NOT fire. Spelling `assessed` as
		// `score === null` would print a false statement here.
		expect(report.score).toBeNull();
		expect(report.assessed).toBe(true);
		expect(report.caveat).toBeNull();
		expect(report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.3.3')!.status).toBe('fail');

		const text = formatCompliance(report, 'full');
		expect(text).toContain('not measured');
		expect(text).not.toMatch(/No checks ran/i);
	});
});
