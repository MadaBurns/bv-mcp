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

// `importOriginal` preserves the module's other named exports (e.g.
// `SCAN_CATEGORIES`, used by the all-transient fixture below to build one
// CheckResult per real scan category) while still overriding `scanDomain`
// itself.
vi.mock('../src/tools/scan-domain', async (importOriginal) => {
	const orig = await importOriginal<typeof import('../src/tools/scan-domain')>();
	return { ...orig, scanDomain: (...args: unknown[]) => mockScanDomain(...args) };
});

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

/**
 * The FOURTH state, distinct from all three above: a total DoH/network outage
 * where every attempted check errors out (`checkStatus: 'error'`, the
 * `buildDnsErrorResult`/`safeCheck` shape) — as opposed to `nonResolvingScan`'s
 * NXDOMAIN/broken-zone shape, where NO CheckResult exists at all. `isMeasured`
 * (`checks.length > 0`) could not tell "19 healthy checks" apart from "19
 * checks that all timed out" — both are truthy — so this shape previously
 * slipped through as `assessed: true`.
 */
async function allTransientScan(domain: string) {
	const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
	const { buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');

	const checks: CheckResult[] = SCAN_CATEGORIES.map((c) => ({
		...buildCheckResult(c, [createFinding(c, `${c} check error`, 'high', 'Check failed: DNS query failed')]),
		score: 0,
		passed: false,
		checkStatus: 'error' as const,
		partial: true,
	}));

	return {
		domain,
		score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'transient outage' },
		checks,
		maturity: { stage: 0, label: 'Unknown', description: 'x', nextStep: 'y' },
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
 * Task 6b: a total outage — every attempted check errors out — previously
 * read `assessed: isMeasured(scanResult.checks)` as `true` (checks.length >
 * 0), so each transient check's own "check error" finding (severity `high`)
 * flowed straight into `actionableFindings` and rendered as a bogus
 * remediation action — confident output manufactured from zero completed
 * evidence. `hasCompletedEvidence` must read this the same way as zero
 * checks, with DISTINCT caveat wording ("no checks ran" would be false when N
 * checks DID run).
 */
describe('generateFixPlan — producer wiring for a total outage (all checks attempted, none completed)', () => {
	it('marks the plan unassessed, emits zero actions, and abstains on the maturity stage', async () => {
		const scan = await allTransientScan('total-outage.example');
		// Non-vacuity guard: prove check data actually existed (unlike the
		// zero-check case above) before asserting on it.
		expect(scan.checks.length).toBeGreaterThan(10);
		mockScanDomain.mockResolvedValue(scan);

		const { generateFixPlan, buildAllTransientFixPlanCaveat, UNASSESSED_FIX_PLAN_CAVEAT } = await import('../src/tools/generate-fix-plan');
		const plan = await generateFixPlan('total-outage.example');

		expect(plan.assessed).toBe(false);
		// Pre-fix this was 19 — one bogus "Fix X: X check error" action per
		// transient category, none of them a real remediation item.
		expect(plan.totalActions).toBe(0);
		expect(plan.actions).toEqual([]);
		expect(plan.maturityStage).toBeNull();
		expect(plan.score).toBeNull();
		expect(plan.grade).toBeNull();
		expect(plan.caveat).toBe(buildAllTransientFixPlanCaveat(scan.checks.length));
		// Distinct from the genuine no-evidence wording — "no checks ran" would
		// be false here, since `scan.checks.length` checks DID run.
		expect(plan.caveat).not.toBe(UNASSESSED_FIX_PLAN_CAVEAT);
		expect(plan.caveat).toMatch(/attempted/i);
		expect(plan.caveat!.toLowerCase()).not.toContain('no checks ran');
	});

	it('does not repeat the caveat wording of the genuine no-evidence case (discriminator)', async () => {
		const { generateFixPlan, UNASSESSED_FIX_PLAN_CAVEAT } = await import('../src/tools/generate-fix-plan');

		mockScanDomain.mockResolvedValue(nonResolvingScan('never-measured-again.example'));
		const neverRan = await generateFixPlan('never-measured-again.example');
		expect(neverRan.caveat).toBe(UNASSESSED_FIX_PLAN_CAVEAT);

		mockScanDomain.mockResolvedValue(await allTransientScan('total-outage-2.example'));
		const allTransient = await generateFixPlan('total-outage-2.example');
		expect(allTransient.caveat).not.toBe(UNASSESSED_FIX_PLAN_CAVEAT);
		expect(allTransient.caveat).not.toBe(neverRan.caveat);
	});

	it('surfaces only completed-check actions when at least one check completed (per-finding transient filter)', async () => {
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
		const { buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');

		// 1 of N checks completed (dmarc genuinely fails); the rest are
		// transient. This must produce exactly the one real remediation
		// action — `hasCompletedEvidence` must not require EVERY check to
		// complete before the plan is treated as assessed, AND the transient
		// checks' own "check error" findings must not be dressed up as
		// remediation actions. Before the per-finding filter, this scan
		// produced `checks.length` actions — one bogus "Fix X: X check error"
		// per transient category alongside the single real one.
		const checks: CheckResult[] = SCAN_CATEGORIES.map((c) => {
			if (c === 'dmarc') {
				return {
					...buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy is p=none', 'high', 'p=none')]),
					score: 40,
					passed: false,
				};
			}
			return {
				...buildCheckResult(c, [createFinding(c, `${c} check error`, 'high', 'Check failed: DNS query failed')]),
				score: 0,
				passed: false,
				checkStatus: 'error' as const,
				partial: true,
			};
		});
		expect(checks.length).toBeGreaterThan(10);

		mockScanDomain.mockResolvedValue({
			domain: 'partial-outage.example',
			score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'partial outage' },
			checks,
			maturity: { stage: 0, label: 'Unknown', description: 'x', nextStep: 'y' },
			resolves: true,
		});

		const { generateFixPlan } = await import('../src/tools/generate-fix-plan');
		const plan = await generateFixPlan('partial-outage.example');

		// One check completed, so the plan IS assessed (no over-abstain) …
		expect(plan.assessed).toBe(true);
		expect(plan.caveat).toBeNull();
		// … but the plan contains ONLY the completed check's real action. The
		// transient checks' findings are a measurement failure, not remediation
		// items — the governing invariant, applied per finding.
		expect(plan.totalActions).toBe(1);
		expect(plan.actions).toHaveLength(1);
		expect(plan.actions[0].category).toBe('dmarc');
		expect(plan.actions[0].findingTitle).toBe('DMARC policy is p=none');
		expect(plan.actions.some((a) => /check error/i.test(a.findingTitle))).toBe(false);
	});

	it('never suppresses a real finding from a completed check that sits NEXT TO transient ones (invariant mirror)', async () => {
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
		const { buildCheckResult, createFinding } = await import('@blackveil/dns-checks/scoring');

		// Two completed checks with real findings (one failing, one passing-with-
		// warning), the rest transient. Both real findings must survive the
		// transient filter — "a real measurement must never be suppressed".
		const checks: CheckResult[] = SCAN_CATEGORIES.map((c) => {
			if (c === 'dmarc') {
				return {
					...buildCheckResult('dmarc', [createFinding('dmarc', 'DMARC policy is p=none', 'high', 'p=none')]),
					score: 40,
					passed: false,
				};
			}
			if (c === 'spf') {
				return {
					...buildCheckResult('spf', [createFinding('spf', 'SPF uses ~all (softfail)', 'medium', 'softfail')]),
					score: 70,
					passed: true,
				};
			}
			return {
				...buildCheckResult(c, [createFinding(c, `${c} check error`, 'high', 'Check failed: DNS query failed')]),
				score: 0,
				passed: false,
				checkStatus: 'error' as const,
				partial: true,
			};
		});

		mockScanDomain.mockResolvedValue({
			domain: 'partial-outage-2.example',
			score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'partial outage' },
			checks,
			maturity: { stage: 0, label: 'Unknown', description: 'x', nextStep: 'y' },
			resolves: true,
		});

		const { generateFixPlan } = await import('../src/tools/generate-fix-plan');
		const plan = await generateFixPlan('partial-outage-2.example');

		expect(plan.totalActions).toBe(2);
		expect(plan.actions.map((a) => a.findingTitle).sort()).toEqual(['DMARC policy is p=none', 'SPF uses ~all (softfail)']);
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
