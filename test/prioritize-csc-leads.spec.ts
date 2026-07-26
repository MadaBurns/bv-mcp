// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import type { Bucket } from '../src/lib/brand-classification';
import type { CscProductKey, CscPriority, CscProductReport, CscProductRecommendation } from '../src/tools/map-csc-products';
import type { CheckResult } from '../src/lib/scoring';
import { bucketFromClassification, computeGapSeverity, computePortfolioGrade, rankCscLeads, formatCscLeads, extractDiscoveredCandidates } from '../src/tools/prioritize-csc-leads';
import type { OwnershipBucket, CscLeadEntry } from '../src/tools/prioritize-csc-leads';
import { UNGRADED_DISPLAY } from '../src/lib/ungraded-display';

const PRODUCT_ORDER: CscProductKey[] = ['csc_multilock', 'managed_dmarc', 'digital_certificates', 'dnssec_management'];

/** Build one recommendation. productName is cosmetic for these pure tests. */
function rec(product: CscProductKey, recommended: boolean, priority: CscPriority): CscProductRecommendation {
	return { product, productName: product, recommended, priority, justifyingGap: '', relatedFindings: [] };
}

/** Build a CscProductReport with all 4 recommendations in fixed order; missing ones default to not-recommended/none. */
function makeReport(domain: string, score: number | null, grade: string | null, recs: CscProductRecommendation[]): CscProductReport {
	const byKey = new Map(recs.map((r) => [r.product, r]));
	const recommendations = PRODUCT_ORDER.map((k) => byKey.get(k) ?? rec(k, false, 'none'));
	return {
		domain,
		score,
		grade,
		// These hand-built fixtures all stand for domains whose checks RAN — the
		// recommendations are given explicitly. The nothing-ran case is built by the
		// real producer (`evaluateCscProducts([], …)`) in the describes below,
		// because only the producer manufactures the "recommended because
		// unobserved" shape that defect lives in.
		assessed: true,
		lockPosture: null,
		recommendations,
		recommendedCount: recommendations.filter((r) => r.recommended).length,
	};
}

describe('bucketFromClassification', () => {
	it('maps each classifyCandidate Bucket to the same-named OwnershipBucket', () => {
		const cases: Array<[Bucket, OwnershipBucket]> = [
			['consolidated', 'consolidated'],
			['shadowIt', 'shadowIt'],
			['indeterminate', 'indeterminate'],
			['impersonation', 'impersonation'],
			['impersonationSurface', 'impersonationSurface'],
		];
		for (const [input, expected] of cases) {
			expect(bucketFromClassification(input)).toBe(expected);
		}
	});
});

describe('computeGapSeverity', () => {
	it('all-clean report (recommendedCount 0) + any bucket → 0', () => {
		const report = makeReport('clean.com', 98, 'A+', []);
		expect(computeGapSeverity(report, 'consolidated')).toBe(0);
		expect(computeGapSeverity(report, 'impersonation')).toBe(0);
	});

	it('MultiLock high only (4×3=12), bucket consolidated (×1.0) → 12', () => {
		const report = makeReport('a.com', 90, 'A', [rec('csc_multilock', true, 'high')]);
		expect(computeGapSeverity(report, 'consolidated')).toBe(12);
	});

	it('same report, bucket impersonation (×0.3) → round(3.6) = 4', () => {
		const report = makeReport('a.com', 90, 'A', [rec('csc_multilock', true, 'high')]);
		expect(computeGapSeverity(report, 'impersonation')).toBe(4);
	});

	it('multiple recommendations sum: MultiLock high(12) + DMARC medium(6) + DNSSEC low(2), bucket unknown → 20', () => {
		const report = makeReport('a.com', 50, 'F', [
			rec('csc_multilock', true, 'high'),
			rec('managed_dmarc', true, 'medium'),
			rec('dnssec_management', true, 'low'),
		]);
		expect(computeGapSeverity(report, 'unknown')).toBe(20);
	});

	it('bucket unknown multiplier is 1.0 (bare-list path not penalized)', () => {
		const report = makeReport('a.com', 50, 'F', [rec('csc_multilock', true, 'high')]);
		expect(computeGapSeverity(report, 'unknown')).toBe(12);
	});
});

/** Build a lead entry: a report (with the given recommendations) + an ownership bucket. */
function entry(
	domain: string,
	score: number | null,
	grade: string | null,
	recs: CscProductRecommendation[],
	bucket: OwnershipBucket,
): CscLeadEntry {
	return { report: makeReport(domain, score, grade, recs), ownershipBucket: bucket };
}

describe('rankCscLeads — ordering and ranks', () => {
	it('orders by gapSeverity descending; priorityRank is 1-based', () => {
		// sev 12 (multilock high), 4 (multilock high × impersonation 0.3), 20 (multilock high + dmarc medium + dnssec low)
		const e12 = entry('twelve.com', 80, 'B', [rec('csc_multilock', true, 'high')], 'unknown');
		const e4 = entry('four.com', 80, 'B', [rec('csc_multilock', true, 'high')], 'impersonation');
		const e20 = entry('twenty.com', 80, 'B', [rec('csc_multilock', true, 'high'), rec('managed_dmarc', true, 'medium'), rec('dnssec_management', true, 'low')], 'unknown');
		const report = rankCscLeads([e12, e4, e20]);
		expect(report.rankedLeads.map((l) => l.domain)).toEqual(['twenty.com', 'twelve.com', 'four.com']);
		expect(report.rankedLeads.map((l) => l.priorityRank)).toEqual([1, 2, 3]);
		expect(report.rankedLeads[0].gapSeverity).toBe(20);
	});

	it('tie on gapSeverity → lower score ranks first', () => {
		const a = entry('a.com', 70, 'C', [rec('csc_multilock', true, 'high')], 'unknown'); // sev 12, score 70
		const b = entry('b.com', 40, 'F', [rec('csc_multilock', true, 'high')], 'unknown'); // sev 12, score 40
		const report = rankCscLeads([a, b]);
		expect(report.rankedLeads.map((l) => l.domain)).toEqual(['b.com', 'a.com']);
	});

	it('tie on gapSeverity AND score → domain ascending (lexical total order)', () => {
		const b = entry('b.com', 50, 'F', [rec('csc_multilock', true, 'high')], 'unknown');
		const a = entry('a.com', 50, 'F', [rec('csc_multilock', true, 'high')], 'unknown');
		const report = rankCscLeads([b, a]);
		expect(report.rankedLeads.map((l) => l.domain)).toEqual(['a.com', 'b.com']);
	});
});

describe('rankCscLeads — per-lead fields', () => {
	it('recommendedCscProducts = recommended keys in fixed product order; recommendedCount matches', () => {
		const e = entry('x.com', 60, 'D', [rec('csc_multilock', true, 'high'), rec('digital_certificates', true, 'medium')], 'consolidated');
		const lead = rankCscLeads([e]).rankedLeads[0];
		expect(lead.recommendedCscProducts).toEqual(['csc_multilock', 'digital_certificates']);
		expect(lead.recommendedCount).toBe(2);
	});

	it('topPriority = max priority among recommended; none when nothing recommended', () => {
		const hi = entry('hi.com', 60, 'D', [rec('csc_multilock', true, 'medium'), rec('managed_dmarc', true, 'high')], 'unknown');
		expect(rankCscLeads([hi]).rankedLeads[0].topPriority).toBe('high');
		const clean = entry('clean.com', 98, 'A+', [], 'unknown');
		expect(rankCscLeads([clean]).rankedLeads[0].topPriority).toBe('none');
	});

	it('pass-through: domain/score/grade/ownershipBucket copied verbatim; a null grade is preserved', () => {
		const e = entry('p.com', null, null, [rec('csc_multilock', true, 'high')], 'shadowIt');
		const lead = rankCscLeads([e]).rankedLeads[0];
		expect(lead.domain).toBe('p.com');
		expect(lead.score).toBeNull();
		expect(lead.grade).toBeNull();
		expect(lead.ownershipBucket).toBe('shadowIt');
	});
});

describe('rankCscLeads — summary', () => {
	it('byProduct counts domains needing each product; totalRecommendations = Σ recommendedCount; hotLeads counts gapSeverity >= 6', () => {
		const e1 = entry('one.com', 50, 'F', [rec('csc_multilock', true, 'high'), rec('managed_dmarc', true, 'medium')], 'unknown'); // sev 18, recs 2
		const e2 = entry('two.com', 90, 'A', [rec('managed_dmarc', true, 'low')], 'unknown'); // sev 3, recs 1
		const report = rankCscLeads([e1, e2]);
		expect(report.summary.byProduct).toEqual({ csc_multilock: 1, managed_dmarc: 2, digital_certificates: 0, dnssec_management: 0 });
		expect(report.summary.totalRecommendations).toBe(3);
		expect(report.summary.hotLeads).toBe(1); // only one.com (18) clears 6; two.com (3) does not
	});

	it('skipped passed through; totalDomains counts only ranked leads, not skipped', () => {
		const e = entry('ok.com', 50, 'F', [rec('csc_multilock', true, 'high')], 'unknown');
		const report = rankCscLeads([e], null, [{ domain: 'bad.com', reason: 'invalid_domain' }]);
		expect(report.summary.skipped).toEqual([{ domain: 'bad.com', reason: 'invalid_domain' }]);
		expect(report.totalDomains).toBe(1);
		expect(report.rankedLeads).toHaveLength(1);
	});

	it('empty input → rankedLeads [], summary zeroes, no throw', () => {
		const report = rankCscLeads([]);
		expect(report.rankedLeads).toEqual([]);
		expect(report.totalDomains).toBe(0);
		expect(report.summary.totalRecommendations).toBe(0);
		expect(report.summary.hotLeads).toBe(0);
		expect(report.summary.byProduct).toEqual({ csc_multilock: 0, managed_dmarc: 0, digital_certificates: 0, dnssec_management: 0 });
		expect(report.summary.skipped).toEqual([]);
	});

	it('brand pass-through: report.brand set when provided, null otherwise', () => {
		const e = entry('z.com', 50, 'F', [], 'unknown');
		expect(rankCscLeads([e], 'acme').brand).toBe('acme');
		expect(rankCscLeads([e]).brand).toBeNull();
	});
});

/** Build a minimal lead-shaped object for the pure portfolio-grade helper (score + bucket + grade). */
function pl(
	bucket: OwnershipBucket,
	score: number | null,
	grade: string | null = 'B',
): Pick<CscLeadEntry['report'], 'score' | 'grade'> & { ownershipBucket: OwnershipBucket } {
	return { score, grade, ownershipBucket: bucket };
}

describe('computePortfolioGrade', () => {
	it('consolidated-heavy weighting pulls harder than a flat average', () => {
		// weighted (2*90 + 1*60)/3 = 240/3 = 80 → B (flat avg 75 would be C)
		expect(computePortfolioGrade([pl('consolidated', 90), pl('shadowIt', 60)])).toEqual({ grade: 'B', weightedScore: 80, contributingDomains: 2 });
	});

	it('impersonation buckets are excluded (weight 0) and do not drag the grade down', () => {
		// only the consolidated 90 counts → 180/2 = 90 → A
		expect(computePortfolioGrade([pl('consolidated', 90), pl('impersonation', 10), pl('impersonationSurface', 0)])).toEqual({
			grade: 'A',
			weightedScore: 90,
			contributingDomains: 1,
		});
	});

	it('all-excluded (only impersonation/impersonationSurface) → null', () => {
		expect(computePortfolioGrade([pl('impersonation', 30), pl('impersonationSurface', 20)])).toBeNull();
	});

	it('zero domains → null', () => {
		expect(computePortfolioGrade([])).toBeNull();
	});

	it('single contributing domain', () => {
		expect(computePortfolioGrade([pl('unknown', 72)])).toEqual({ grade: 'C', weightedScore: 72, contributingDomains: 1 });
	});

	it('mixed buckets exact numeric check', () => {
		// numerator 2*100 + 80 + 60 + 40 = 380, denom 5 → 76 → C; impersonation 0 excluded
		expect(
			computePortfolioGrade([pl('consolidated', 100), pl('shadowIt', 80), pl('indeterminate', 60), pl('unknown', 40), pl('impersonation', 0)]),
		).toEqual({ grade: 'C', weightedScore: 76, contributingDomains: 4 });
	});

	it('letter comes from the weighted numeric score, not an average of per-domain letters', () => {
		// (2*96 + 60)/3 = 252/3 = 84 → B (letter-average of A+ and D is meaningless)
		expect(computePortfolioGrade([pl('consolidated', 96, 'A+'), pl('shadowIt', 60, 'D')])).toEqual({ grade: 'B', weightedScore: 84, contributingDomains: 2 });
	});

	it('does NOT reuse OWNERSHIP_MULTIPLIER (indeterminate rolls up at weight 1, not 0.6)', () => {
		// rollup (2*90 + 1*60)/3 = 80 → B. OWNERSHIP_MULTIPLIER would give (1.0*90+0.6*60)/1.6 = 78.75 → 79 → C.
		expect(computePortfolioGrade([pl('consolidated', 90), pl('indeterminate', 60)])).toEqual({ grade: 'B', weightedScore: 80, contributingDomains: 2 });
	});

	it('rounding is applied once and the letter derives from the rounded integer', () => {
		// (2*95 + 96)/3 = 286/3 = 95.33 → round 95 → A+
		expect(computePortfolioGrade([pl('consolidated', 95), pl('shadowIt', 96)])).toEqual({ grade: 'A+', weightedScore: 95, contributingDomains: 2 });
		// (2*90 + 91)/3 = 271/3 = 90.33 → round 90 → A
		expect(computePortfolioGrade([pl('consolidated', 90), pl('unknown', 91)])).toEqual({ grade: 'A', weightedScore: 90, contributingDomains: 2 });
	});

	it('excludes ungraded leads (NXDOMAIN / broken) from the rollup entirely', () => {
		// ungraded unknown lead skipped: (2*95 + 2*90)/4 = 370/4 = 92.5 → round 93 → A, contributing 2 (not 3)
		const withNa = computePortfolioGrade([pl('consolidated', 95, 'A+'), pl('consolidated', 90, 'A'), pl('unknown', null, null)]);
		const withoutNa = computePortfolioGrade([pl('consolidated', 95, 'A+'), pl('consolidated', 90, 'A')]);
		expect(withNa).toEqual({ grade: 'A', weightedScore: 93, contributingDomains: 2 });
		expect(withNa).toEqual(withoutNa);
	});
});

describe('rankCscLeads — portfolioGrade field', () => {
	it('sets portfolioGrade equal to computePortfolioGrade(rankedLeads)', () => {
		const e1 = entry('one.com', 90, 'A', [rec('csc_multilock', true, 'high')], 'consolidated');
		const e2 = entry('two.com', 60, 'D', [rec('managed_dmarc', true, 'medium')], 'shadowIt');
		const report = rankCscLeads([e1, e2]);
		expect(report.portfolioGrade).toEqual(computePortfolioGrade(report.rankedLeads));
		expect(report.portfolioGrade).toEqual({ grade: 'B', weightedScore: 80, contributingDomains: 2 });
	});

	it('empty input → portfolioGrade null', () => {
		expect(rankCscLeads([]).portfolioGrade).toBeNull();
		expect(rankCscLeads([], 'acme', []).portfolioGrade).toBeNull();
	});

	it('only impersonation buckets → portfolioGrade null', () => {
		const e = entry('imp.com', 20, 'F', [rec('csc_multilock', true, 'high')], 'impersonation');
		expect(rankCscLeads([e]).portfolioGrade).toBeNull();
	});
});

describe('formatCscLeads — portfolio grade line', () => {
	it('full output renders the portfolio grade line when present', () => {
		const report = rankCscLeads([entry('one.com', 90, 'A', [], 'consolidated'), entry('two.com', 60, 'D', [], 'shadowIt')], 'acme');
		const out = formatCscLeads(report, 'full');
		expect(out).toContain('Portfolio grade: B');
		expect(out).toContain('weighted 80/100');
		expect(out).toContain('2 domain(s)');
	});

	it('full output renders the shared ungraded token on the portfolio line when there are no gradeable domains', () => {
		const report = rankCscLeads([], 'acme');
		const out = formatCscLeads(report, 'full');
		// Was 'Portfolio grade: N/A'. One prioritize_csc_leads output could carry THREE
		// vocabularies for the same state — a lead line saying `null/100 (null)`, this
		// portfolio line saying N/A, and the scan surfaces saying 'not measured'. The
		// assertion is unchanged in intent: the line still names the ungraded state and
		// still explains why; it now uses the one token every other surface uses.
		expect(out).toContain(`Portfolio grade: ${UNGRADED_DISPLAY}`);
		expect(out).toContain('no gradeable domains');
		expect(out).not.toContain('N/A');
	});

	it('compact output appends a portfolio segment when present', () => {
		const report = rankCscLeads([entry('one.com', 90, 'A', [], 'consolidated'), entry('two.com', 60, 'D', [], 'shadowIt')], 'acme');
		const compact = formatCscLeads(report, 'compact');
		expect(compact).toContain('portfolio B (80)');
	});

	it('compact output omits the portfolio segment entirely when null', () => {
		const report = rankCscLeads([], 'acme');
		const compact = formatCscLeads(report, 'compact');
		expect(compact.toLowerCase()).not.toContain('portfolio');
	});
});

describe('formatCscLeads', () => {
	function sampleReport() {
		const hot = entry('hot.com', 40, 'F', [rec('csc_multilock', true, 'high'), rec('managed_dmarc', true, 'high')], 'consolidated');
		const cold = entry('cold.com', 95, 'A+', [], 'unknown');
		return rankCscLeads([hot, cold], 'acme');
	}

	it('full output lists leads in rank order with domain, score/grade, products and a summary block', () => {
		const out = formatCscLeads(sampleReport(), 'full');
		expect(out).toContain('acme');
		expect(out).toContain('hot.com');
		expect(out).toContain('cold.com');
		expect(out).toContain('40/100');
		expect(out).toContain('csc_multilock');
		// rank order: hot.com (rank 1) appears before cold.com
		expect(out.indexOf('hot.com')).toBeLessThan(out.indexOf('cold.com'));
		// a summary rollup is present
		expect(out.toLowerCase()).toContain('summary');
	});

	it('compact output is shorter than full and still names the top lead', () => {
		const report = sampleReport();
		const full = formatCscLeads(report, 'full');
		const compact = formatCscLeads(report, 'compact');
		expect(compact.length).toBeLessThan(full.length);
		expect(compact).toContain('hot.com');
	});

	it('renders "not measured" for an ungraded lead and excludes it from the portfolio rollup', async () => {
		const { rankCscLeads: rank, formatCscLeads: fmt } = await import('../src/tools/prioritize-csc-leads');
		const report = rank([entry('graded.com', 90, 'A', [], 'consolidated'), entry('ungraded.com', null, null, [], 'consolidated')]);

		const ungradedLead = report.rankedLeads.filter((l) => l.domain === 'ungraded.com');
		// Non-empty guard — without it the assertions below never execute.
		expect(ungradedLead).toHaveLength(1);
		expect(ungradedLead[0].grade).toBeNull();

		expect(report.portfolioGrade).not.toBeNull();
		// The ungraded domain is dropped from the weighted average, not averaged as 0.
		expect(report.portfolioGrade!.contributingDomains).toBe(1);
		expect(report.portfolioGrade!.weightedScore).toBe(90);

		const text = fmt(report, 'full');
		expect(text).toContain(UNGRADED_DISPLAY);
		expect(text).not.toContain('null/100');
		// Control — the graded lead still carries its real score in the same output.
		expect(text).toContain('90/100 (A)');
	});

	it('still calls a graded lead with no gaps "posture clean" (control)', async () => {
		const { rankCscLeads: rank, formatCscLeads: fmt } = await import('../src/tools/prioritize-csc-leads');
		const text = fmt(rank([entry('clean.com', 95, 'A+', [], 'consolidated')]), 'full');
		expect(text).toContain('posture clean');
	});
});

/**
 * A never-measured domain was ranked as the #1 HOT lead.
 *
 * `evaluateCscProducts([], null, …)` — the real producer for a domain that does
 * not resolve — marks all three scan-driven products `recommended: true,
 * priority: 'low'` on the strength of having observed nothing ("DMARC not
 * observed", …). That is gapValue 3+2+2 = 7, and `consolidated` multiplies by
 * 1.0, so gapSeverity 7 — above HOT_LEAD_THRESHOLD (6). `gapSeverity` is the
 * FIRST sort key (the score tiebreak is second and never gets a say), so the
 * unmeasured domain outranks a real domain with a genuinely failing DMARC
 * policy, and is counted in `hotLeads`. Nothing on the wire let a dashboard
 * gate on it.
 *
 * Every fixture below is built by the REAL producers — `evaluateCscProducts`
 * over real CheckResults — because a hand-built lead shape cannot reach this
 * defect: it is the producer's own "recommended because unobserved" output that
 * manufactures the severity.
 */
/** The exact producer output for a domain that does not resolve: no checks, no score. */
async function ungradedReport(domain: string) {
	const { evaluateCscProducts } = await import('../src/tools/map-csc-products');
	return evaluateCscProducts([], null, domain, null, null);
}

/**
 * A measured domain with ONE medium DMARC failure → managed_dmarc recommended
 * `medium` → gapValue 3x2 = 6, gapSeverity 6. Deliberately BELOW the 7 an
 * unmeasured domain used to manufacture, so the ordering assertion has teeth.
 */
async function gradedReport(domain: string) {
	const { evaluateCscProducts } = await import('../src/tools/map-csc-products');
	const checks = [
		{
			category: 'dmarc',
			passed: false,
			score: 40,
			findings: [{ category: 'dmarc', title: 'DMARC policy is p=none', severity: 'medium', detail: '' }],
		},
		{ category: 'ssl', passed: true, score: 100, findings: [] },
		{ category: 'dnssec', passed: true, score: 100, findings: [] },
	] as unknown as CheckResult[];
	const locked = { level: 'registry-lock', registryLevel: true, transferLocked: true } as never;
	return evaluateCscProducts(checks, locked, domain, 73, 'C+');
}

async function mixedPortfolio() {
	const { rankCscLeads: rank } = await import('../src/tools/prioritize-csc-leads');
	return rank([
		{ report: await ungradedReport('never-measured.example'), ownershipBucket: 'consolidated' },
		{ report: await gradedReport('measured.example'), ownershipBucket: 'consolidated' },
	]);
}

describe('rankCscLeads — a never-measured domain must not outrank a measured one', () => {

	it('assigns the unmeasured domain NO gap severity, so it cannot outrank a measured one', async () => {
		const report = await mixedPortfolio();

		// Fixture-reachability guard: the producer really does recommend three
		// products purely from non-observation. Without this the test could pass
		// against a producer that returned nothing and never reached the defect.
		const ungradedInput = await ungradedReport('never-measured.example');
		expect(ungradedInput.recommendedCount).toBe(3);

		const byDomain = new Map(report.rankedLeads.map((l) => [l.domain, l]));
		expect(byDomain.get('never-measured.example')!.gapSeverity).toBeNull();
		expect(byDomain.get('never-measured.example')!.graded).toBe(false);
		// The measured domain keeps its real, lower severity — and now ranks first.
		expect(byDomain.get('measured.example')!.gapSeverity).toBe(6);
		expect(report.rankedLeads.map((l) => l.domain)).toEqual(['measured.example', 'never-measured.example']);
		expect(report.rankedLeads.map((l) => l.priorityRank)).toEqual([1, 2]);
	});

	it('excludes the unmeasured domain from the hot-lead count and the sales rollups', async () => {
		const report = await mixedPortfolio();

		// Was 2 — the unmeasured domain counted as hot at severity 7.
		expect(report.summary.hotLeads).toBe(1);
		// Only the measured domain's single real recommendation is rolled up.
		expect(report.summary.totalRecommendations).toBe(1);
		expect(report.summary.byProduct.managed_dmarc).toBe(1);
		expect(report.summary.byProduct.digital_certificates).toBe(0);
		expect(report.summary.byProduct.dnssec_management).toBe(0);
		expect(report.summary.unassessedDomains).toBe(1);
		// The measured lead scored, so nothing is merely unscored here.
		expect(report.summary.unscoredDomains).toBe(0);
	});

	it('carries the qualifier on the wire so a dashboard can gate on it', async () => {
		const { formatCscLeads: fmt } = await import('../src/tools/prioritize-csc-leads');
		const { buildToolResult } = await import('../src/handlers/tool-formatters');
		const report = await mixedPortfolio();
		const result = buildToolResult(fmt(report, 'full'), report, 'full');

		const wire = JSON.stringify(result.structuredContent);
		// Both flags, each meaning its own thing: nothing ran AND nothing scored.
		expect(wire).toContain('"assessed":false');
		expect(wire).toContain('"graded":false');
		expect(wire).toContain('"gapSeverity":null');
		expect(wire).toContain('"unassessedDomains":1');
		// True of THIS fixture — `evaluateCscProducts([], …)` really did run no checks.
		expect(report.caveat).toMatch(/no checks ran/i);

		const comment = result.content.map((c) => c.text).find((t) => t.includes('STRUCTURED_RESULT'));
		expect(comment).toBeDefined();
		expect(comment).toContain('"gapSeverity":null');
	});

	it('never presents the unmeasured domain as a severity-bearing lead in the prose', async () => {
		const { formatCscLeads: fmt } = await import('../src/tools/prioritize-csc-leads');
		const report = await mixedPortfolio();

		// Each format is checked against the string IT can actually emit: `full` says
		// "gap severity N", `compact` says "sev N". Asserting both against both would
		// leave one half vacuous in each format.
		const full = fmt(report, 'full');
		expect(full).not.toContain('gap severity 7');
		expect(full).toContain('gap severity 6');
		const compact = fmt(report, 'compact');
		expect(compact).not.toContain('sev 7');
		expect(compact).toContain('sev 6');
		for (const [format, text] of [
			['full', full],
			['compact', compact],
		] as const) {
			expect(text, format).toContain(UNGRADED_DISPLAY);
		}
		// The unmeasured lead must not advertise products recommended purely because
		// nothing was observed — it states why instead. Scoped to that lead's OWN
		// block: the four per-product rollup lines in the Summary always name every
		// product key, so a whole-document search would match them and prove nothing.
		const ungradedBlock = full.split('\n## ').find((b) => b.startsWith('2. never-measured.example'));
		expect(ungradedBlock).toBeDefined();
		expect(ungradedBlock).toMatch(/No checks ran/i);
		expect(ungradedBlock).not.toContain('Recommended CSC products');
		expect(ungradedBlock).not.toContain('digital_certificates');
		expect(ungradedBlock).not.toContain('Top priority');

		// Control — the measured lead's block still carries every sales claim.
		const gradedBlock = full.split('\n## ').find((b) => b.startsWith('1. measured.example'));
		expect(gradedBlock).toContain('Recommended CSC products: managed_dmarc');
		expect(gradedBlock).toContain('Top priority: medium');
	});

	it('leaves an all-measured portfolio completely unchanged (control)', async () => {
		const { rankCscLeads: rank, formatCscLeads: fmt } = await import('../src/tools/prioritize-csc-leads');

		const report = rank([
			{ report: await gradedReport('a.example'), ownershipBucket: 'consolidated' },
			{ report: await gradedReport('b.example'), ownershipBucket: 'consolidated' },
		]);

		// Without this the assertions above would hold under an implementation that
		// nulled every gap severity and rolled nothing up.
		expect(report.rankedLeads.map((l) => l.gapSeverity)).toEqual([6, 6]);
		expect(report.rankedLeads.every((l) => l.graded && l.assessed)).toBe(true);
		expect(report.summary.hotLeads).toBe(2);
		expect(report.summary.totalRecommendations).toBe(2);
		expect(report.summary.unassessedDomains).toBe(0);
		expect(report.summary.unscoredDomains).toBe(0);
		expect(report.caveat).toBeNull();
		expect(fmt(report, 'full')).not.toContain(UNGRADED_DISPLAY);
	});
});

/**
 * The over-abstain mirror, in its most damaging form.
 *
 * `buildUnscoredResult` is the SHIPPED "m5 is not defined" path: every check ran
 * and found real problems, and only the weighted scoring bundle failed. Such a
 * domain is ungraded (`score === null`) but thoroughly MEASURED.
 *
 * Gating the lead's abstention on `graded` — a score-based predicate — while the
 * note asserts "No checks ran for this domain" (a checks-based claim) made the
 * tool state a falsehood AND suppress the evidence: a critical expired
 * certificate, a high missing-DMARC, and DNSSEC not enabled were reported to an
 * MSSP as "no checks ran", with `hotLeads: 0` and `totalRecommendations: 0`.
 *
 * `gapSeverity` is derived from the RECOMMENDATIONS, which are derived from the
 * CHECKS — not from the score. So `isMeasured` is the predicate that makes it
 * true, and it is what now gates it.
 */
describe('rankCscLeads — checks ran but the scan could not be scored', () => {
	/** The buildUnscoredResult shape: real findings, no score. */
	async function unscoredReport(domain: string) {
		const { evaluateCscProducts } = await import('../src/tools/map-csc-products');
		const checks = [
			{
				category: 'ssl',
				passed: false,
				score: 0,
				findings: [{ category: 'ssl', title: 'Certificate expired', severity: 'critical', detail: '' }],
			},
			{
				category: 'dmarc',
				passed: false,
				score: 0,
				findings: [{ category: 'dmarc', title: 'No DMARC record', severity: 'high', detail: '' }],
			},
			{
				category: 'dnssec',
				passed: false,
				score: 40,
				findings: [{ category: 'dnssec', title: 'DNSSEC not enabled', severity: 'medium', detail: '' }],
			},
		] as unknown as CheckResult[];
		return evaluateCscProducts(checks, null, domain, null, null);
	}

	it('does NOT claim that no checks ran', async () => {
		const { rankCscLeads: rank, formatCscLeads: fmt } = await import('../src/tools/prioritize-csc-leads');
		const report = rank([{ report: await unscoredReport('unscored.example'), ownershipBucket: 'consolidated' }]);

		for (const format of ['compact', 'full'] as const) {
			const text = fmt(report, format);
			expect(text, format).not.toMatch(/no checks ran/i);
		}
		expect(report.caveat).not.toMatch(/no checks ran/i);
		// It says what actually happened instead.
		expect(report.caveat).toMatch(/could not be scored/i);
		expect(fmt(report, 'full')).toMatch(/could not be scored/i);
	});

	it('keeps the measured evidence — real severity, real products, counted in the rollups', async () => {
		const { rankCscLeads: rank, formatCscLeads: fmt } = await import('../src/tools/prioritize-csc-leads');
		const input = await unscoredReport('unscored.example');
		// Fixture-reachability guard: the producer really did derive recommendations
		// from the findings, so there is genuine evidence available to suppress.
		expect(input.assessed).toBe(true);
		expect(input.recommendedCount).toBe(3);

		const report = rank([{ report: input, ownershipBucket: 'consolidated' }]);
		const lead = report.rankedLeads[0];

		expect(lead.assessed).toBe(true);
		expect(lead.graded).toBe(false);
		// Was null, and the whole lead was demoted. csc_multilock is not recommended
		// (no RDAP posture), so 3 (dmarc high) + 2 (ssl high) + 2 (dnssec medium)...
		expect(lead.gapSeverity).toBeGreaterThan(0);
		// Was 0 for all three — the critical expired certificate vanished.
		expect(report.summary.totalRecommendations).toBe(3);
		expect(report.summary.byProduct.digital_certificates).toBe(1);
		expect(report.summary.byProduct.managed_dmarc).toBe(1);
		expect(report.summary.hotLeads).toBe(1);
		expect(report.summary.unassessedDomains).toBe(0);
		expect(report.summary.unscoredDomains).toBe(1);

		const full = fmt(report, 'full');
		expect(full).toContain('digital_certificates');
		expect(full).toContain('managed_dmarc');
		expect(full).toContain('Top priority: high');
	});

	it('still withholds the SCORE-derived claims', async () => {
		const { rankCscLeads: rank, formatCscLeads: fmt } = await import('../src/tools/prioritize-csc-leads');
		const report = rank([{ report: await unscoredReport('unscored.example'), ownershipBucket: 'consolidated' }]);

		// No score means no portfolio grade contribution and no score line — the half
		// that genuinely is unknown. Abstention is scoped to what the score supports.
		expect(report.portfolioGrade).toBeNull();
		const full = fmt(report, 'full');
		expect(full).toContain(`Score: ${UNGRADED_DISPLAY}`);
		expect(full).not.toMatch(/Score: \d+\/100/);
	});

	it('ranks an unscored-but-measured lead by its REAL severity, above a lower-severity graded lead', async () => {
		const { rankCscLeads: rank } = await import('../src/tools/prioritize-csc-leads');
		// graded.example has severity 6; the unscored domain has genuine gaps worth
		// more. Under the previous fix it had NO severity and sorted last, burying a
		// critical finding beneath a lesser one.
		const report = rank([
			{ report: await gradedReport('graded.example'), ownershipBucket: 'consolidated' },
			{ report: await unscoredReport('unscored.example'), ownershipBucket: 'consolidated' },
		]);
		expect(report.rankedLeads[0].domain).toBe('unscored.example');
		expect(report.rankedLeads[0].gapSeverity).toBeGreaterThan(6);
	});
});

describe('extractDiscoveredCandidates', () => {
	function candidateResult(): CheckResult {
		return {
			category: 'brand_discovery',
			passed: true,
			score: 100,
			findings: [
				{ category: 'brand_discovery', title: 'Summary', severity: 'info', detail: '', metadata: { surfaced: 2 } },
				{ category: 'brand_discovery', title: 'Brand candidate: owned.com', severity: 'low', detail: '', metadata: { candidate: 'owned.com', bucket: 'consolidated' } },
				{ category: 'brand_discovery', title: 'Brand candidate: typo.com', severity: 'info', detail: '', metadata: { candidate: 'typo.com', bucket: 'impersonation' } },
			],
		} as unknown as CheckResult;
	}

	it('maps candidate findings to {domain, ownershipBucket}; ignores non-candidate findings', () => {
		const out = extractDiscoveredCandidates(candidateResult());
		expect(out).toEqual([
			{ domain: 'owned.com', ownershipBucket: 'consolidated' },
			{ domain: 'typo.com', ownershipBucket: 'impersonation' },
		]);
	});

	it('defaults a candidate with no bucket metadata to indeterminate', () => {
		const result = {
			category: 'brand_discovery',
			passed: true,
			score: 100,
			findings: [{ category: 'brand_discovery', title: 'Brand candidate: x.com', severity: 'info', detail: '', metadata: { candidate: 'x.com' } }],
		} as unknown as CheckResult;
		expect(extractDiscoveredCandidates(result)).toEqual([{ domain: 'x.com', ownershipBucket: 'indeterminate' }]);
	});

	it('returns [] when no finding carries a candidate (async-handoff / failure shape)', () => {
		const result = {
			category: 'brand_discovery',
			passed: false,
			score: 0,
			findings: [{ category: 'brand_discovery', title: 'Brand audit requires async processing', severity: 'info', detail: '', metadata: { asyncHandoff: true } }],
		} as unknown as CheckResult;
		expect(extractDiscoveredCandidates(result)).toEqual([]);
	});
});
