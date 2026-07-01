// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import type { Bucket } from '../src/lib/brand-classification';
import type { CscProductKey, CscPriority, CscProductReport, CscProductRecommendation } from '../src/tools/map-csc-products';
import type { CheckResult } from '../src/lib/scoring';
import { bucketFromClassification, computeGapSeverity, computePortfolioGrade, rankCscLeads, formatCscLeads, extractDiscoveredCandidates } from '../src/tools/prioritize-csc-leads';
import type { OwnershipBucket, CscLeadEntry } from '../src/tools/prioritize-csc-leads';

const PRODUCT_ORDER: CscProductKey[] = ['csc_multilock', 'managed_dmarc', 'digital_certificates', 'dnssec_management'];

/** Build one recommendation. productName is cosmetic for these pure tests. */
function rec(product: CscProductKey, recommended: boolean, priority: CscPriority): CscProductRecommendation {
	return { product, productName: product, recommended, priority, justifyingGap: '', relatedFindings: [] };
}

/** Build a CscProductReport with all 4 recommendations in fixed order; missing ones default to not-recommended/none. */
function makeReport(domain: string, score: number, grade: string, recs: CscProductRecommendation[]): CscProductReport {
	const byKey = new Map(recs.map((r) => [r.product, r]));
	const recommendations = PRODUCT_ORDER.map((k) => byKey.get(k) ?? rec(k, false, 'none'));
	return {
		domain,
		score,
		grade,
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
function entry(domain: string, score: number, grade: string, recs: CscProductRecommendation[], bucket: OwnershipBucket): CscLeadEntry {
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

	it('pass-through: domain/score/grade/ownershipBucket copied verbatim; grade "N/A" preserved', () => {
		const e = entry('p.com', 0, 'N/A', [rec('csc_multilock', true, 'high')], 'shadowIt');
		const lead = rankCscLeads([e]).rankedLeads[0];
		expect(lead.domain).toBe('p.com');
		expect(lead.score).toBe(0);
		expect(lead.grade).toBe('N/A');
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
function pl(bucket: OwnershipBucket, score: number, grade = 'B'): Pick<CscLeadEntry['report'], 'score' | 'grade'> & { ownershipBucket: OwnershipBucket } {
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

	it('excludes graceful N/A leads (NXDOMAIN / broken) from the rollup entirely', () => {
		// N/A unknown lead skipped: (2*95 + 2*90)/4 = 370/4 = 92.5 → round 93 → A, contributing 2 (not 3)
		const withNa = computePortfolioGrade([pl('consolidated', 95, 'A+'), pl('consolidated', 90, 'A'), pl('unknown', 0, 'N/A')]);
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

	it('full output renders an N/A portfolio line when there are no gradeable domains', () => {
		const report = rankCscLeads([], 'acme');
		const out = formatCscLeads(report, 'full');
		expect(out).toContain('Portfolio grade: N/A');
		expect(out).toContain('no gradeable domains');
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
