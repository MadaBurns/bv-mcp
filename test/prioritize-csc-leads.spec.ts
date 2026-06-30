// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import type { Bucket } from '../src/lib/brand-classification';
import type { CscProductKey, CscPriority, CscProductReport, CscProductRecommendation } from '../src/tools/map-csc-products';
import { bucketFromClassification, computeGapSeverity } from '../src/tools/prioritize-csc-leads';
import type { OwnershipBucket } from '../src/tools/prioritize-csc-leads';

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
