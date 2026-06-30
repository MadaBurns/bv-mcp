// SPDX-License-Identifier: BUSL-1.1

/**
 * CSC sales-lead prioritization tool (portfolio aggregation layer).
 * Aggregates a brand's portfolio (or an operator-supplied domain set) into a
 * ranked sales-lead list, ordered by product-gap value × ownership actionability,
 * reusing Spec B's PURE units (evaluateCscProducts + extractLockPosture) per domain.
 * Emits NO new security finding/severity — gapSeverity/priorityRank are SALES
 * signals, deliberately distinct from a security severity. Paid-gated, multi-domain.
 */

import type { Bucket } from '../lib/brand-classification';
import type { CscProductKey, CscPriority, CscProductReport } from './map-csc-products';

/** Portfolio ownership lens (from classifyCandidate) + 'unknown' for a bare domain list. */
export type OwnershipBucket =
	| 'consolidated'
	| 'shadowIt'
	| 'indeterminate'
	| 'impersonation'
	| 'impersonationSurface'
	| 'unknown';

/** A single ranked sales lead. */
export interface CscLead {
	domain: string;
	score: number;
	grade: string;
	ownershipBucket: OwnershipBucket;
	recommendedCscProducts: CscProductKey[];
	gapSeverity: number;
	priorityRank: number;
	recommendedCount: number;
	topPriority: CscPriority;
}

export interface CscLeadReport {
	brand: string | null;
	totalDomains: number;
	rankedLeads: CscLead[];
	summary: {
		totalRecommendations: number;
		byProduct: Record<CscProductKey, number>;
		hotLeads: number;
		skipped: Array<{ domain: string; reason: string }>;
	};
}

/** A domain to rank, paired with its portfolio ownership lens. */
export interface CscLeadEntry {
	report: CscProductReport;
	ownershipBucket: OwnershipBucket;
}

/** A discovered candidate from the brand path. */
export interface DiscoveredCandidate {
	domain: string;
	ownershipBucket: OwnershipBucket;
}

const CSC_PRODUCT_ORDER: CscProductKey[] = ['csc_multilock', 'managed_dmarc', 'digital_certificates', 'dnssec_management'];

// Product sales value — MultiLock is the flagship anti-hijacking product.
const PRODUCT_VALUE: Record<CscProductKey, number> = {
	csc_multilock: 4,
	managed_dmarc: 3,
	digital_certificates: 2,
	dnssec_management: 2,
};
// Spec B sales priority → weight.
const PRIORITY_WEIGHT: Record<CscPriority, number> = { high: 3, medium: 2, low: 1, none: 0 };
// Ownership actionability — can CSC actually sell THIS domain a lock?
const OWNERSHIP_MULTIPLIER: Record<OwnershipBucket, number> = {
	consolidated: 1.0,
	shadowIt: 1.0,
	unknown: 1.0,
	indeterminate: 0.6,
	impersonation: 0.3,
	impersonationSurface: 0.3,
};
const HOT_LEAD_THRESHOLD = 6; // gapSeverity at/above = "hot"

/** Pure mapper from classifyCandidate's Bucket to OwnershipBucket (identity for the 5 shared values). */
export function bucketFromClassification(b: Bucket): OwnershipBucket {
	return b;
}

/** Σ over recommended products of PRODUCT_VALUE × PRIORITY_WEIGHT. */
function gapValue(report: CscProductReport): number {
	let total = 0;
	for (const r of report.recommendations) {
		if (r.recommended) total += PRODUCT_VALUE[r.product] * PRIORITY_WEIGHT[r.priority];
	}
	return total;
}

/** "Product-gap value × ownership severity", rounded. PURE. */
export function computeGapSeverity(report: CscProductReport, bucket: OwnershipBucket): number {
	return Math.round(gapValue(report) * OWNERSHIP_MULTIPLIER[bucket]);
}
