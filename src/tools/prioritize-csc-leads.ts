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
import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';

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

/** Recommended product keys in fixed product order. */
function recommendedProducts(report: CscProductReport): CscProductKey[] {
	return CSC_PRODUCT_ORDER.filter((k) => report.recommendations.find((r) => r.product === k)?.recommended === true);
}

const PRIORITY_RANK: Record<CscPriority, number> = { high: 3, medium: 2, low: 1, none: 0 };

/** Highest sales priority among the recommended products ('none' when nothing recommended). */
function topPriorityOf(report: CscProductReport): CscPriority {
	let best: CscPriority = 'none';
	for (const r of report.recommendations) {
		if (r.recommended && PRIORITY_RANK[r.priority] > PRIORITY_RANK[best]) best = r.priority;
	}
	return best;
}

/**
 * Rank a set of per-domain CSC product reports into prioritized sales leads (PURE).
 * Sort: gapSeverity desc, then lower score, then domain asc (total order). The
 * heart of Spec C's TDD — no I/O.
 */
export function rankCscLeads(
	entries: CscLeadEntry[],
	brand: string | null = null,
	skipped: Array<{ domain: string; reason: string }> = [],
): CscLeadReport {
	const leads: CscLead[] = entries.map((e) => ({
		domain: e.report.domain,
		score: e.report.score,
		grade: e.report.grade,
		ownershipBucket: e.ownershipBucket,
		recommendedCscProducts: recommendedProducts(e.report),
		gapSeverity: computeGapSeverity(e.report, e.ownershipBucket),
		priorityRank: 0, // assigned after the sort
		recommendedCount: e.report.recommendedCount,
		topPriority: topPriorityOf(e.report),
	}));

	leads.sort((a, b) => b.gapSeverity - a.gapSeverity || a.score - b.score || a.domain.localeCompare(b.domain));
	leads.forEach((lead, i) => {
		lead.priorityRank = i + 1;
	});

	const byProduct: Record<CscProductKey, number> = {
		csc_multilock: 0,
		managed_dmarc: 0,
		digital_certificates: 0,
		dnssec_management: 0,
	};
	for (const lead of leads) {
		for (const key of lead.recommendedCscProducts) byProduct[key] += 1;
	}

	return {
		brand,
		totalDomains: leads.length,
		rankedLeads: leads,
		summary: {
			totalRecommendations: leads.reduce((sum, l) => sum + l.recommendedCount, 0),
			byProduct,
			hotLeads: leads.filter((l) => l.gapSeverity >= HOT_LEAD_THRESHOLD).length,
			skipped,
		},
	};
}

/** Render a ranked CSC lead report for display. */
export function formatCscLeads(report: CscLeadReport, format: OutputFormat = 'full'): string {
	const lines: string[] = [];
	const brandLabel = report.brand ? sanitizeOutputText(report.brand, 253) : 'domain set';

	if (format === 'compact') {
		lines.push(`CSC leads (${brandLabel}): ${report.totalDomains} ranked, ${report.summary.hotLeads} hot`);
		for (const lead of report.rankedLeads) {
			lines.push(
				`${lead.priorityRank}. ${sanitizeOutputText(lead.domain, 253)} — sev ${lead.gapSeverity} — ${lead.score}/100 (${lead.grade}) — ${lead.recommendedCount} product(s)`,
			);
		}
		return lines.join('\n').trimEnd();
	}

	lines.push(`# CSC Sales Leads: ${brandLabel}`);
	lines.push(`**${report.totalDomains}** domain(s) ranked | **${report.summary.hotLeads}** hot lead(s)`);
	lines.push('');
	for (const lead of report.rankedLeads) {
		lines.push(`## ${lead.priorityRank}. ${sanitizeOutputText(lead.domain, 253)} — gap severity ${lead.gapSeverity}`);
		lines.push(`  - Score: ${lead.score}/100 (${lead.grade}) | Ownership: ${lead.ownershipBucket} | Top priority: ${lead.topPriority}`);
		if (lead.recommendedCscProducts.length > 0) {
			lines.push(`  - Recommended CSC products: ${lead.recommendedCscProducts.join(', ')}`);
		} else {
			lines.push('  - No CSC upsell — posture clean');
		}
	}
	lines.push('');
	lines.push('## Summary');
	lines.push(`  - Total recommendations: ${report.summary.totalRecommendations}`);
	for (const key of CSC_PRODUCT_ORDER) {
		lines.push(`  - ${key}: ${report.summary.byProduct[key]} domain(s)`);
	}
	if (report.summary.skipped.length > 0) {
		lines.push(`  - Skipped: ${report.summary.skipped.map((s) => `${sanitizeOutputText(s.domain, 253)} (${sanitizeOutputText(s.reason, 60)})`).join(', ')}`);
	}

	return lines.join('\n').trimEnd();
}
