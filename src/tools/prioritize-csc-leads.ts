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
import { evaluateCscProducts, extractLockPosture } from './map-csc-products';
import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';
import type { CheckResult } from '../lib/scoring';
import { scanDomain } from './scan-domain';
import { checkRdapLookup, RDAP_LOOKUP_SYNC_BUDGET_MS } from './check-rdap-lookup';
import { brandAuditSingle } from './brand-audit-single';
import { validateDomain, sanitizeDomain } from '../lib/sanitize';
import type { ScanRuntimeOptions } from './scan/post-processing';

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

const KNOWN_BUCKETS: ReadonlySet<Bucket> = new Set<Bucket>([
	'consolidated',
	'shadowIt',
	'indeterminate',
	'impersonation',
	'impersonationSurface',
]);

/**
 * Extract {domain, ownershipBucket} candidates from a brandAuditSingle CheckResult.
 * The pipeline stamps each candidate finding with metadata.candidate (the domain)
 * and metadata.bucket (a classifier Bucket — brand-audit-pipeline.ts:962-964).
 * A candidate with no/unknown bucket defaults to 'indeterminate' (0.6 multiplier —
 * honest, doesn't over-claim consolidation). Non-candidate findings (summary,
 * async-handoff) are ignored — an async-handoff result yields []. PURE.
 */
export function extractDiscoveredCandidates(result: CheckResult): DiscoveredCandidate[] {
	const out: DiscoveredCandidate[] = [];
	for (const f of result.findings) {
		const meta = (f as { metadata?: Record<string, unknown> }).metadata;
		const candidate = meta?.candidate;
		if (typeof candidate !== 'string' || candidate.length === 0) continue;
		const rawBucket = meta?.bucket;
		const bucket: OwnershipBucket =
			typeof rawBucket === 'string' && KNOWN_BUCKETS.has(rawBucket as Bucket) ? bucketFromClassification(rawBucket as Bucket) : 'indeterminate';
		out.push({ domain: candidate, ownershipBucket: bucket });
	}
	return out;
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

const TOTAL_BUDGET_MS = 25_000; // parity with batch_scan
const SCAN_CONCURRENCY = 3; // scan_domain is already ~16× parallel internally
const LEAD_BUDGET = 10; // max leads ranked (parity with the domains[] cap)

/** runtimeOptions accepted by the orchestrator — ScanRuntimeOptions plus the optional WHOIS binding the RDAP call threads. */
export type CscRuntimeOptions = ScanRuntimeOptions & { whoisBinding?: { fetch: typeof fetch } };

export type DiscoverPortfolioFn = (
	brand: string,
	opts: { kv?: KVNamespace; runtimeOptions?: CscRuntimeOptions; deadlineMs: number },
) => Promise<DiscoveredCandidate[]>;

export interface PrioritizeCscLeadsDeps {
	/** Override the brand portfolio discoverer (default wraps brandAuditSingle). */
	discoverPortfolio?: DiscoverPortfolioFn;
}

export interface PrioritizeCscLeadsArgsShape {
	domains?: string[];
	brand?: string;
	force_refresh?: boolean;
}

/** Buckets CSC can actually sell a lock — preferred when truncating to LEAD_BUDGET. */
const SELLABLE_BUCKETS: ReadonlySet<OwnershipBucket> = new Set<OwnershipBucket>(['consolidated', 'shadowIt']);

/** Default brand discoverer — runs a bounded brand audit, then extracts candidates+buckets. */
const defaultDiscoverPortfolio: DiscoverPortfolioFn = async (brand, opts) => {
	const result = await brandAuditSingle(
		brand,
		{ timeoutBehavior: 'async_handoff', deadlineMs: opts.deadlineMs, kv: opts.kv, ...opts.runtimeOptions } as never,
		{},
	);
	return extractDiscoveredCandidates(result);
};

/** Evaluate one domain → a CscLeadEntry (scan + RDAP + Spec B pure evaluation). */
async function evaluateOne(domain: string, ownershipBucket: OwnershipBucket, kv: KVNamespace | undefined, runtimeOptions: CscRuntimeOptions | undefined): Promise<CscLeadEntry> {
	const scanResult = await scanDomain(domain, kv, runtimeOptions);
	const rdap = await checkRdapLookup(domain, {
		whoisBinding: runtimeOptions?.whoisBinding,
		signal: AbortSignal.timeout(RDAP_LOOKUP_SYNC_BUDGET_MS),
		deadlineMs: Date.now() + RDAP_LOOKUP_SYNC_BUDGET_MS,
	});
	const lockPosture = extractLockPosture(rdap);
	const report = evaluateCscProducts(scanResult.checks, lockPosture, domain, scanResult.score.overall, scanResult.score.grade);
	return { report, ownershipBucket };
}

/**
 * Prioritize CSC sales leads across a domain set or a brand portfolio (orchestrator — impure).
 * Per-domain isolation + a wall-clock budget (batch_scan pattern): one bad domain
 * lands in summary.skipped and never sinks the batch. NEVER throws a non-allowlisted error.
 */
export async function prioritizeCscLeads(
	args: PrioritizeCscLeadsArgsShape,
	kv?: KVNamespace,
	runtimeOptions?: CscRuntimeOptions,
	deps: PrioritizeCscLeadsDeps = {},
): Promise<CscLeadReport> {
	const deadline = Date.now() + TOTAL_BUDGET_MS;
	const skipped: Array<{ domain: string; reason: string }> = [];
	let brand: string | null = null;

	// 1. Resolve the work set.
	let work: Array<{ domain: string; ownershipBucket: OwnershipBucket }> = [];
	if (args.brand != null) {
		brand = args.brand;
		const discover = deps.discoverPortfolio ?? defaultDiscoverPortfolio;
		let candidates: DiscoveredCandidate[] = [];
		try {
			candidates = await discover(args.brand, { kv, runtimeOptions, deadlineMs: deadline });
		} catch {
			candidates = [];
		}
		if (candidates.length === 0) {
			skipped.push({ domain: args.brand, reason: 'discovery_incomplete' });
			return rankCscLeads([], brand, skipped);
		}
		// Prefer sellable buckets when truncating to the lead budget.
		const ordered = [...candidates].sort((a, b) => Number(SELLABLE_BUCKETS.has(b.ownershipBucket)) - Number(SELLABLE_BUCKETS.has(a.ownershipBucket)));
		work = ordered.slice(0, LEAD_BUDGET).map((c) => ({ domain: c.domain, ownershipBucket: c.ownershipBucket }));
	} else {
		const domains = (args.domains ?? []).slice(0, LEAD_BUDGET);
		for (const raw of domains) {
			const validation = validateDomain(raw);
			if (!validation.valid) {
				skipped.push({ domain: raw, reason: validation.error ?? 'invalid_domain' });
				continue;
			}
			work.push({ domain: sanitizeDomain(raw), ownershipBucket: 'unknown' });
		}
	}

	// 2. Evaluate with bounded concurrency + per-domain budget (batch_scan pattern).
	const entries: CscLeadEntry[] = [];
	let cursor = 0;
	const worker = async (): Promise<void> => {
		while (cursor < work.length) {
			const task = work[cursor++];
			if (!task) return;
			const remaining = deadline - Date.now();
			if (remaining <= 0) {
				skipped.push({ domain: task.domain, reason: 'budget_exceeded' });
				continue;
			}
			let timeoutId: ReturnType<typeof setTimeout> | undefined;
			try {
				const evalPromise = evaluateOne(task.domain, task.ownershipBucket, kv, runtimeOptions);
				const timeoutPromise = new Promise<never>((_, reject) => {
					timeoutId = setTimeout(() => reject(new Error('budget_exceeded')), remaining);
				});
				entries.push(await Promise.race([evalPromise, timeoutPromise]));
			} catch (err) {
				skipped.push({ domain: task.domain, reason: err instanceof Error ? err.message : 'scan_failed' });
			} finally {
				if (timeoutId !== undefined) clearTimeout(timeoutId);
			}
		}
	};
	await Promise.all(Array.from({ length: Math.max(1, Math.min(SCAN_CONCURRENCY, work.length || 1)) }, () => worker()));

	// 3. Rank (pure).
	return rankCscLeads(entries, brand, skipped);
}
