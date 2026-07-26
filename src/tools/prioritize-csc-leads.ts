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
import type { CscProductKey, CscPriority, CscProductReport, CaveatKind } from './map-csc-products';
import { evaluateCscProducts, extractLockPosture, UNASSESSED_CSC_NOTE } from './map-csc-products';
import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';
import type { CheckResult } from '../lib/scoring';
import { nistScoreToGrade } from '../lib/scoring';
import { scanDomain } from './scan-domain';
import { checkRdapLookup, RDAP_LOOKUP_SYNC_BUDGET_MS } from './check-rdap-lookup';
import { brandAuditSingle } from './brand-audit-single';
import { validateDomain, sanitizeDomain } from '../lib/sanitize';
import type { ScanRuntimeOptions } from './scan/post-processing';
import { UNGRADED_DISPLAY, formatScoreGrade } from '../lib/ungraded-display';

/** Portfolio ownership lens (from classifyCandidate) + 'unknown' for a bare domain list. */
export type OwnershipBucket = 'consolidated' | 'shadowIt' | 'indeterminate' | 'impersonation' | 'impersonationSurface' | 'unknown';

/** A single ranked sales lead. */
export interface CscLead {
	domain: string;
	/** `null` when the scan produced no gradeable measurement. Never a coerced 0. */
	score: number | null;
	/** `null` when the scan produced no gradeable measurement. Never a fabricated letter. */
	grade: string | null;
	/**
	 * Is there any COMPLETED check evidence for this domain? (`hasCompletedEvidence`,
	 * via `evaluateCscProducts` — NOT `isMeasured`: a total-outage scan has checks
	 * with `checkStatus: 'timeout' | 'error'` on every one of them, which
	 * `isMeasured` alone could not tell apart from a genuinely measured scan.)
	 * Gates everything derived from the CHECKS: `gapSeverity`, the product list,
	 * and every sales rollup. Same meaning as the `assessed` flag on
	 * `map_compliance`/`generate_fix_plan`.
	 */
	assessed: boolean;
	/**
	 * `null` when `assessed` is `true`; otherwise the producer's own
	 * (`evaluateCscProducts`'s) explanation of WHY — "no checks ran"
	 * ({@link UNASSESSED_CSC_NOTE}) vs. "checks were attempted but none
	 * completed" (`buildAllTransientCscNote`, from `map_csc_products`).
	 * Threaded straight through from `CscProductReport.caveat` so this tool
	 * never re-derives or re-guesses the reason — it only had ONE reason to say
	 * before this field existed, which is exactly how an all-transient lead
	 * ended up printing the false "no checks ran" sentence.
	 */
	caveat: string | null;
	/**
	 * REQUIRED — the STRUCTURAL discriminant paired with `caveat`, threaded
	 * straight through from `CscProductReport.caveatKind`. `null` exactly when
	 * `assessed` is `true`. The render helpers below (`leadUnassessedNote`,
	 * `compactUnassessedNote`, `buildReportCaveat`) MUST branch on this field,
	 * never on `caveat`'s string content — see the type doc on `CaveatKind` in
	 * `map_csc_products`.
	 */
	caveatKind: CaveatKind | null;
	/**
	 * Did this domain produce a gradeable SCORE? (`isGraded`.) Gates only what the
	 * score supports: the portfolio-grade contribution and the score line.
	 *
	 * The two flags genuinely diverge on `buildUnscoredResult` — the shipped
	 * scoring-bundle-failure path — where every check ran and found real problems
	 * but the weighted score did not compute: `assessed` true, `graded` false. Each
	 * claim this tool makes is gated by the predicate that makes it true; using one
	 * for the other is how the tool ended up telling an MSSP "no checks ran" about
	 * a domain with a critical expired certificate.
	 */
	graded: boolean;
	ownershipBucket: OwnershipBucket;
	recommendedCscProducts: CscProductKey[];
	/**
	 * `null` for an UNASSESSED lead — NOT 0, and not merely for an ungraded one.
	 *
	 * `evaluateCscProducts` recommends every scan-driven product it could not
	 * observe ("DMARC not observed", …), so a domain that does not resolve
	 * manufactures gapValue 3+2+2 = 7 — above HOT_LEAD_THRESHOLD — purely from
	 * having measured nothing. Since `gapSeverity` is the FIRST sort key, that
	 * presented a non-existent domain as the top-priority hot lead, outranking a
	 * real domain with a genuinely failing DMARC policy. A severity derived from
	 * absence of observation is not a severity.
	 *
	 * The gate is `assessed`, not `graded`, because this number is derived from the
	 * recommendations and therefore from the CHECKS — the score never enters it. A
	 * scoring-failure domain has genuine gaps and keeps its real severity.
	 */
	gapSeverity: number | null;
	priorityRank: number;
	recommendedCount: number;
	topPriority: CscPriority;
}

/** Brand-level portfolio rollup grade (weighted average of contributing domains' scan scores). */
export interface PortfolioGrade {
	/** NIST 6-band DISPLAY letter (A+/A/B/C/D/F) from nistScoreToGrade(weightedScore). */
	grade: string;
	/** Weighted-average scan score across contributing domains, 0–100, Math.round'd to an integer. */
	weightedScore: number;
	/** Count of leads whose ownership bucket carries a non-zero rollup weight AND that carry a real grade (grade !== null). */
	contributingDomains: number;
}

export interface CscLeadReport {
	brand: string | null;
	totalDomains: number;
	rankedLeads: CscLead[];
	/** NEW — additive/optional. rankCscLeads ALWAYS sets it (PortfolioGrade or null). */
	portfolioGrade?: PortfolioGrade | null;
	/**
	 * Set when at least one ranked lead was not fully measured; `null` otherwise.
	 * A consumer reading only the rollups still learns they exclude domains.
	 *
	 * Phrased in REPORT-level terms — counts, never "this domain". A dashboard
	 * renders this field on its own, away from the per-lead prose, so a lead-shaped
	 * sentence loses its referent here: concatenating the two per-lead notes read as
	 * a flat self-contradiction ("No checks ran for this domain… The checks for this
	 * domain ran…") even though each half was true of a different lead.
	 *
	 * There is deliberately no report-level `assessed` boolean: on a multi-domain
	 * report that word would have to mean "every lead was measured", a different
	 * proposition from the per-domain flag of the same name on the single-domain
	 * reports. `summary.unassessedDomains` / `summary.unscoredDomains` say exactly
	 * how many of each, which a boolean cannot.
	 */
	caveat?: string | null;
	summary: {
		totalRecommendations: number;
		byProduct: Record<CscProductKey, number>;
		hotLeads: number;
		/**
		 * Ranked leads with no COMPLETED check evidence — excluded from every
		 * rollup above. Two distinct causes collapse into this one count: the
		 * domain never resolved (no checks ran), or every attempted check hit a
		 * transient DNS/network failure and never completed. `rankedLeads[].caveat`
		 * says which, per lead.
		 */
		unassessedDomains: number;
		/**
		 * Ranked leads whose checks ran but which produced no score. They DO count in
		 * the rollups above (their gaps are measured evidence) and are excluded only
		 * from the score-derived portfolio grade.
		 */
		unscoredDomains: number;
		skipped: Array<{ domain: string; reason: string }>;
	};
}

/**
 * The per-lead qualifier for "no check ran" — the domain does not resolve, or its
 * zone is broken. Nothing derived from the checks is reported for such a domain.
 *
 * The first sentence is {@link UNASSESSED_CSC_NOTE}, shared with
 * `map_csc_products` so both tools say the same thing about the same state; the
 * second is the leads-specific consequence.
 *
 * Byte-identical to its pre-fix-round wording — kept as the CONTROL a lead
 * whose producer caveat genuinely is {@link UNASSESSED_CSC_NOTE} still renders.
 * A lead whose caveat is the DIFFERENT "attempted, none completed" sentence
 * (a total-outage scan) must NOT render this constant — see
 * {@link leadUnassessedNote}, which chooses between the two using the
 * producer's own `caveat`.
 */
export const UNASSESSED_LEAD_NOTE = `${UNASSESSED_CSC_NOTE} It is excluded from the hot-lead count, the recommendation totals and the portfolio grade.`;

/**
 * True when a per-lead `caveatKind` is the producer's never-ran reason
 * (NXDOMAIN, broken zone) rather than its all-transient reason (a total
 * DoH/network outage). STRUCTURAL — reads the discriminant, never the
 * `caveat` string. `null`/`'never_ran'` both classify as never-ran; only the
 * literal `'all_transient'` classifies as transient. A round-1 version of
 * this compared `caveat === UNASSESSED_CSC_NOTE` by STRING IDENTITY, with
 * "anything else" defaulting to transient — a renamed constant or a third
 * wording introduced later would have silently misclassified. `caveatKind`
 * cannot drift that way: it is a closed union the producer sets explicitly.
 */
function isNeverRanKind(caveatKind: CaveatKind | null): boolean {
	return caveatKind !== 'all_transient';
}

/**
 * The FULL-format per-lead note for an unassessed lead, choosing between the
 * two producer-computed reasons rather than always printing
 * {@link UNASSESSED_LEAD_NOTE}. Before this, EVERY unassessed lead printed "no
 * checks ran" — false for a lead whose checks were attempted and errored out
 * (a total-outage scan), which is exactly the state `map_csc_products` already
 * distinguishes via `CscProductReport.caveatKind`. This tool only had to start
 * reading that field. `caveat` (the prose) is still what gets PRINTED; only the
 * BRANCH is decided by `caveatKind`.
 */
function leadUnassessedNote(caveat: string | null, caveatKind: CaveatKind | null): string {
	// caveat === null guard: the producer sets caveat and caveatKind together, but a
	// hand-built report violating that contract would interpolate a literal "null"
	// into customer prose here — the exact shape of the null/100 (null) regression.
	if (isNeverRanKind(caveatKind) || caveat === null) return UNASSESSED_LEAD_NOTE;
	return `${caveat} It is excluded from the hot-lead count, the recommendation totals and the portfolio grade.`;
}

/** The COMPACT-format per-lead qualifier — same distinction as {@link leadUnassessedNote}, terser. */
function compactUnassessedNote(caveatKind: CaveatKind | null): string {
	return isNeverRanKind(caveatKind) ? 'no checks ran' : 'checks attempted, none completed';
}

/**
 * The per-lead qualifier for "checks ran, scan could not be scored".
 *
 * A DIFFERENT sentence for a different fact. Reusing the "no checks ran" wording
 * here stated a falsehood about a domain whose checks ran and found a critical
 * expired certificate — the note was gated on `graded` while asserting something
 * only `isMeasured` could support.
 */
export const UNSCORED_LEAD_NOTE =
	'The checks for this domain ran and the gaps below are real, but the scan could not be scored, so this domain is excluded from the portfolio grade.';

/**
 * The same fact for an unscored lead with NO recommendations — reachable whenever
 * the scoring bundle fails on a clean domain. {@link UNSCORED_LEAD_NOTE} promises
 * "the gaps below are real" and the next line then reads "No CSC upsell — posture
 * clean": a dangling referent, a promise the output immediately breaks.
 */
export const UNSCORED_LEAD_NOTE_NO_GAPS =
	'The checks for this domain ran and found no product gap, but the scan could not be scored, so this domain is excluded from the portfolio grade.';

/** `1 domain` / `N domains` — report-level counts read on their own, so they must not be bare numbers. */
function domainCount(n: number): string {
	return n === 1 ? '1 domain' : `${n} domains`;
}

/**
 * Compose the report-level caveat from the unassessed leads' own producer
 * caveat KINDS plus the unscored-domain count, or `null` when every lead was
 * fully measured. Each clause is a statement about the REPORT.
 *
 * STATE-AWARE: `unassessedKinds` is one entry per unassessed lead (its own
 * `caveatKind`, threaded from `CscProductReport.caveatKind`), not a bare
 * count. A hardcoded "no checks ran" reason here was false whenever the
 * exclusions were actually a total-outage scan (checks attempted, none
 * completed) — the exact same defect this fix round addresses at the
 * per-lead render sites, one level up. A MIXED population (some leads never
 * ran, others hit a transient outage) states both reasons rather than
 * picking one arbitrarily. Classifies by the STRUCTURAL `caveatKind`, not by
 * comparing prose strings — see {@link isNeverRanKind}.
 */
function buildReportCaveat(unassessedKinds: ReadonlyArray<CaveatKind | null>, unscoredDomains: number): string | null {
	const parts: string[] = [];
	const unassessedDomains = unassessedKinds.length;
	if (unassessedDomains > 0) {
		const anyNeverRan = unassessedKinds.some(isNeverRanKind);
		const anyTransient = unassessedKinds.some((k) => !isNeverRanKind(k));
		const reason =
			anyNeverRan && anyTransient
				? 'some had no checks run at all, and others had checks attempted but none of them completed (transient DNS/network failure)'
				: anyTransient
					? 'checks were attempted but none of them completed (transient DNS/network failure)'
					: 'no checks ran';
		parts.push(
			`${domainCount(unassessedDomains)} could not be assessed: ${reason}, so ${unassessedDomains === 1 ? 'it is' : 'they are'} excluded from the hot-lead count, the recommendation totals and the portfolio grade.`,
		);
	}
	if (unscoredDomains > 0) {
		parts.push(
			`${domainCount(unscoredDomains)} could not be scored: the checks ran and ${unscoredDomains === 1 ? 'its gaps are' : 'their gaps are'} counted in the totals, but ${unscoredDomains === 1 ? 'it is' : 'they are'} excluded from the portfolio grade.`,
		);
	}
	return parts.length > 0 ? parts.join(' ') : null;
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

// Portfolio-grade rollup weights — the weight each domain's SCORE carries toward the
// brand-level grade. DISTINCT concern from OWNERSHIP_MULTIPLIER (sales actionability);
// do NOT reuse or mutate that map. Impersonation buckets are excluded (weight 0).
const PORTFOLIO_ROLLUP_WEIGHTS: Record<OwnershipBucket, number> = {
	consolidated: 2,
	shadowIt: 1,
	indeterminate: 1,
	unknown: 1,
	impersonationSurface: 0,
	impersonation: 0,
};

/**
 * Weighted portfolio rollup grade (PURE). weightedScore = round( Σ(w[bucket]*score) / Σ(w[bucket]) )
 * over all leads, where w = PORTFOLIO_ROLLUP_WEIGHTS. Domains with weight 0 (impersonation buckets)
 * and ungraded (`grade === null`) results (NXDOMAIN / SERVFAIL-broken / scoring-bundle failure) drop
 * out — averaging their 0 score would silently sink the portfolio (see scan-domain.ts aggregator
 * contract). Returns null when `leads` is empty OR Σ(weight) === 0 (no contributing domains).
 * NEVER averages letters and NEVER inlines band thresholds — it rounds the numeric weighted average
 * once, then calls nistScoreToGrade(weightedScore) exactly once so the displayed score and letter
 * never disagree at a band edge.
 */
export function computePortfolioGrade(leads: Pick<CscLead, 'score' | 'ownershipBucket' | 'grade'>[]): PortfolioGrade | null {
	let numerator = 0;
	let denominator = 0;
	let contributingDomains = 0;
	for (const lead of leads) {
		// An ungraded lead has no score to average — `null` is the SINGLE representation
		// of that state (3.35.0 retired the string sentinel the producers used to emit).
		// Averaging a coerced 0 in its place would silently sink the whole portfolio.
		if (lead.score === null || lead.grade === null) continue;
		const weight = PORTFOLIO_ROLLUP_WEIGHTS[lead.ownershipBucket];
		if (weight === 0) continue;
		numerator += weight * lead.score;
		denominator += weight;
		contributingDomains += 1;
	}
	if (denominator === 0) return null; // empty or all-excluded — never divide, never reach nistScoreToGrade
	const weightedScore = Math.round(numerator / denominator);
	return { grade: nistScoreToGrade(weightedScore), weightedScore, contributingDomains };
}

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
	const leads: CscLead[] = entries.map((e) => {
		// Two predicates, deliberately separate. `graded` is the SAME condition
		// `computePortfolioGrade` has always used to drop a lead from the weighted
		// average. `assessed` is whether there is any COMPLETED check evidence —
		// the producer computes it with `hasCompletedEvidence`, and it is what the
		// check-derived numbers hang on.
		const graded = e.report.score !== null && e.report.grade !== null;
		const assessed = e.report.assessed;
		return {
			domain: e.report.domain,
			score: e.report.score,
			grade: e.report.grade,
			assessed,
			// Threaded straight from the producer — never re-derived — so this tool
			// says the SAME reason `map_csc_products` would say about the same
			// domain. `null` exactly when `assessed` is `true`.
			caveat: e.report.caveat,
			// The STRUCTURAL twin, likewise threaded straight through. See the
			// type doc on `CscLead.caveatKind`.
			caveatKind: e.report.caveatKind,
			graded,
			ownershipBucket: e.ownershipBucket,
			recommendedCscProducts: recommendedProducts(e.report),
			// Absence of observation is not a gap. See the `gapSeverity` doc above.
			gapSeverity: assessed ? computeGapSeverity(e.report, e.ownershipBucket) : null,
			priorityRank: 0, // assigned after the sort
			recommendedCount: e.report.recommendedCount,
			topPriority: topPriorityOf(e.report),
		};
	});

	// An ungraded lead has no severity to rank on, so it sorts AFTER every graded
	// lead (-Infinity under the descending primary key) rather than being ordered by
	// a severity manufactured from non-observation. Two ungraded leads then fall
	// through to the score key — also absent — and finally to the domain tiebreak.
	const severityRank = (l: CscLead): number => (l.gapSeverity === null ? Number.NEGATIVE_INFINITY : l.gapSeverity);
	const scoreRank = (l: CscLead): number => (l.score === null ? Number.POSITIVE_INFINITY : l.score);
	leads.sort((a, b) => severityRank(b) - severityRank(a) || scoreRank(a) - scoreRank(b) || a.domain.localeCompare(b.domain));
	leads.forEach((lead, i) => {
		lead.priorityRank = i + 1;
	});

	// The sales rollups aggregate ASSESSED domains — every number in them is
	// derived from the checks. An unassessed lead's recommendations exist solely
	// because nothing was observed; counting them inflates the portfolio's apparent
	// sales surface. An unscored-but-assessed lead's gaps ARE measured evidence and
	// are counted: withholding them hid a critical expired certificate.
	// Only the score-derived portfolio grade uses `graded`, inside
	// `computePortfolioGrade` where that condition has always lived.
	const assessedLeads = leads.filter((l) => l.assessed);
	const byProduct: Record<CscProductKey, number> = {
		csc_multilock: 0,
		managed_dmarc: 0,
		digital_certificates: 0,
		dnssec_management: 0,
	};
	for (const lead of assessedLeads) {
		for (const key of lead.recommendedCscProducts) byProduct[key] += 1;
	}

	const portfolioGrade = computePortfolioGrade(leads);
	const unassessedLeads = leads.filter((l) => !l.assessed);
	const unassessedDomains = unassessedLeads.length;
	const unscoredDomains = assessedLeads.filter((l) => !l.graded).length;

	return {
		brand,
		totalDomains: leads.length,
		rankedLeads: leads,
		portfolioGrade,
		// State-aware: each unassessed lead carries its OWN producer-computed
		// reason (never-ran vs. attempted-none-completed); `buildReportCaveat`
		// reads those rather than hardcoding a single reason for the whole
		// report, which is what let an all-transient portfolio print the false
		// "no checks ran" sentence.
		caveat: buildReportCaveat(
			unassessedLeads.map((l) => l.caveatKind),
			unscoredDomains,
		),
		summary: {
			totalRecommendations: assessedLeads.reduce((sum, l) => sum + l.recommendedCount, 0),
			byProduct,
			hotLeads: assessedLeads.filter((l) => l.gapSeverity !== null && l.gapSeverity >= HOT_LEAD_THRESHOLD).length,
			unassessedDomains,
			unscoredDomains,
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
			typeof rawBucket === 'string' && KNOWN_BUCKETS.has(rawBucket as Bucket)
				? bucketFromClassification(rawBucket as Bucket)
				: 'indeterminate';
		out.push({ domain: candidate, ownershipBucket: bucket });
	}
	return out;
}

/** Render a ranked CSC lead report for display. */
export function formatCscLeads(report: CscLeadReport, format: OutputFormat = 'full'): string {
	const lines: string[] = [];
	const brandLabel = report.brand ? sanitizeOutputText(report.brand, 253) : 'domain set';

	if (format === 'compact') {
		// Append the portfolio segment only when gradeable; omit entirely when null (keeps compact lean).
		const portfolioSegment = report.portfolioGrade
			? ` — portfolio ${report.portfolioGrade.grade} (${report.portfolioGrade.weightedScore})`
			: '';
		lines.push(`CSC leads (${brandLabel}): ${report.totalDomains} ranked, ${report.summary.hotLeads} hot${portfolioSegment}`);
		for (const lead of report.rankedLeads) {
			// Only an UNASSESSED lead loses its severity and product count. An
			// unscored-but-assessed lead keeps both — `formatScoreGrade` already
			// renders its missing score as the ungraded token, which is the only part
			// that is genuinely unknown.
			lines.push(
				lead.assessed
					? `${lead.priorityRank}. ${sanitizeOutputText(lead.domain, 253)} — sev ${lead.gapSeverity} — ${formatScoreGrade(lead.score, lead.grade)} — ${lead.recommendedCount} product(s)`
					: `${lead.priorityRank}. ${sanitizeOutputText(lead.domain, 253)} — sev ${UNGRADED_DISPLAY} — ${UNGRADED_DISPLAY} — ${compactUnassessedNote(lead.caveatKind)}`,
			);
		}
		return lines.join('\n').trimEnd();
	}

	lines.push(`# CSC Sales Leads: ${brandLabel}`);
	lines.push(`**${report.totalDomains}** domain(s) ranked | **${report.summary.hotLeads}** hot lead(s)`);
	if (report.portfolioGrade) {
		lines.push(
			`**Portfolio grade: ${report.portfolioGrade.grade}** (weighted ${report.portfolioGrade.weightedScore}/100 across ${report.portfolioGrade.contributingDomains} domain(s))`,
		);
	} else {
		// `computePortfolioGrade` returns null for TWO different states, and one
		// sentence covered both: a portfolio of graded impersonation domains printed
		// "no gradeable domains" directly above `Score: 91/100 (A)`. Distinguish
		// "nothing carries a score" from "nothing carries rollup WEIGHT".
		const reason = report.rankedLeads.some((l) => l.graded)
			? 'no domain carries rollup weight — every graded domain sits in an impersonation bucket'
			: 'no gradeable domains';
		lines.push(`**Portfolio grade: ${UNGRADED_DISPLAY}** (${reason})`);
	}
	lines.push('');
	for (const lead of report.rankedLeads) {
		// An UNASSESSED lead gets a header with no severity, its score qualified, and
		// the note — and NONE of the derived sales claims. `topPriority` and the
		// product list for such a lead are artifacts of having observed nothing
		// ("DMARC not observed"), so printing them under a "not measured" score
		// would sell products for a domain nobody looked at.
		if (!lead.assessed) {
			lines.push(`## ${lead.priorityRank}. ${sanitizeOutputText(lead.domain, 253)} — gap severity ${UNGRADED_DISPLAY}`);
			lines.push(`  - Score: ${formatScoreGrade(lead.score, lead.grade)} | Ownership: ${lead.ownershipBucket}`);
			lines.push(`  - ${leadUnassessedNote(lead.caveat, lead.caveatKind)}`);
			continue;
		}
		lines.push(`## ${lead.priorityRank}. ${sanitizeOutputText(lead.domain, 253)} — gap severity ${lead.gapSeverity}`);
		lines.push(
			`  - Score: ${formatScoreGrade(lead.score, lead.grade)} | Ownership: ${lead.ownershipBucket} | Top priority: ${lead.topPriority}`,
		);
		// Checks ran, so only the score is missing. Say exactly that rather than
		// reusing the "no checks ran" sentence — and only promise gaps when the next
		// line will actually list some.
		if (!lead.graded) {
			lines.push(`  - ${lead.recommendedCscProducts.length > 0 ? UNSCORED_LEAD_NOTE : UNSCORED_LEAD_NOTE_NO_GAPS}`);
		}
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
		lines.push(
			`  - Skipped: ${report.summary.skipped.map((s) => `${sanitizeOutputText(s.domain, 253)} (${sanitizeOutputText(s.reason, 60)})`).join(', ')}`,
		);
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
	// Pass only the fields BrandAuditSingleOptions accepts: timeoutBehavior + deadlineMs.
	// kv is not part of BrandAuditPipelineOptions (the latent bug hidden by `as never`).
	// ScanRuntimeOptions fields spread in from opts.runtimeOptions are silently ignored
	// by the pipeline; the spread is kept for any future overlap but is currently a no-op.
	const result = await brandAuditSingle(
		brand,
		{ timeoutBehavior: 'async_handoff', deadlineMs: opts.deadlineMs, ...opts.runtimeOptions },
		{},
	);
	return extractDiscoveredCandidates(result);
};

/** Evaluate one domain → a CscLeadEntry (scan + RDAP + Spec B pure evaluation). */
async function evaluateOne(
	domain: string,
	ownershipBucket: OwnershipBucket,
	kv: KVNamespace | undefined,
	runtimeOptions: CscRuntimeOptions | undefined,
): Promise<CscLeadEntry> {
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
		const ordered = [...candidates].sort(
			(a, b) => Number(SELLABLE_BUCKETS.has(b.ownershipBucket)) - Number(SELLABLE_BUCKETS.has(a.ownershipBucket)),
		);
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
