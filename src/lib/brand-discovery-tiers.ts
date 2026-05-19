// SPDX-License-Identifier: BUSL-1.1
//
// Brand-discovery tier classification — pure logic, no I/O.
//
// Five tiers route discovery observations by provenance and corroboration
// strength. See docs/superpowers/plans/2026-05-20-brand-discovery-first-principles.md
// for the full design. Companion plan: 2026-05-20-brand-discovery-first-principles-tdd.md (Task 1).
//
// Tier 0 — tenant-declared portfolios (`bv-enterprise.tenant_domains`).
// Tier 1 — pre-computed signal-graph candidates (`bv-infrastructure-graph`).
// Tier 2 — declared/witnessed evidence from intel gateway (RDAP / DMARC rua / CT walk / etc).
// Tier 3 — live DNS-signal sweep (existing pipeline; fallback only when upstream is stale/miss).
// Tier 4 — impersonation surface (lookalikes, score-alert critical-drops).
//
// `MUTUAL_EXCLUSIVE_PAIRS` lists tier pairs that must not co-occur on a single domain
// candidate. Owned-portfolio tiers (0..3) are mutually exclusive with the impersonation
// tier (4) because a domain owned by the tenant cannot also be classified as impersonating
// the tenant.

/** Observation shape consumed by the tier-classification predicate. Pure structural type. */
export interface TierClassifiableObservation {
	/** Provenance string identifying which subsystem produced this observation. */
	readonly source: string;
	/** Optional confidence in [0, 1]; reserved for future tie-breaking. */
	readonly confidence?: number;
	/** Optional specificity weight from the infra-graph signal_specificity table. */
	readonly specificityScore?: number;
}

/** Tier number for an observation. */
export type BrandDiscoveryTier = 0 | 1 | 2 | 3 | 4;

const TIER_0_SOURCES: ReadonlySet<string> = new Set(['tenant_domains']);

const TIER_1_SOURCES: ReadonlySet<string> = new Set(['infra_graph_signal']);

const TIER_2_SOURCES: ReadonlySet<string> = new Set([
	'rdap_registrant_match',
	'dmarc_rua',
	'ct_walk',
	'mta_sts',
	'bimi',
	'security_txt',
]);

const TIER_3_SOURCES: ReadonlySet<string> = new Set([
	'ns',
	'dkim_key_reuse',
	'san',
	'san_recursive',
	'http_redirect',
	'mx_overlap',
	'mx_platform',
	'txt_verification',
	'spf_include',
	'spf_include_seed',
	'cname_alignment',
]);

const TIER_4_SOURCES: ReadonlySet<string> = new Set([
	'active_lookalike',
	'markov_gen',
	'score_alert_critical_drop',
]);

/**
 * Classify an observation into its discovery tier.
 *
 * Pure function. Throws on unknown `source` so silent misclassification is impossible —
 * callers must register new signal provenances explicitly.
 */
export function tierFor(observation: TierClassifiableObservation): BrandDiscoveryTier {
	const { source } = observation;
	if (TIER_0_SOURCES.has(source)) return 0;
	if (TIER_1_SOURCES.has(source)) return 1;
	if (TIER_2_SOURCES.has(source)) return 2;
	if (TIER_3_SOURCES.has(source)) return 3;
	if (TIER_4_SOURCES.has(source)) return 4;
	throw new Error(`tierFor: unknown observation source '${source}' — register it in brand-discovery-tiers.ts`);
}

/**
 * Pairs of tiers that must not co-occur on the same domain candidate.
 *
 * Owned tiers (0/1/2/3) are mutually exclusive with the impersonation tier (4).
 * Enforced by an audit test in test/audits/brand-discovery-tier-mutual-exclusion.audit.test.ts
 * (landed in a later task); declared here as the canonical source.
 */
export const MUTUAL_EXCLUSIVE_PAIRS: readonly (readonly [BrandDiscoveryTier, BrandDiscoveryTier])[] = [
	[0, 4],
	[1, 4],
	[2, 4],
	[3, 4],
] as const;
