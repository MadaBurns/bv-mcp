// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared types for @blackveil/dns-checks
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

// SPDX-License-Identifier: BUSL-1.1

// DNS query function — dependency injection interface
export type DNSQueryFunction = (domain: string, recordType: string, options?: { timeout?: number }) => Promise<string[]>;

/**
 * Raw DoH-style DNS response for checks that need the AD flag or full Answer array.
 * Mirrors the subset of DoH JSON response used by DNSSEC and NS checks.
 */
export interface RawDNSResponse {
	AD?: boolean;
	Answer?: Array<{ type: number; data: string }>;
}

/**
 * Extended DNS query function that returns the full DoH-style response.
 * Used by DNSSEC and NS checks that need the AD flag or answer type filtering.
 */
export type RawDNSQueryFunction = (
	domain: string,
	recordType: string,
	dnssecFlag?: boolean,
	options?: { timeout?: number },
) => Promise<RawDNSResponse>;

/**
 * Fetch function — dependency injection interface for HTTP-based checks.
 * Matches the standard fetch() API signature.
 */
export type FetchFunction = (url: string, init?: RequestInit) => Promise<Response>;

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingConfidence = 'deterministic' | 'heuristic' | 'verified';

export type CheckCategory =
	| 'spf'
	| 'dmarc'
	| 'dkim'
	| 'dnssec'
	| 'ssl'
	| 'mta_sts'
	| 'ns'
	| 'caa'
	| 'subdomain_takeover'
	| 'mx'
	| 'bimi'
	| 'tlsrpt'
	| 'lookalikes'
	| 'shadow_domains'
	| 'txt_hygiene'
	| 'http_security'
	| 'dane'
	| 'ptr'
	| 'mx_reputation'
	| 'srv'
	| 'zone_hygiene'
	| 'dane_https'
	| 'svcb_https'
	| 'subdomailing'
	| 'brand_discovery'
	| 'authoritative_dns_infra'
	| 'dnskey_strength';

/** Three-tier classification for check categories: core (critical baseline), protective (active risk mitigation), hardening (advanced posture). */
export type CategoryTier = 'core' | 'protective' | 'hardening';

/** Maps every check category to its tier classification. */
export const CATEGORY_TIERS: Record<CheckCategory, CategoryTier> = {
	spf: 'core',
	dmarc: 'core',
	dkim: 'core',
	dnssec: 'core',
	ssl: 'core',
	subdomain_takeover: 'protective',
	http_security: 'protective',
	mta_sts: 'protective',
	mx: 'protective',
	caa: 'protective',
	ns: 'protective',
	lookalikes: 'protective',
	shadow_domains: 'protective',
	dane: 'hardening',
	ptr: 'hardening',
	bimi: 'hardening',
	tlsrpt: 'hardening',
	txt_hygiene: 'hardening',
	mx_reputation: 'hardening',
	srv: 'hardening',
	zone_hygiene: 'hardening',
	dane_https: 'protective',
	svcb_https: 'protective',
	subdomailing: 'protective',
	brand_discovery: 'hardening',
	authoritative_dns_infra: 'core',
	dnskey_strength: 'hardening',
};

export interface Finding {
	category: CheckCategory;
	title: string;
	severity: Severity;
	detail: string;
	metadata?: Record<string, unknown>;
}

export type CheckStatus = 'completed' | 'timeout' | 'error';

export interface CheckResult {
	category: CheckCategory;
	passed: boolean;
	score: number;
	findings: Finding[];
	/** Execution status of the check. Absent or 'completed' means the check ran normally. 'timeout'/'error' indicate failed execution — findings are unreliable and category score is forced to 0. */
	checkStatus?: CheckStatus;
	/** When true, the result is incomplete (e.g. timeout) and should not be cached long-term. */
	partial?: boolean;
	/**
	 * Whether the checked control is *meaningfully present and active* — distinct from `passed`.
	 * `true` = an active record/response was observed (real mail MX, non-revoked DKIM key, MTA-STS
	 * policy record, DMARC-enforcing BIMI, reachable HTTPS, CAA records). `false` = definitively
	 * absent or inactive (no MX / null MX, all-revoked DKIM, no record, non-enforcing BIMI,
	 * unreachable HTTPS). `undefined` = could not be determined (e.g. the DNS query failed).
	 *
	 * `passed` is unsafe as a presence proxy: an absent-but-not-penalized control (e.g. MTA-STS on a
	 * non-mail domain) still yields `passed === true`. Profile detection (`detectDomainContext`) reads
	 * this instead of `passed`/finding prose. Only the checks `detectDomainContext` consumes set it.
	 */
	controlPresent?: boolean;
	/** Optional structured metadata attached to the result by the check wrapper (not the core package). */
	metadata?: Record<string, unknown>;
}

export interface ScanScore {
	overall: number;
	grade: string;
	categoryScores: Record<CheckCategory, number>;
	findings: Finding[];
	summary: string;
	/**
	 * Points earned per scoring tier (core/protective/hardening) for the overall
	 * score — the tier-weighted composition behind the headline number, as opposed
	 * to the per-category `categoryScores`. Structurally identical to `TierBreakdown`
	 * (scoring/generic); kept inline here because `types` is a leaf module that
	 * `scoring/generic` imports from. Optional: absent only for the degenerate
	 * no-checks result.
	 */
	tierBreakdown?: { core: number; protective: number; hardening: number };
}

/** Display/UI weight distribution for categories. NOT used in scoring — see IMPORTANCE_WEIGHTS for actual scoring weights. Exists for category registry and display purposes only. */
export const CATEGORY_DISPLAY_WEIGHTS: Record<CheckCategory, number> = {
	spf: 0.15,
	dmarc: 0.15,
	dkim: 0.15,
	dnssec: 0.15,
	ssl: 0.15,
	mta_sts: 0.05,
	ns: 0.05,
	caa: 0.05,
	subdomain_takeover: 0.1,
	mx: 0,
	bimi: 0,
	tlsrpt: 0.02,
	lookalikes: 0,
	shadow_domains: 0,
	txt_hygiene: 0,
	http_security: 0.05,
	dane: 0,
	ptr: 0,
	mx_reputation: 0,
	srv: 0,
	zone_hygiene: 0,
	dane_https: 0,
	svcb_https: 0,
	subdomailing: 0.05,
	brand_discovery: 0,
	authoritative_dns_infra: 0.2,
	dnskey_strength: 0,
};

/** Severity penalty multipliers applied to the category score */
export const SEVERITY_PENALTIES: Record<Severity, number> = {
	critical: 40,
	high: 25,
	medium: 15,
	low: 5,
	info: 0,
};

/**
 * Maximum total penalty per category. When a category accumulates many findings of the
 * same class, the raw penalty sum can exceed the base score (100) and saturate the
 * category score at 0 — losing the distinction between "many same-class findings" and
 * "one truly catastrophic finding".
 *
 * This map caps per-category penalty BEFORE clamping to [0, 100]. Categories omitted
 * from the map retain the legacy uncapped-then-clamped behavior, preserving all
 * existing test expectations across the non-takeover category surface.
 *
 * Initial coverage: only `subdomain_takeover`. The takeover sweep is the one category
 * where a single upstream resource deletion (e.g., the x.ai AWS NLB cluster: 9 dangling
 * subdomains) routinely produces many same-class findings, all of which represent
 * the SAME operational miss rather than independent compounding risks.
 *
 * Cap = 75 means: even with 5+ MEDIUM findings (15×5=75) or 2 CRITICAL findings
 * (40×2=80→75), the category score floors at 25/100 rather than 0/100. Preserves
 * discriminative power between "broken" (25-49) and "system-critical missing" (0).
 */
export const CATEGORY_PENALTY_CAPS: Partial<Record<CheckCategory, number>> = {
	subdomain_takeover: 75,
};

export type ZoneDelegationStatus =
	| 'apex' // scanned label IS its zone apex (registrable domain, or has its own NS RRset)
	| 'inherited' // not delegated; posture governed by an ancestor zone apex
	| 'undelegated_broken' // no NS anywhere up to the registrable apex (genuine failure)
	| 'unknown'; // resolver could not determine (timeout/error) — inconclusive

export interface ZoneContext {
	/** The exact hostname that was scanned. */
	scannedLabel: string;
	/** PSL registrable domain — the hard floor the walk never crosses. */
	registrableDomain: string;
	/** True when the scanned label is (or is equivalent to) its own zone apex. */
	isApex: boolean;
	/** Nearest ancestor (<= registrableDomain) that owns an NS RRset. */
	zoneApex: string;
	/** NS records at zoneApex (empty for undelegated_broken/unknown). */
	apexNsRecords: string[];
	/** How the label relates to its zone apex. */
	delegationStatus: ZoneDelegationStatus;
}
