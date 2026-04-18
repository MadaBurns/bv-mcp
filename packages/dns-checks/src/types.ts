/**
 * Shared types for @blackveil/dns-checks
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

// SPDX-License-Identifier: BUSL-1.1

// DNS query function — dependency injection interface
export type DNSQueryFunction = (
	domain: string,
	recordType: string,
	options?: { timeout?: number }
) => Promise<string[]>;

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
	options?: { timeout?: number }
) => Promise<RawDNSResponse>;

/**
 * Fetch function — dependency injection interface for HTTP-based checks.
 * Matches the standard fetch() API signature.
 */
export type FetchFunction = (
	url: string,
	init?: RequestInit
) => Promise<Response>;

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
	| 'mx_reputation'
	| 'srv'
	| 'zone_hygiene'
	| 'dane_https'
	| 'svcb_https'
	| 'subdomailing';

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
	bimi: 'hardening',
	tlsrpt: 'hardening',
	txt_hygiene: 'hardening',
	mx_reputation: 'hardening',
	srv: 'hardening',
	zone_hygiene: 'hardening',
	dane_https: 'protective',
	svcb_https: 'protective',
	subdomailing: 'protective',
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
	/** Optional structured metadata attached to the result by the check wrapper (not the core package). */
	metadata?: Record<string, unknown>;
}

export interface ScanScore {
	overall: number;
	grade: string;
	categoryScores: Record<CheckCategory, number>;
	findings: Finding[];
	summary: string;
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
	mx_reputation: 0,
	srv: 0,
	zone_hygiene: 0,
	dane_https: 0,
	svcb_https: 0,
	subdomailing: 0.05,
};

/** Severity penalty multipliers applied to the category score */
export const SEVERITY_PENALTIES: Record<Severity, number> = {
	critical: 40,
	high: 25,
	medium: 15,
	low: 5,
	info: 0,
};
