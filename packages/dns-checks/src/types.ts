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
	| 'svcb_https';

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
};

export interface Finding {
	category: CheckCategory;
	title: string;
	severity: Severity;
	detail: string;
	metadata?: Record<string, unknown>;
}

export interface CheckResult {
	category: CheckCategory;
	passed: boolean;
	score: number;
	findings: Finding[];
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
};

/** Severity penalty multipliers applied to the category score */
export const SEVERITY_PENALTIES: Record<Severity, number> = {
	critical: 40,
	high: 25,
	medium: 15,
	low: 5,
	info: 0,
};
