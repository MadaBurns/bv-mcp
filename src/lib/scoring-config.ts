// SPDX-License-Identifier: BUSL-1.1

/**
 * Runtime scoring configuration.
 *
 * All scoring weights, thresholds, and tuning constants are configurable
 * via the `SCORING_CONFIG` environment variable (JSON string). The open-source
 * codebase ships with reasonable defaults; production deployments can override
 * any subset of values.
 *
 * Parse once at request entry and thread through the call chain — never
 * re-parse per tool call.
 */

import type { CheckCategory } from './scoring-model';
import type { DomainProfile } from './context-profiles';

/** All tunable scoring parameters. */
export interface ScoringConfig {
	/** Base importance weights per check category (used when no profile context). */
	weights: Record<CheckCategory, number>;

	/** Per-profile importance weights. */
	profileWeights: Record<DomainProfile, Record<CheckCategory, number>>;

	/** Scoring thresholds and constants. */
	thresholds: {
		emailBonusImportance: number;
		spfStrongThreshold: number;
		criticalOverallPenalty: number;
		criticalGapCeiling: number;
	};

	/** Grade boundaries (minimum score for each grade). */
	grades: {
		aPlus: number;
		a: number;
		bPlus: number;
		b: number;
		cPlus: number;
		c: number;
		dPlus: number;
		d: number;
		e: number;
	};

	/** Baseline failure rates for adaptive weight computation. */
	baselineFailureRates: Record<string, number>;
}

/** Built-in defaults — used when `SCORING_CONFIG` env var is absent or partial. */
export const DEFAULT_SCORING_CONFIG: ScoringConfig = {
	weights: {
		spf: 10,
		dmarc: 22,
		dkim: 16,
		dnssec: 2,
		ssl: 5,
		mta_sts: 2,
		ns: 0,
		caa: 0,
		subdomain_takeover: 3,
		mx: 2,
		bimi: 0,
		tlsrpt: 1,
		lookalikes: 0,
		shadow_domains: 0,
		txt_hygiene: 0,
	},
	profileWeights: {
		mail_enabled: { dmarc: 22, dkim: 16, spf: 10, ssl: 5, subdomain_takeover: 3, dnssec: 2, mta_sts: 2, mx: 2, tlsrpt: 1, caa: 0, ns: 0, bimi: 0, lookalikes: 0, shadow_domains: 0, txt_hygiene: 0 },
		enterprise_mail: { dmarc: 24, dkim: 18, spf: 12, ssl: 5, subdomain_takeover: 3, dnssec: 3, mta_sts: 4, mx: 2, tlsrpt: 2, caa: 0, ns: 0, bimi: 1, lookalikes: 0, shadow_domains: 0, txt_hygiene: 0 },
		non_mail: { ssl: 8, subdomain_takeover: 5, dnssec: 5, caa: 3, dmarc: 2, ns: 2, dkim: 1, spf: 1, mx: 0, mta_sts: 0, tlsrpt: 0, bimi: 0, lookalikes: 0, shadow_domains: 0, txt_hygiene: 0 },
		web_only: { ssl: 12, subdomain_takeover: 5, dnssec: 5, caa: 5, dmarc: 2, ns: 2, dkim: 1, spf: 1, mx: 0, mta_sts: 0, tlsrpt: 0, bimi: 0, lookalikes: 0, shadow_domains: 0, txt_hygiene: 0 },
		minimal: { dmarc: 5, ssl: 5, dnssec: 5, dkim: 3, spf: 3, subdomain_takeover: 3, ns: 2, mx: 1, caa: 1, mta_sts: 0, tlsrpt: 0, bimi: 0, lookalikes: 0, shadow_domains: 0, txt_hygiene: 0 },
	},
	thresholds: {
		emailBonusImportance: 8,
		spfStrongThreshold: 57,
		criticalOverallPenalty: 15,
		criticalGapCeiling: 64,
	},
	grades: {
		aPlus: 90,
		a: 85,
		bPlus: 80,
		b: 75,
		cPlus: 70,
		c: 65,
		dPlus: 60,
		d: 55,
		e: 50,
	},
	baselineFailureRates: {
		dmarc: 0.40,
		spf: 0.25,
		dkim: 0.35,
		ssl: 0.08,
		mta_sts: 0.85,
		dnssec: 0.80,
		mx: 0.05,
		caa: 0.70,
		ns: 0.03,
		bimi: 0.95,
		tlsrpt: 0.90,
		subdomain_takeover: 0.10,
		lookalikes: 0.00,
		shadow_domains: 0.00,
		txt_hygiene: 0.00,
	},
};

/**
 * Convert flat weight numbers to the `{ importance: number }` shape
 * used by the scoring engine and profile system.
 */
export function toImportanceRecord<K extends string>(
	weights: Record<K, number>,
): Record<K, { importance: number }> {
	const result = {} as Record<K, { importance: number }>;
	for (const key of Object.keys(weights) as K[]) {
		result[key] = { importance: weights[key] };
	}
	return result;
}

/** Safely merge a partial weight record into defaults. */
function mergeWeights(
	defaults: Record<string, number>,
	overrides: Record<string, unknown> | undefined,
): Record<string, number> {
	if (!overrides || typeof overrides !== 'object') return { ...defaults };
	const result = { ...defaults };
	for (const [key, value] of Object.entries(overrides)) {
		if (key in defaults && typeof value === 'number' && Number.isFinite(value)) {
			result[key] = Math.max(0, value);
		}
	}
	return result;
}

/**
 * Parse a `SCORING_CONFIG` env var string into a fully-populated `ScoringConfig`.
 *
 * Gracefully handles undefined, empty, invalid JSON, partial overrides,
 * and invalid value types. Always returns a complete config by merging
 * overrides into defaults.
 */
export function parseScoringConfig(raw: string | undefined): ScoringConfig {
	if (!raw || raw.trim().length === 0) return DEFAULT_SCORING_CONFIG;

	let parsed: Record<string, unknown>;
	try {
		parsed = JSON.parse(raw) as Record<string, unknown>;
	} catch {
		return DEFAULT_SCORING_CONFIG;
	}

	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
		return DEFAULT_SCORING_CONFIG;
	}

	// Merge weights
	const weights = mergeWeights(
		DEFAULT_SCORING_CONFIG.weights,
		parsed.weights as Record<string, unknown> | undefined,
	) as Record<CheckCategory, number>;

	// Merge profile weights
	const profileWeights = { ...DEFAULT_SCORING_CONFIG.profileWeights } as Record<DomainProfile, Record<CheckCategory, number>>;
	const rawProfileWeights = parsed.profileWeights as Record<string, Record<string, unknown>> | undefined;
	if (rawProfileWeights && typeof rawProfileWeights === 'object') {
		for (const profile of Object.keys(DEFAULT_SCORING_CONFIG.profileWeights) as DomainProfile[]) {
			if (profile in rawProfileWeights) {
				profileWeights[profile] = mergeWeights(
					DEFAULT_SCORING_CONFIG.profileWeights[profile],
					rawProfileWeights[profile],
				) as Record<CheckCategory, number>;
			}
		}
	}

	// Merge thresholds
	const rawThresholds = parsed.thresholds as Record<string, unknown> | undefined;
	const thresholds = { ...DEFAULT_SCORING_CONFIG.thresholds };
	if (rawThresholds && typeof rawThresholds === 'object') {
		for (const key of Object.keys(thresholds) as Array<keyof typeof thresholds>) {
			if (key in rawThresholds && typeof rawThresholds[key] === 'number' && Number.isFinite(rawThresholds[key])) {
				thresholds[key] = rawThresholds[key] as number;
			}
		}
	}

	// Merge grades
	const rawGrades = parsed.grades as Record<string, unknown> | undefined;
	const grades = { ...DEFAULT_SCORING_CONFIG.grades };
	if (rawGrades && typeof rawGrades === 'object') {
		for (const key of Object.keys(grades) as Array<keyof typeof grades>) {
			if (key in rawGrades && typeof rawGrades[key] === 'number' && Number.isFinite(rawGrades[key])) {
				grades[key] = rawGrades[key] as number;
			}
		}
	}

	// Merge baseline failure rates
	const baselineFailureRates = mergeWeights(
		DEFAULT_SCORING_CONFIG.baselineFailureRates,
		parsed.baselineFailureRates as Record<string, unknown> | undefined,
	);

	return { weights, profileWeights, thresholds, grades, baselineFailureRates };
}
