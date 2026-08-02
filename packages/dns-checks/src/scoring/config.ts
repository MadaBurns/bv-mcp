// SPDX-License-Identifier: BUSL-1.1

/**
 * Runtime scoring configuration.
 *
 * All scoring weights, thresholds, and tuning constants are configurable
 * via the `SCORING_CONFIG` environment variable (JSON string). The source-available
 * codebase ships with reasonable defaults; production deployments can override
 * any subset of values.
 *
 * Parse once at request entry and thread through the call chain — never
 * re-parse per tool call.
 */

import type { CheckCategory } from '../types';
import { CATEGORY_TIERS } from '../types';
import type { DomainProfile } from './profiles';
import { PROFILE_WEIGHTS } from './profiles';
import { EVIDENCE_SUFFICIENCY_THRESHOLD } from './evidence';

/** All tunable scoring parameters. */
export interface ScoringConfig {
	/**
	 * Flat per-category weights.
	 *
	 * @deprecated NOT read at runtime. No scoring path consumes this field: the profile-aware
	 * scorer weights every category from {@link ScoringConfig.profileWeights} (via
	 * `getProfileWeights`). The ONLY code that reads it is the legacy migration inside
	 * {@link parseScoringConfig}, which partitions a legacy `weights` override into
	 * `coreWeights`/`protectiveWeights` — themselves also unread by the scan path (see below).
	 * Retained because `ScoringConfig` is a published npm surface. Set `profileWeights` instead.
	 */
	weights: Record<CheckCategory, number>;

	/** Per-profile importance weights. */
	profileWeights: Record<DomainProfile, Record<CheckCategory, number>>;

	/** Tier budget split — percentage of the total score allocated to each tier. Must sum to 100. */
	tierSplit: { core: number; protective: number; hardening: number };

	/**
	 * Importance weights for core-tier categories (SPF, DMARC, DKIM, DNSSEC, SSL).
	 *
	 * @deprecated NOT read by any bv-mcp scan path. `buildGenericContext` (engine.ts) consults
	 * this ONLY in its `context === undefined` branch, and every scan supplies a real
	 * `DomainContext` — so a `SCORING_CONFIG` that sets `coreWeights` silently changes nothing.
	 * Set the matching per-profile entries in {@link ScoringConfig.profileWeights} instead;
	 * `parseScoringConfig` warns when a config sets only unread keys. Retained for the
	 * published-surface contract and for direct `computeScanScore(results)` callers that pass
	 * no context.
	 */
	coreWeights: Record<string, number>;

	/**
	 * Importance weights for protective-tier categories.
	 *
	 * @deprecated NOT read by any bv-mcp scan path — same `context === undefined` caveat as
	 * {@link ScoringConfig.coreWeights}. Use {@link ScoringConfig.profileWeights}.
	 */
	protectiveWeights: Record<string, number>;

	/**
	 * Per-provider DKIM confidence factors (0–1).
	 *
	 * @deprecated NOT read at runtime, anywhere. Parsed, clamped and returned by
	 * {@link parseScoringConfig}, then never consulted — DKIM provider confidence reaches the
	 * scorer as `finding.metadata.providerConfidence`, emitted by the DKIM check itself, not
	 * from config. Retained because `ScoringConfig` is a published npm surface.
	 */
	providerDkimConfidence: Record<string, number>;

	/** Scoring thresholds and constants. */
	thresholds: {
		/** @deprecated Use emailBonusFull, emailBonusMid, emailBonusPartial */
		emailBonusImportance: number;
		emailBonusFull: number;
		emailBonusMid: number;
		emailBonusPartial: number;
		spfStrongThreshold: number;
		criticalOverallPenalty: number;
		criticalGapCeiling: number;
		/**
		 * Minimum fraction of attempted checks that must COMPLETE for a scan to be
		 * graded at all (0–1). Not a scoring cut-point: it never changes what a grade
		 * means, only whether one is emitted. Clamped to [0, 1] on parse.
		 */
		evidenceSufficiency: number;
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
	};

	/** Baseline failure rates for adaptive weight computation. */
	baselineFailureRates: Record<string, number>;
}

/**
 * Flatten an `{ importance: number }` weight table to plain numbers.
 *
 * The inverse of {@link toImportanceRecord}. Module-private on purpose: it exists to let the
 * config DERIVE its profile weights from the single weight source rather than restate them,
 * and adding it to the published surface would invite exactly the parallel-table pattern this
 * removes.
 */
function toFlatWeightRecord<K extends string>(weights: Record<K, { importance: number }>): Record<K, number> {
	const result = {} as Record<K, number>;
	for (const key of Object.keys(weights) as K[]) {
		result[key] = weights[key].importance;
	}
	return result;
}

/**
 * Derive the config's default `profileWeights` from {@link PROFILE_WEIGHTS} — the SINGLE
 * source of profile weight values.
 *
 * These 324 numbers used to be restated here as literals and hand-synced with
 * `scoring/profiles.ts`, guarded only by a value-comparison test. A duplicated weight table is
 * a live score-divergence hazard: `getProfileWeights(profile, config)` reads the CONFIG copy
 * while `getProfileWeights(profile)` and `detectDomainContext` read the PROFILES copy, so a
 * one-sided edit makes a domain's score depend on which call site reached it. Deriving makes
 * that class of drift unrepresentable. Values are identical to the former literals; the
 * `scoring-profile-weights-ssot` audit fails if literals reappear here.
 */
function deriveDefaultProfileWeights(): Record<DomainProfile, Record<CheckCategory, number>> {
	const result = {} as Record<DomainProfile, Record<CheckCategory, number>>;
	for (const profile of Object.keys(PROFILE_WEIGHTS) as DomainProfile[]) {
		result[profile] = toFlatWeightRecord(PROFILE_WEIGHTS[profile]);
	}
	return result;
}

/** Built-in defaults — used when `SCORING_CONFIG` env var is absent or partial. */
export const DEFAULT_SCORING_CONFIG: ScoringConfig = {
	weights: {
		spf: 10,
		dmarc: 16,
		dkim: 10,
		dnssec: 10,
		ssl: 8,
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
		http_security: 3,
		dane: 1,
		ptr: 1,
		mx_reputation: 0,
		srv: 0,
		zone_hygiene: 0,
		dane_https: 2,
		svcb_https: 1,
		subdomailing: 3,
		brand_discovery: 0,
		authoritative_dns_infra: 0,
		dnskey_strength: 1,
	},
	profileWeights: deriveDefaultProfileWeights(),
	tierSplit: { core: 70, protective: 20, hardening: 10 },
	coreWeights: { dmarc: 16, dkim: 10, spf: 10, dnssec: 10, ssl: 8, authoritative_dns_infra: 0 },
	protectiveWeights: {
		subdomain_takeover: 4, http_security: 3, mta_sts: 3, subdomailing: 3, mx: 2,
		caa: 2, ns: 2, lookalikes: 2, shadow_domains: 2,
	},
	providerDkimConfidence: {
		amazonses: 0.8, sendgrid: 0.8, mailgun: 0.8, postmark: 0.8,
		google: 0.9, microsoft365: 0.9, proofpoint: 0.6, mimecast: 0.6,
		cloudflare: 0.9, // Cloudflare Email Routing
	},
	thresholds: {
		emailBonusImportance: 8,
		emailBonusFull: 5,
		emailBonusMid: 3,
		emailBonusPartial: 2,
		spfStrongThreshold: 57,
		criticalOverallPenalty: 15,
		criticalGapCeiling: 64,
		evidenceSufficiency: EVIDENCE_SUFFICIENCY_THRESHOLD,
	},
	grades: {
		aPlus: 92,
		a: 87,
		bPlus: 82,
		b: 76,
		cPlus: 70,
		c: 63,
		dPlus: 56,
		d: 50,
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
		http_security: 0.35,
		dane: 0.90,
		ptr: 0.90,
		mx_reputation: 0.00,
		srv: 0.00,
		zone_hygiene: 0.00,
		dane_https: 0.95,
		svcb_https: 0.85,
		subdomailing: 0.15,
		brand_discovery: 0.00,
		authoritative_dns_infra: 0.00,
		dnskey_strength: 0.80,
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
 * `SCORING_CONFIG` keys that NO profile-aware scan reads.
 *
 * Every bv-mcp scan builds a real `DomainContext` before scoring, and
 * `buildGenericContext` (engine.ts) then takes its weights from
 * `context.weights` — i.e. from `profileWeights` via `getProfileWeights`. Its
 * `config.coreWeights` / `config.protectiveWeights` branch is the
 * `context === undefined` fallback, which no scan path reaches.
 * `weights` only feeds the legacy migration INTO those same two unread keys, and
 * `providerDkimConfidence` is parsed, clamped, returned and then never consulted
 * (DKIM provider confidence arrives as `finding.metadata.providerConfidence`).
 *
 * So an operator override built from any of these is inert — which is not a
 * theoretical concern: production ran a live `SCORING_CONFIG` setting only
 * `coreWeights` and it had been changing nothing, undetectably, because the
 * parse succeeded and the returned config really did carry the new numbers.
 * A config that parses cleanly and then does nothing is the worst possible
 * failure mode, so name it out loud.
 */
const NO_OP_SCORING_CONFIG_KEYS = ['coreWeights', 'protectiveWeights', 'weights', 'providerDkimConfidence'] as const;

/** The key an operator reaching for any {@link NO_OP_SCORING_CONFIG_KEYS} entry almost certainly wanted. */
const EFFECTIVE_WEIGHT_KEY = 'profileWeights';

/** Optional hooks for {@link parseScoringConfig}. */
export interface ParseScoringConfigOptions {
	/**
	 * Sink for the inert-key warning. Defaults to `console.warn`.
	 *
	 * Injectable so a host can route it into its own structured logger (and so tests can
	 * assert on it), NOT so it can be disabled — passing a no-op restores exactly the
	 * silence this warning exists to end.
	 */
	onWarn?: (message: string) => void;
}

/**
 * Warn when a parsed config sets keys that no profile-aware scan will ever read.
 *
 * ADVISORY ONLY — never throws and never changes what the config resolves to. Config
 * handling in this codebase is fail-open by doctrine: a bad `SCORING_CONFIG` must degrade
 * to defaults, never take the scanner down. The point is to make an inert override
 * *visible*, not to reject it.
 */
function warnOnInertConfigKeys(parsed: Record<string, unknown>, onWarn: ((message: string) => void) | undefined): void {
	const inert = NO_OP_SCORING_CONFIG_KEYS.filter((key) => parsed[key] !== undefined && typeof parsed[key] === 'object');
	if (inert.length === 0) return;

	const emit = onWarn ?? (typeof console !== 'undefined' ? console.warn.bind(console) : undefined);
	if (!emit) return;

	const keyList = inert.join(', ');
	const plural = inert.length > 1 ? 's' : '';
	emit(
		`[dns-checks] SCORING_CONFIG sets ${keyList} — key${plural} that no profile-aware scan reads, ` +
			`so this override changes no score. Set \`${EFFECTIVE_WEIGHT_KEY}.<profile>.<category>\` instead ` +
			`(all 6 profiles: mail_enabled, enterprise_mail, non_mail, web_only, minimal, authoritative_dns_infra). ` +
			`The parsed config still carries the value${plural} verbatim; only direct context-less ` +
			`computeScanScore(results) callers consume coreWeights/protectiveWeights.`,
	);
}

/**
 * Parse a `SCORING_CONFIG` env var string into a fully-populated `ScoringConfig`.
 *
 * Gracefully handles undefined, empty, invalid JSON, partial overrides,
 * and invalid value types. Always returns a complete config by merging
 * overrides into defaults.
 *
 * Provides legacy migration:
 * - `weights` without `coreWeights` → partitions into core/protective via CATEGORY_TIERS
 * - `thresholds.emailBonusImportance` without `emailBonusFull` → derives three-tier bonus fields
 * - `tierSplit` not summing to 100 → falls back to default tierSplit
 * - `grades.e` → silently ignored (E grade removed in scoring v2)
 *
 * Emits an advisory warning (see {@link warnOnInertConfigKeys}) when the config sets keys
 * the scan path never reads. The warning does not change the returned config.
 */
export function parseScoringConfig(raw: string | undefined, options?: ParseScoringConfigOptions): ScoringConfig {
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

	// Advisory only — must run before any early return path below can hide it, and must not
	// influence the parse result in any way.
	warnOnInertConfigKeys(parsed, options?.onWarn);

	// Merge weights
	const rawWeightsObj = parsed.weights as Record<string, unknown> | undefined;
	const weights = mergeWeights(DEFAULT_SCORING_CONFIG.weights, rawWeightsObj) as Record<CheckCategory, number>;

	// Merge profile weights
	const profileWeights = { ...DEFAULT_SCORING_CONFIG.profileWeights } as Record<DomainProfile, Record<CheckCategory, number>>;
	const rawProfileWeights = parsed.profileWeights as Record<string, Record<string, unknown>> | undefined;
	if (rawProfileWeights && typeof rawProfileWeights === 'object') {
		for (const profile of Object.keys(DEFAULT_SCORING_CONFIG.profileWeights) as DomainProfile[]) {
			if (profile in rawProfileWeights) {
				profileWeights[profile] = mergeWeights(DEFAULT_SCORING_CONFIG.profileWeights[profile], rawProfileWeights[profile]) as Record<
					CheckCategory,
					number
				>;
			}
		}
	}

	// --- Tier split ---
	let tierSplit = { ...DEFAULT_SCORING_CONFIG.tierSplit };
	const rawTierSplit = parsed.tierSplit as Record<string, unknown> | undefined;
	if (rawTierSplit && typeof rawTierSplit === 'object') {
		const c = rawTierSplit.core;
		const p = rawTierSplit.protective;
		const h = rawTierSplit.hardening;
		if (typeof c === 'number' && typeof p === 'number' && typeof h === 'number' && Number.isFinite(c + p + h)) {
			if (c + p + h === 100) {
				tierSplit = { core: c, protective: p, hardening: h };
			}
			// Sum != 100 → fall back to default (validation rejection)
		}
	}

	// --- Core/Protective weights with legacy migration ---
	let coreWeights: Record<string, number>;
	let protectiveWeights: Record<string, number>;

	if (parsed.coreWeights && typeof parsed.coreWeights === 'object') {
		coreWeights = mergeWeights(DEFAULT_SCORING_CONFIG.coreWeights, parsed.coreWeights as Record<string, unknown>);
	} else if (rawWeightsObj && typeof rawWeightsObj === 'object') {
		// Legacy migration: partition weights into core/protective via CATEGORY_TIERS
		const migrated = { ...DEFAULT_SCORING_CONFIG.coreWeights };
		for (const [key, value] of Object.entries(rawWeightsObj)) {
			if (typeof value === 'number' && Number.isFinite(value) && key in CATEGORY_TIERS) {
				const tier = CATEGORY_TIERS[key as CheckCategory];
				if (tier === 'core') {
					migrated[key] = Math.max(0, value);
				}
			}
		}
		coreWeights = migrated;
	} else {
		coreWeights = { ...DEFAULT_SCORING_CONFIG.coreWeights };
	}

	if (parsed.protectiveWeights && typeof parsed.protectiveWeights === 'object') {
		protectiveWeights = mergeWeights(DEFAULT_SCORING_CONFIG.protectiveWeights, parsed.protectiveWeights as Record<string, unknown>);
	} else if (rawWeightsObj && typeof rawWeightsObj === 'object') {
		// Legacy migration: partition weights into core/protective via CATEGORY_TIERS
		const migrated = { ...DEFAULT_SCORING_CONFIG.protectiveWeights };
		for (const [key, value] of Object.entries(rawWeightsObj)) {
			if (typeof value === 'number' && Number.isFinite(value) && key in CATEGORY_TIERS) {
				const tier = CATEGORY_TIERS[key as CheckCategory];
				if (tier === 'protective') {
					migrated[key] = Math.max(0, value);
				}
			}
		}
		protectiveWeights = migrated;
	} else {
		protectiveWeights = { ...DEFAULT_SCORING_CONFIG.protectiveWeights };
	}

	// --- Provider DKIM confidence ---
	const providerDkimConfidence = { ...DEFAULT_SCORING_CONFIG.providerDkimConfidence };
	const rawProviderDkim = parsed.providerDkimConfidence as Record<string, unknown> | undefined;
	if (rawProviderDkim && typeof rawProviderDkim === 'object') {
		for (const [key, value] of Object.entries(rawProviderDkim)) {
			if (typeof value === 'number' && Number.isFinite(value)) {
				providerDkimConfidence[key] = Math.max(0, Math.min(1, value));
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

		// Legacy migration: emailBonusImportance → three-tier bonus fields
		if (
			'emailBonusImportance' in rawThresholds &&
			typeof rawThresholds.emailBonusImportance === 'number' &&
			!('emailBonusFull' in rawThresholds)
		) {
			const v = rawThresholds.emailBonusImportance;
			thresholds.emailBonusFull = v;
			thresholds.emailBonusMid = Math.ceil(v * 0.6);
			thresholds.emailBonusPartial = Math.ceil(v * 0.4);
		}
	}

	// A fraction, not a percentage. Clamp so a `60`-for-60% typo in SCORING_CONFIG
	// cannot ungrade every scan in the fleet.
	thresholds.evidenceSufficiency = Math.max(0, Math.min(1, thresholds.evidenceSufficiency));

	// Merge grades — silently ignore legacy 'e' grade
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

	return {
		weights,
		profileWeights,
		tierSplit,
		coreWeights,
		protectiveWeights,
		providerDkimConfidence,
		thresholds,
		grades,
		baselineFailureRates,
	};
}
