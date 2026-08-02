// SPDX-License-Identifier: BUSL-1.1

/**
 * Adaptive weight computation for context-aware scoring.
 *
 * Uses exponential moving averages (EMA) of per-category failure rates,
 * collected by the ProfileAccumulator Durable Object, to adjust static
 * importance weights at scoring time. A maturity-gated blend ensures
 * weights stay close to static until enough telemetry has accumulated.
 */

import type { CheckCategory } from '@blackveil/dns-checks/scoring';
import type { DomainProfile } from '@blackveil/dns-checks/scoring';
import { DEFAULT_SCORING_CONFIG, PROFILE_WEIGHTS, getProfileWeights } from '@blackveil/dns-checks/scoring';
import type { ScoringConfig } from '@blackveil/dns-checks/scoring';
import { parseScoringConfigCached } from './scoring-config';

// ─── Telemetry interfaces ──────────────────────────────────────────────

/** A single scan's telemetry payload sent to the ProfileAccumulator DO. */
export interface ScanTelemetry {
	profile: string;
	provider: string | null;
	categoryFindings: Array<{ category: string; score: number; passed: boolean }>;
	timestamp: number;
	/** Overall scan score (0–100). Used for intelligence layer aggregation (histogram, cohort, trends). */
	overallScore?: number;
}

/** Response from the adaptive weights endpoint. */
export interface AdaptiveWeightsResponse {
	profile: string;
	provider: string | null;
	sampleCount: number;
	blendFactor: number;
	weights: Record<string, number>;
	boundHits: string[];
}

/** Min/max bounds for an adaptive weight value. */
export interface WeightBound {
	min: number;
	max: number;
}

// ─── Constants ─────────────────────────────────────────────────────────

/** How aggressively deviation from baseline adjusts the weight (0–1). */
export const SENSITIVITY = 0.5;

/** Sample count at which blending reaches 100% adaptive. */
export const MATURITY_THRESHOLD = 200;

/** EMA span (number of recent observations the average reflects). */
export const EMA_SPAN = 200;

/** EMA smoothing factor derived from span. */
export const EMA_ALPHA = 2 / (EMA_SPAN + 1);

/** Minimum |scoreDelta| before a scoring note is generated. */
export const SCORING_NOTE_DELTA_THRESHOLD = 3;

/**
 * Expected failure rate per category across all domains (prior) — the WORKER-SIDE
 * source of truth for the adaptive-weight baseline.
 *
 * This is the single place the worker states these numbers. `ProfileAccumulator`
 * reads it through {@link resolveBaselineFailureRates} (never a private copy), and
 * `test/adaptive-weights.spec.ts` asserts the SHAPE of this object rather than
 * restating its literals — a third copy of the table is exactly what let the
 * scoring-config key drift out of the loop unnoticed.
 *
 * Deliberately a SUBSET of `DEFAULT_SCORING_CONFIG.baselineFailureRates` (the
 * package's 28-category table): only these 13 categories have a calibrated prior,
 * and every other category falls through to `0` at the call site. Keeping the
 * subset (rather than adopting the package's full table wholesale) is what makes
 * {@link resolveBaselineFailureRates} exactly behaviour-neutral when no
 * `SCORING_CONFIG` override is set.
 */
export const BASELINE_FAILURE_RATES: Record<string, number> = {
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
};

/**
 * Resolve the EFFECTIVE adaptive-weight baseline for a raw `SCORING_CONFIG` value.
 *
 * Before this existed, `DEFAULT_SCORING_CONFIG.baselineFailureRates` — and therefore
 * the `SCORING_CONFIG.baselineFailureRates` override key — was **inert**: the
 * accumulator read {@link BASELINE_FAILURE_RATES} directly, so an operator could set
 * the key and nothing anywhere would consume it. This makes the key live while
 * keeping the un-overridden path byte-identical to the previous behaviour:
 *
 * - No `SCORING_CONFIG`, unparseable config, or a config that does not move any
 *   baseline off the package default → returns the {@link BASELINE_FAILURE_RATES}
 *   object itself (same 13 keys, same values, same identity).
 * - A config that DOES move a baseline → returns a copy of
 *   {@link BASELINE_FAILURE_RATES} with only the moved categories overlaid.
 *
 * Only entries that DIFFER from the package default are overlaid, deliberately: the
 * parsed config is always fully populated (`parseScoringConfig` merges onto the
 * package's 28-category defaults), so copying it wholesale would silently introduce
 * priors for 15 categories that today resolve to `0` — a behaviour change nobody
 * asked for. Adaptive weights never reach a reported score (see `scanDomain`), so
 * this is confined to `scoringNote` / `adaptiveWeightDeltas` either way.
 */
export function resolveBaselineFailureRates(rawScoringConfig?: string): Record<string, number> {
	if (!rawScoringConfig) return BASELINE_FAILURE_RATES;

	let configured: Record<string, number>;
	try {
		configured = parseScoringConfigCached(rawScoringConfig).baselineFailureRates;
	} catch {
		// Fail-soft: a malformed override must never disarm the adaptive baseline.
		return BASELINE_FAILURE_RATES;
	}

	const packageDefaults = DEFAULT_SCORING_CONFIG.baselineFailureRates;
	let overlaid: Record<string, number> | null = null;

	for (const [category, rate] of Object.entries(configured)) {
		if (typeof rate !== 'number' || !isFinite(rate) || rate < 0) continue;
		if (rate === packageDefaults[category]) continue;
		overlaid ??= { ...BASELINE_FAILURE_RATES };
		overlaid[category] = rate;
	}

	return overlaid ?? BASELINE_FAILURE_RATES;
}

// ─── Weight bounds ─────────────────────────────────────────────────────

/** Categories treated as "critical mail" for bound computation in mail-centric profiles. */
const CRITICAL_MAIL_CATEGORIES = new Set<string>(['dmarc', 'spf', 'dkim', 'ssl']);

/** Profiles where critical-mail floor applies. */
const CRITICAL_MAIL_PROFILES = new Set<string>(['mail_enabled', 'enterprise_mail']);

/**
 * Compute default min/max bounds for an adaptive weight.
 *
 * Critical-mail categories get a higher floor (min 5) to prevent
 * important email-auth checks from being zeroed out.
 */
export function defaultBounds(staticWeight: number, isCriticalMail: boolean): WeightBound {
	const minFloor = isCriticalMail ? 5 : 0;
	return {
		min: Math.max(minFloor, Math.floor(staticWeight * 0.5)),
		max: Math.ceil(staticWeight * 2) + 3,
	};
}

/**
 * Pre-computed bounds for every profile × category combination.
 *
 * KNOWN LIMITATION (not fixed here): these bounds — and the accumulator's own static
 * blend base — come from the RAW `PROFILE_WEIGHTS` table, not from
 * `getProfileWeights(profile, config)`. With no `profileWeights` override the two are
 * numerically identical (`DEFAULT_SCORING_CONFIG.profileWeights` is DERIVED from
 * `PROFILE_WEIGHTS` via `deriveDefaultProfileWeights()`), so today this is inert. Under
 * a live `profileWeights` override it is not: the adaptive blend would be anchored to
 * the un-overridden weights. Making it config-aware means threading the effective
 * config into the ProfileAccumulator DO and changing the adaptive weight VALUES it
 * returns — a behaviour change, so it is recorded rather than silently made. Adaptive
 * output never reaches a reported score, so the blast radius is `scoringNote` /
 * `adaptiveWeightDeltas`.
 */
export const WEIGHT_BOUNDS: Record<DomainProfile, Record<CheckCategory, WeightBound>> = (() => {
	const profiles = Object.keys(PROFILE_WEIGHTS) as DomainProfile[];
	const result = {} as Record<DomainProfile, Record<CheckCategory, WeightBound>>;

	for (const profile of profiles) {
		const weights = PROFILE_WEIGHTS[profile];
		const categories = Object.keys(weights) as CheckCategory[];
		const profileBounds = {} as Record<CheckCategory, WeightBound>;

		for (const cat of categories) {
			const isCritical = CRITICAL_MAIL_PROFILES.has(profile) && CRITICAL_MAIL_CATEGORIES.has(cat);
			profileBounds[cat] = defaultBounds(weights[cat].importance, isCritical);
		}

		result[profile] = profileBounds;
	}

	return result;
})();

// ─── Computation functions ─────────────────────────────────────────────

/**
 * Compute a single adaptive weight from EMA failure rate and baseline.
 *
 * @returns The clamped weight and whether a bound was hit ('min' | 'max' | null).
 */
export function computeAdaptiveWeight(params: {
	staticWeight: number;
	emaFailureRate: number;
	baselineFailureRate: number;
	bounds: WeightBound;
}): { weight: number; boundHit: 'min' | 'max' | null } {
	const { staticWeight, emaFailureRate, baselineFailureRate, bounds } = params;

	const deviation = emaFailureRate - baselineFailureRate;
	const rawAdjustment = deviation * SENSITIVITY * staticWeight;
	const adaptive = staticWeight + rawAdjustment;
	const clamped = Math.max(bounds.min, Math.min(bounds.max, adaptive));

	let boundHit: 'min' | 'max' | null = null;
	if (clamped <= bounds.min && adaptive < bounds.min) {
		boundHit = 'min';
	} else if (clamped >= bounds.max && adaptive > bounds.max) {
		boundHit = 'max';
	}

	return { weight: clamped, boundHit };
}

/**
 * Blend static and adaptive weights based on sample maturity.
 *
 * Returns `(1 - blendFactor) * staticWeight + blendFactor * adaptiveWeight`
 * where `blendFactor = min(1.0, sampleCount / MATURITY_THRESHOLD)`.
 */
export function blendWeights(staticWeight: number, adaptiveWeight: number, sampleCount: number): number {
	const blendFactor = Math.min(1.0, sampleCount / MATURITY_THRESHOLD);
	return (1 - blendFactor) * staticWeight + blendFactor * adaptiveWeight;
}

// ─── Type adapter ──────────────────────────────────────────────────────

/**
 * Convert a DO-returned weight map to a CheckCategory-keyed importance record.
 *
 * Falls back to the profile's static weight for any category not present in the
 * DO response. Returns `null` if any value is non-finite or negative.
 *
 * `config` MUST be the same effective `ScoringConfig` the caller uses to compute the
 * static comparison side of `adaptiveWeightDeltas` (`scan-domain.ts` passes
 * `runtimeOptions.scoringConfig`). Before it was threaded, this fallback read the raw
 * `PROFILE_WEIGHTS` table while the delta's other operand came from
 * `getProfileWeights(profile, config)` — under a live `profileWeights` override the two
 * bases disagreed, so every category the accumulator had NO data for reported a
 * non-zero "adaptive" delta that no adaptation produced, and the customer-visible
 * `scoringNote` could fire off it. Omitting `config` reproduces the old raw-table
 * behaviour and is correct only when the caller also compares against the raw table.
 *
 * NOTE: this closes the CALLER-side half only. The accumulator still computes its
 * blend (and `WEIGHT_BOUNDS`) from the raw `PROFILE_WEIGHTS`, so a category the DO DID
 * return still carries an override-skewed base. See the module note on `WEIGHT_BOUNDS`.
 */
export function adaptiveWeightsToContext(
	doWeights: Record<string, number>,
	profile: DomainProfile,
	config?: ScoringConfig,
): Record<CheckCategory, { importance: number }> | null {
	const staticWeights = getProfileWeights(profile, config);
	const categories = Object.keys(staticWeights) as CheckCategory[];
	const result = {} as Record<CheckCategory, { importance: number }>;

	for (const cat of categories) {
		const value = cat in doWeights ? doWeights[cat] : staticWeights[cat].importance;
		if (!isFinite(value) || value < 0) {
			return null;
		}
		result[cat] = { importance: value };
	}

	return result;
}

// ─── Scoring note generation ───────────────────────────────────────────

/**
 * Generate a human-readable note describing observed peer patterns.
 *
 * IMPORTANT: adaptive weighting is **telemetry-only and does NOT affect the
 * returned scan score** — the score is always computed from static profile
 * weights (see `scanDomain` in `src/tools/scan-domain.ts`). These notes must
 * therefore describe what was *observed* across similar domains and be framed
 * as a non-scoring, experimental signal. They must never claim or imply the
 * returned score was reweighted, shifted, or adjusted.
 *
 * Returns `null` if the absolute score delta is below the threshold.
 */
export function generateScoringNote(
	weightDeltas: Record<string, number>,
	scoreDelta: number,
	provider: string | null,
): string | null {
	if (Math.abs(scoreDelta) < SCORING_NOTE_DELTA_THRESHOLD) {
		return null;
	}

	// Collect significant deltas (|delta| >= 2) sorted by magnitude descending
	const significant = Object.entries(weightDeltas)
		.filter(([, d]) => Math.abs(d) >= 2)
		.sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));

	if (significant.length === 0) {
		// No individually significant deltas but overall threshold met — use the largest anyway
		const all = Object.entries(weightDeltas).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
		if (all.length === 0) return null;
		const [topCat, topDelta] = all[0];
		return formatNote(topCat, topDelta, provider);
	}

	if (significant.length >= 3) {
		const [topCat] = significant[0];
		return `${EXPERIMENTAL_PREFIX} similar domains show divergent patterns across several checks, most notably ${topCat.toUpperCase()}. ${NON_SCORING_SUFFIX}`;
	}

	const [topCat, topDelta] = significant[0];
	return formatNote(topCat, topDelta, provider);
}

/** Prefix marking the note as an experimental, non-scoring observation. */
const EXPERIMENTAL_PREFIX = 'Experimental signal:';

/** Suffix making the non-scoring nature of the note explicit to consumers. */
const NON_SCORING_SUFFIX = 'This observation did not affect this scan’s score.';

/** Format a single-category scoring note. */
function formatNote(category: string, delta: number, provider: string | null): string {
	const cat = category.toUpperCase();

	if (delta > 0 && provider) {
		const providerDisplay = capitalizeWords(provider);
		return `${EXPERIMENTAL_PREFIX} domains using ${providerDisplay} frequently show ${cat} issues. ${NON_SCORING_SUFFIX}`;
	}

	if (delta > 0) {
		return `${EXPERIMENTAL_PREFIX} ${cat} issues are common across similar domains. ${NON_SCORING_SUFFIX}`;
	}

	return `${EXPERIMENTAL_PREFIX} similar domains rarely show ${cat} issues. ${NON_SCORING_SUFFIX}`;
}

/** Capitalize the first letter of each word. */
function capitalizeWords(s: string): string {
	return s.replace(/\b\w/g, (c) => c.toUpperCase());
}
