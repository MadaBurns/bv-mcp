// SPDX-License-Identifier: BUSL-1.1

/**
 * Adaptive weight computation for context-aware scoring.
 *
 * Uses exponential moving averages (EMA) of per-category failure rates,
 * collected by the ProfileAccumulator Durable Object, to adjust static
 * importance weights at scoring time. A maturity-gated blend ensures
 * weights stay close to static until enough telemetry has accumulated.
 */

import type { CheckCategory } from './scoring-model';
import type { DomainProfile } from './context-profiles';
import { PROFILE_WEIGHTS } from './context-profiles';

// ─── Telemetry interfaces ──────────────────────────────────────────────

/** A single scan's telemetry payload sent to the ProfileAccumulator DO. */
export interface ScanTelemetry {
	profile: string;
	provider: string | null;
	categoryFindings: Array<{ category: string; score: number; passed: boolean }>;
	timestamp: number;
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

/** Expected failure rate per category across all domains (prior). */
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

/** Pre-computed bounds for every profile × category combination. */
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
 * Falls back to the static profile weight for any category not present in the
 * DO response. Returns `null` if any value is non-finite or negative.
 */
export function adaptiveWeightsToContext(
	doWeights: Record<string, number>,
	profile: DomainProfile,
): Record<CheckCategory, { importance: number }> | null {
	const staticWeights = PROFILE_WEIGHTS[profile];
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
 * Generate a human-readable note explaining adaptive weight shifts.
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
		return `Several checks were weighted differently based on patterns seen across similar domains. The biggest shift was in ${topCat.toUpperCase()}.`;
	}

	const [topCat, topDelta] = significant[0];
	return formatNote(topCat, topDelta, provider);
}

/** Format a single-category scoring note. */
function formatNote(category: string, delta: number, provider: string | null): string {
	const cat = category.toUpperCase();

	if (delta > 0 && provider) {
		const providerDisplay = capitalizeWords(provider);
		return `${cat} carried more weight because domains using ${providerDisplay} frequently have issues in this area.`;
	}

	if (delta > 0) {
		return `${cat} carried more weight in this scan because it is a common issue across similar domains.`;
	}

	return `${cat} carried less weight because similar domains rarely have issues there.`;
}

/** Capitalize the first letter of each word. */
function capitalizeWords(s: string): string {
	return s.replace(/\b\w/g, (c) => c.toUpperCase());
}
