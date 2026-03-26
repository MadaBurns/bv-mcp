// SPDX-License-Identifier: BUSL-1.1

/**
 * Generic scoring engine for @blackveil/dns-checks
 *
 * Accepts string keys (not concrete `CheckCategory`) so any consumer can plug in
 * their own check vocabulary. The existing `computeScanScore` (which uses `CheckResult[]`
 * and `CheckCategory`) will later become a wrapper around this function.
 *
 * Three-tier formula:
 * - **Core** (default 70 pts): Weighted accumulation. `missingControls[key]=true` zeros the contribution.
 * - **Protective** (default 20 pts): Weighted accumulation. No missing control zeroing.
 * - **Hardening** (default 10 pts): Binary pass/fail from `hardeningPassed` map. Only submitted keys count.
 * - **Email bonus**: +5/+3/+2 based on DMARC quality (configurable keys).
 * - **Provider modifier**: Average of providerConfidence values, centered at 0.5, scaled to -5..+5.
 * - **Critical penalty**: -15 if findingSeverityCounts.critical > 0.
 * - **Critical gap ceiling**: If any criticalCategories key has missingControls=true, cap at 64.
 */

import type { CategoryTier } from '../types';
import type { ScoringConfig } from './config';
import { DEFAULT_SCORING_CONFIG } from './config';
import { scoreToGrade } from './engine';

/** Finding severity counts for summary generation and critical penalty. */
export interface FindingSeverityCounts {
	critical: number;
	high: number;
	medium: number;
	low: number;
	info: number;
}

/** Mapping of the three email-related keys to arbitrary category key names. */
export interface EmailBonusKeyMap {
	spf: string;
	dkim: string;
	dmarc: string;
}

/**
 * Generic scoring context — all inputs needed to compute a score.
 * Keys are arbitrary strings, not tied to `CheckCategory`.
 */
export interface GenericScoringContext {
	/** Category key → score (0–100). Absent keys default to 100. */
	categoryScores: Record<string, number>;

	/** Category key → tier classification. Only keys present here participate in scoring. */
	tierMap: Record<string, CategoryTier>;

	/** Category key → importance weight. Must cover all keys in tierMap. */
	weights: Record<string, number>;

	/** Category keys that trigger the critical gap ceiling when missing. */
	criticalCategories: string[];

	/** Whether this context is eligible for the email bonus. */
	emailBonusEligible: boolean;

	/** Category key → true if the control is fundamentally missing (deterministic/verified). */
	missingControls: Record<string, boolean>;

	/** Hardening category key → true if passed. Only submitted keys count. */
	hardeningPassed: Record<string, boolean>;

	/** Category key → true if the check suffered a transient failure (excluded from scoring). */
	transientFailures?: Record<string, boolean>;

	/** Override default email bonus keys (spf/dkim/dmarc) with custom category key names. */
	emailBonusKeys?: EmailBonusKeyMap;

	/** Category key → provider confidence (0–1). Averaged, centered at 0.5, scaled to -5..+5. */
	providerConfidence?: Record<string, number>;

	/** Severity counts for summary generation and critical penalty. */
	findingSeverityCounts?: FindingSeverityCounts;
}

/** Tier breakdown showing earned points per tier. */
export interface TierBreakdown {
	core: number;
	protective: number;
	hardening: number;
}

/** Result of the generic scoring computation. */
export interface GenericScanScore {
	/** Overall score (0–100). */
	overall: number;

	/** Letter grade (A+ through F). */
	grade: string;

	/** Input category scores echoed back (with absent defaults filled to 100). */
	categoryScores: Record<string, number>;

	/** Human-readable summary. */
	summary: string;

	/** Points earned per tier. */
	tierBreakdown: TierBreakdown;

	/** Email bonus points added (0, 2, 3, or 5). */
	emailBonus: number;

	/** Category keys that triggered the critical gap ceiling. */
	criticalGaps: string[];

	/** Provider confidence modifier applied (-5 to +5). */
	providerModifier: number;

	/** Critical penalty applied (0 or criticalOverallPenalty from config). */
	criticalPenalty: number;
}

const DEFAULT_EMAIL_BONUS_KEYS: EmailBonusKeyMap = {
	spf: 'spf',
	dkim: 'dkim',
	dmarc: 'dmarc',
};

function clampPercent(score: number): number {
	return Math.max(0, Math.min(100, score));
}

function computeProviderModifier(providerConfidence: Record<string, number> | undefined): number {
	if (!providerConfidence) return 0;

	const values = Object.values(providerConfidence).filter(
		(v) => typeof v === 'number' && Number.isFinite(v),
	);
	if (values.length === 0) return 0;

	const clamped = values.map((v) => Math.max(0, Math.min(1, v)));
	const avg = clamped.reduce((sum, v) => sum + v, 0) / clamped.length;
	const centered = avg - 0.5;
	return Math.round(centered * 10);
}

/**
 * Compute a score using the three-tier formula with arbitrary string keys.
 *
 * @param input - Scoring context with category scores, tier map, weights, etc.
 * @param config - Optional scoring config override (defaults to DEFAULT_SCORING_CONFIG).
 * @returns A GenericScanScore with overall score, grade, breakdown, and metadata.
 */
export function computeGenericScore(input: GenericScoringContext, config?: ScoringConfig): GenericScanScore {
	const cfg = config ?? DEFAULT_SCORING_CONFIG;
	const tierSplit = cfg.tierSplit;
	const thresholds = cfg.thresholds;

	const transient = input.transientFailures ?? {};
	const emailKeys = input.emailBonusKeys ?? DEFAULT_EMAIL_BONUS_KEYS;

	// --- Partition weights by tier, excluding transient failures ---
	const coreWeights: Record<string, number> = {};
	const protectiveWeights: Record<string, number> = {};
	const hardeningKeys: string[] = [];

	for (const [key, tier] of Object.entries(input.tierMap)) {
		if (transient[key]) continue;
		const weight = input.weights[key] ?? 0;
		if (tier === 'core') {
			coreWeights[key] = weight;
		} else if (tier === 'protective') {
			protectiveWeights[key] = weight;
		} else if (tier === 'hardening') {
			hardeningKeys.push(key);
		}
	}

	// --- Core tier accumulation ---
	const coreMax = Object.values(coreWeights).reduce((sum, w) => sum + w, 0);
	let coreEarned = 0;

	for (const [key, weight] of Object.entries(coreWeights)) {
		if (weight === 0) continue;
		const rawScore = clampPercent(input.categoryScores[key] ?? 100);
		const effectiveScore = input.missingControls[key] ? 0 : rawScore;
		coreEarned += (effectiveScore / 100) * weight;
	}

	const corePct = coreMax > 0 ? coreEarned / coreMax : 1;
	const corePoints = corePct * tierSplit.core;

	// --- Protective tier accumulation ---
	const protectiveMax = Object.values(protectiveWeights).reduce((sum, w) => sum + w, 0);
	let protectiveEarned = 0;

	for (const [key, weight] of Object.entries(protectiveWeights)) {
		if (weight === 0) continue;
		const rawScore = clampPercent(input.categoryScores[key] ?? 100);
		// Protective: NO missingControls zeroing
		protectiveEarned += (rawScore / 100) * weight;
	}

	const protectivePct = protectiveMax > 0 ? protectiveEarned / protectiveMax : 1;
	const protectivePoints = protectivePct * tierSplit.protective;

	// --- Hardening tier (binary pass/fail) ---
	// Only keys present in hardeningPassed count — absent hardening categories are ignored.
	const submittedHardeningKeys = hardeningKeys.filter((key) => key in input.hardeningPassed);
	const passedCount = submittedHardeningKeys.filter((key) => input.hardeningPassed[key]).length;
	const hardeningPoints = submittedHardeningKeys.length > 0
		? (passedCount / submittedHardeningKeys.length) * tierSplit.hardening
		: 0;

	// --- Base score ---
	const base = corePoints + protectivePoints + hardeningPoints;

	// --- Email bonus ---
	let emailBonus = 0;
	if (input.emailBonusEligible) {
		const spfKey = emailKeys.spf;
		const dkimKey = emailKeys.dkim;
		const dmarcKey = emailKeys.dmarc;

		const spfScore = input.categoryScores[spfKey] ?? 0;
		const spfStrong = !input.missingControls[spfKey] && spfScore >= thresholds.spfStrongThreshold;

		const dkimNotMissing = !input.missingControls[dkimKey];

		const dmarcScore = input.categoryScores[dmarcKey];
		const dmarcPresent = dmarcScore !== undefined && !input.missingControls[dmarcKey];

		if (spfStrong && dkimNotMissing && dmarcPresent) {
			if (dmarcScore >= 90) {
				emailBonus = thresholds.emailBonusFull;
			} else if (dmarcScore >= 70) {
				emailBonus = thresholds.emailBonusMid;
			} else {
				emailBonus = thresholds.emailBonusPartial;
			}
		}
	}

	// --- Provider confidence modifier ---
	const providerModifier = computeProviderModifier(input.providerConfidence);

	// --- Critical penalty ---
	const counts = input.findingSeverityCounts;
	const criticalPenalty = counts && counts.critical > 0 ? thresholds.criticalOverallPenalty : 0;

	// --- Assemble pre-ceiling score ---
	const preCeiling = clampPercent(Math.round(base) + emailBonus + providerModifier - criticalPenalty);

	// --- Critical gap ceiling ---
	const criticalGaps: string[] = [];
	for (const key of input.criticalCategories) {
		if (input.missingControls[key]) {
			criticalGaps.push(key);
		}
	}
	const overall = criticalGaps.length > 0
		? Math.min(preCeiling, thresholds.criticalGapCeiling)
		: preCeiling;

	// --- Grade ---
	const grade = scoreToGrade(overall, config);

	// --- Summary ---
	const summary = buildSummary(counts, grade);

	// --- Populate category scores with absent defaults ---
	const filledScores: Record<string, number> = {};
	for (const key of Object.keys(input.tierMap)) {
		filledScores[key] = input.categoryScores[key] ?? 100;
	}
	// Also include any explicitly-provided scores not in tierMap
	for (const key of Object.keys(input.categoryScores)) {
		if (!(key in filledScores)) {
			filledScores[key] = input.categoryScores[key];
		}
	}

	return {
		overall,
		grade,
		categoryScores: filledScores,
		summary,
		tierBreakdown: {
			core: corePoints,
			protective: protectivePoints,
			hardening: hardeningPoints,
		},
		emailBonus,
		criticalGaps,
		providerModifier,
		criticalPenalty,
	};
}

function buildSummary(counts: FindingSeverityCounts | undefined, grade: string): string {
	if (!counts) {
		const totalIssues = 0;
		if (totalIssues === 0) {
			return `Excellent! No security issues found. Grade: ${grade}`;
		}
	}

	if (counts) {
		const { critical, high, medium, low } = counts;
		const totalNonInfo = critical + high + medium + low;

		if (totalNonInfo === 0) {
			return `Excellent! No security issues found. Grade: ${grade}`;
		}
		if (critical > 0) {
			return `${critical} critical issue(s) found requiring immediate attention. Grade: ${grade}`;
		}
		if (high > 0) {
			return `${high} high-severity issue(s) found. Grade: ${grade}`;
		}
		return `${totalNonInfo} issue(s) found. Grade: ${grade}`;
	}

	return `Excellent! No security issues found. Grade: ${grade}`;
}
