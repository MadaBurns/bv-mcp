// SPDX-License-Identifier: BUSL-1.1

import {
	CATEGORY_DISPLAY_WEIGHTS,
	CATEGORY_TIERS,
	type CheckCategory,
	type CheckResult,
	type Finding,
	inferFindingConfidence,
	type ScanScore,
} from './scoring-model';
import type { DomainContext } from './context-profiles';
import { PROFILE_CRITICAL_CATEGORIES, PROFILE_EMAIL_BONUS_ELIGIBLE } from './context-profiles';
import type { ScoringConfig } from './scoring-config';
import { DEFAULT_SCORING_CONFIG } from './scoring-config';

interface ImportanceProfile {
	importance: number;
}

/**
 * Scanner-aligned importance weighting for the checks currently supported by this MCP server.
 * @deprecated Use CORE_WEIGHTS and PROTECTIVE_WEIGHTS for three-tier scoring. Retained for backward compatibility.
 */
export const IMPORTANCE_WEIGHTS: Record<CheckCategory, ImportanceProfile> = {
	spf: { importance: 10 },
	dmarc: { importance: 22 },
	dkim: { importance: 16 },
	dnssec: { importance: 2 },
	ssl: { importance: 5 },
	mta_sts: { importance: 2 },
	ns: { importance: 0 },
	caa: { importance: 0 },
	subdomain_takeover: { importance: 3 },
	mx: { importance: 2 },
	bimi: { importance: 0 },
	tlsrpt: { importance: 1 },
	lookalikes: { importance: 0 },
	shadow_domains: { importance: 0 },
	txt_hygiene: { importance: 0 },
	http_security: { importance: 3 },
	dane: { importance: 1 },
	mx_reputation: { importance: 0 },
	srv: { importance: 0 },
	zone_hygiene: { importance: 0 },
	dane_https: { importance: 2 },
	svcb_https: { importance: 1 },
};

/** Core-tier importance weights (SPF, DMARC, DKIM, DNSSEC, SSL). Used by the three-tier scoring formula. */
export const CORE_WEIGHTS: Record<string, number> = {
	dmarc: 22, dkim: 16, spf: 10, dnssec: 7, ssl: 5,
};

/** Protective-tier importance weights. Used by the three-tier scoring formula. */
export const PROTECTIVE_WEIGHTS: Record<string, number> = {
	subdomain_takeover: 4, http_security: 3, mta_sts: 3, mx: 2,
	caa: 2, ns: 2, lookalikes: 2, shadow_domains: 2,
};

/** Regex for detecting missing control patterns in finding text. */
const MISSING_CONTROL_REGEX = /(no\s+.+\s+record|missing|required|not\s+found)/i;

/**
 * Determine whether findings for a category indicate a fundamentally missing control.
 * Requires both a missing-control text pattern AND deterministic/verified confidence
 * to avoid false zeroing from heuristic checks (e.g., DKIM selector probing).
 */
function scoreIndicatesMissingControl(findings: Finding[]): boolean {
	return findings.some((f) => {
		const isMissingPattern = MISSING_CONTROL_REGEX.test(f.detail) || MISSING_CONTROL_REGEX.test(f.title);
		const confidence = (f.metadata?.confidence as string) ?? inferFindingConfidence(f);
		return isMissingPattern
			&& (f.severity === 'critical' || f.severity === 'high')
			&& (confidence === 'deterministic' || confidence === 'verified');
	});
}

function clampPercent(score: number): number {
	return Math.max(0, Math.min(100, score));
}

function computeProviderConfidenceModifier(findings: Finding[]): number {
	const confidences: number[] = [];

	for (const finding of findings) {
		const confidence = finding.metadata?.providerConfidence;
		if (typeof confidence === 'number' && Number.isFinite(confidence)) {
			confidences.push(Math.max(0, Math.min(1, confidence)));
		}
	}

	if (confidences.length === 0) return 0;

	const avgConfidence = confidences.reduce((sum, value) => sum + value, 0) / confidences.length;
	const centered = avgConfidence - 0.5;
	return Math.round(centered * 10);
}

/** Map numeric score to letter grade */
export function scoreToGrade(score: number, config?: ScoringConfig): string {
	const g = config?.grades ?? DEFAULT_SCORING_CONFIG.grades;
	if (score >= g.aPlus) return 'A+';
	if (score >= g.a) return 'A';
	if (score >= g.bPlus) return 'B+';
	if (score >= g.b) return 'B';
	if (score >= g.cPlus) return 'C+';
	if (score >= g.c) return 'C';
	if (score >= g.dPlus) return 'D+';
	if (score >= g.d) return 'D';
	return 'F';
}

/** Default critical categories used when no context is provided. */
const DEFAULT_CRITICAL_CATEGORIES: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'ssl'];

/**
 * Compute the overall scan score from individual check results using the three-tier formula.
 *
 * Three tiers:
 * - **Core** (default 70 points): Weighted accumulation of foundational categories (SPF, DMARC, DKIM, DNSSEC, SSL).
 *   `scoreIndicatesMissingControl()` can zero a category's contribution when confidence is deterministic/verified.
 * - **Protective** (default 20 points): Weighted accumulation of active defense categories.
 *   No `scoreIndicatesMissingControl()` override.
 * - **Hardening** (default 10 points): Binary pass/fail — each category with score >= 50 contributes
 *   `tierSplit.hardening / hardeningCount` points. Never subtracts.
 *
 * When a `DomainContext` is provided, uses profile-specific weights partitioned by CATEGORY_TIERS,
 * critical gap categories, and email bonus eligibility instead of defaults.
 */
export function computeScanScore(results: CheckResult[], context?: DomainContext, config?: ScoringConfig): ScanScore {
	const partialScores: Partial<Record<CheckCategory, number>> = {};
	const allFindings: Finding[] = [];

	// Seed all categories to 100 (default for absent results)
	for (const category of Object.keys(CATEGORY_DISPLAY_WEIGHTS) as CheckCategory[]) {
		partialScores[category] = 100;
	}

	// All CheckCategory keys are populated above — safe to widen from Partial
	const categoryScores = partialScores as Record<CheckCategory, number>;

	const cfg = config ?? DEFAULT_SCORING_CONFIG;
	const tierSplit = cfg.tierSplit;
	const spfStrongThreshold = cfg.thresholds.spfStrongThreshold;
	const criticalOverallPenalty = cfg.thresholds.criticalOverallPenalty;
	const criticalGapCeiling = cfg.thresholds.criticalGapCeiling;

	if (results.length === 0) {
		return {
			overall: 100,
			grade: scoreToGrade(100, config),
			categoryScores,
			findings: [],
			summary: `Excellent! No security issues found. Grade: ${scoreToGrade(100, config)}`,
		};
	}

	// Populate category scores from actual results
	for (const result of results) {
		categoryScores[result.category] = result.score;
		allFindings.push(...result.findings);
	}

	// --- Determine active weights per tier ---
	// When context is provided, partition context.weights by CATEGORY_TIERS.
	// Otherwise, use config.coreWeights and config.protectiveWeights.
	const activeCoreWeights: Record<string, number> = {};
	const activeProtectiveWeights: Record<string, number> = {};

	if (context) {
		for (const category of Object.keys(context.weights) as CheckCategory[]) {
			const tier = CATEGORY_TIERS[category];
			const weight = context.weights[category].importance;
			if (tier === 'core') {
				activeCoreWeights[category] = weight;
			} else if (tier === 'protective') {
				activeProtectiveWeights[category] = weight;
			}
			// Hardening categories are handled separately (binary pass/fail)
		}
	} else {
		Object.assign(activeCoreWeights, cfg.coreWeights);
		Object.assign(activeProtectiveWeights, cfg.protectiveWeights);
	}

	// --- Core tier accumulation ---
	const coreMax = Object.values(activeCoreWeights).reduce((sum, w) => sum + w, 0);
	let coreEarned = 0;

	for (const [category, weight] of Object.entries(activeCoreWeights)) {
		if (weight === 0) continue;
		const cat = category as CheckCategory;
		const result = results.find((r) => r.category === cat);
		const rawScore = result ? clampPercent(result.score) : 100;
		const effectiveScore = result && scoreIndicatesMissingControl(result.findings) ? 0 : rawScore;
		coreEarned += (effectiveScore / 100) * weight;
	}

	const corePct = coreMax > 0 ? coreEarned / coreMax : 1;

	// --- Protective tier accumulation ---
	const protectiveMax = Object.values(activeProtectiveWeights).reduce((sum, w) => sum + w, 0);
	let protectiveEarned = 0;

	for (const [category, weight] of Object.entries(activeProtectiveWeights)) {
		if (weight === 0) continue;
		const cat = category as CheckCategory;
		const result = results.find((r) => r.category === cat);
		const rawScore = result ? clampPercent(result.score) : 100;
		// Protective: NO scoreIndicatesMissingControl override
		protectiveEarned += (rawScore / 100) * weight;
	}

	const protectivePct = protectiveMax > 0 ? protectiveEarned / protectiveMax : 1;

	// --- Hardening tier (binary pass/fail) ---
	const hardeningCategories = (Object.keys(CATEGORY_TIERS) as CheckCategory[]).filter(
		(cat) => CATEGORY_TIERS[cat] === 'hardening',
	);
	const hardeningCount = hardeningCategories.length;
	let passedHardeningCount = 0;

	for (const cat of hardeningCategories) {
		const score = categoryScores[cat]; // defaults to 100 if no result
		// Only count as passed if an actual result was provided AND score >= 50
		const hasResult = results.some((r) => r.category === cat);
		if (hasResult && score >= 50) {
			passedHardeningCount++;
		}
		// If no result was submitted, the category doesn't contribute to hardening bonus
		// (defaults to 100 in categoryScores but shouldn't count as a passed hardening check)
	}

	const hardeningPts = hardeningCount > 0
		? (passedHardeningCount / hardeningCount) * tierSplit.hardening
		: 0;

	// --- Base score ---
	const base = (corePct * tierSplit.core) + (protectivePct * tierSplit.protective) + hardeningPts;

	// --- Email bonus ---
	const emailBonusEligible = context ? PROFILE_EMAIL_BONUS_ELIGIBLE[context.profile] : true;

	const spfResult = results.find((result) => result.category === 'spf');
	const dkimResult = results.find((result) => result.category === 'dkim');
	const dmarcResult = results.find((result) => result.category === 'dmarc');
	const spfStrong = !!spfResult && !scoreIndicatesMissingControl(spfResult.findings) && spfResult.score >= spfStrongThreshold;
	const dkimNotDeterministicallyMissing = !dkimResult || !scoreIndicatesMissingControl(dkimResult.findings);
	const dmarcPresent = !!dmarcResult && !scoreIndicatesMissingControl(dmarcResult.findings);

	let emailBonus = 0;
	if (emailBonusEligible && spfStrong && dkimNotDeterministicallyMissing && dmarcPresent && dmarcResult) {
		if (dmarcResult.score >= 90) {
			emailBonus = cfg.thresholds.emailBonusFull;
		} else if (dmarcResult.score >= 70) {
			emailBonus = cfg.thresholds.emailBonusMid;
		} else {
			emailBonus = cfg.thresholds.emailBonusPartial;
		}
	}

	// --- Provider confidence modifier ---
	const providerModifier = computeProviderConfidenceModifier(allFindings);

	// --- Critical penalty ---
	const verifiedCriticalCount = allFindings.filter(
		(finding) => finding.severity === 'critical' && inferFindingConfidence(finding) === 'verified',
	).length;
	const criticalPenalty = verifiedCriticalCount > 0 ? criticalOverallPenalty : 0;

	// --- Assemble overall ---
	const preCeiling = clampPercent(Math.round(base) + emailBonus + providerModifier - criticalPenalty);

	// --- Critical gap ceiling: only Core categories in PROFILE_CRITICAL_CATEGORIES ---
	const criticalCategories = context
		? PROFILE_CRITICAL_CATEGORIES[context.profile]
		: DEFAULT_CRITICAL_CATEGORIES;
	const hasCriticalGap = criticalCategories.some((cat) => {
		const result = results.find((r) => r.category === cat);
		return result && scoreIndicatesMissingControl(result.findings);
	});
	const overall = hasCriticalGap ? Math.min(preCeiling, criticalGapCeiling) : preCeiling;

	const grade = scoreToGrade(overall, config);

	// --- Summary ---
	const criticalCount = allFindings.filter((finding) => finding.severity === 'critical').length;
	const highCount = allFindings.filter((finding) => finding.severity === 'high').length;
	const totalIssues = allFindings.filter((finding) => finding.severity !== 'info').length;

	let summary: string;
	if (totalIssues === 0) {
		summary = `Excellent! No security issues found. Grade: ${grade}`;
	} else if (criticalCount > 0) {
		summary = `${criticalCount} critical issue(s) found requiring immediate attention. Grade: ${grade}`;
	} else if (highCount > 0) {
		summary = `${highCount} high-severity issue(s) found. Grade: ${grade}`;
	} else {
		summary = `${totalIssues} issue(s) found. Grade: ${grade}`;
	}

	return {
		overall,
		grade,
		categoryScores,
		findings: allFindings,
		summary,
	};
}
