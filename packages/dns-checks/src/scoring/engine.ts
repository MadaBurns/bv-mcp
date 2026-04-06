// SPDX-License-Identifier: BUSL-1.1

import {
	CATEGORY_DISPLAY_WEIGHTS,
	CATEGORY_TIERS,
	type CheckCategory,
	type CheckResult,
	type Finding,
	inferFindingConfidence,
	scoreIndicatesMissingControl,
	type ScanScore,
} from './model';
import type { DomainContext } from './profiles';
import { PROFILE_CRITICAL_CATEGORIES, PROFILE_EMAIL_BONUS_ELIGIBLE } from './profiles';
import type { ScoringConfig } from './config';
import { DEFAULT_SCORING_CONFIG } from './config';
import { computeGenericScore } from './generic';
import type { GenericScoringContext, FindingSeverityCounts } from './generic';

interface ImportanceProfile {
	importance: number;
}

/**
 * Scanner-aligned importance weighting for the checks currently supported by this MCP server.
 * @deprecated Use CORE_WEIGHTS and PROTECTIVE_WEIGHTS for three-tier scoring. Retained for backward compatibility.
 */
export const IMPORTANCE_WEIGHTS: Record<CheckCategory, ImportanceProfile> = {
	spf: { importance: 10 },
	dmarc: { importance: 16 },
	dkim: { importance: 10 },
	dnssec: { importance: 8 },
	ssl: { importance: 8 },
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
	subdomailing: { importance: 3 },
};

/** Core-tier importance weights (SPF, DMARC, DKIM, DNSSEC, SSL). Used by the three-tier scoring formula. */
export const CORE_WEIGHTS: Record<string, number> = {
	dmarc: 16, dkim: 10, spf: 10, dnssec: 8, ssl: 8,
};

/** Protective-tier importance weights. Used by the three-tier scoring formula. */
export const PROTECTIVE_WEIGHTS: Record<string, number> = {
	subdomain_takeover: 4, http_security: 3, mta_sts: 3, subdomailing: 3, mx: 2,
	caa: 2, ns: 2, lookalikes: 2, shadow_domains: 2,
};


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
 * Build a GenericScoringContext from CheckResult[] + DomainContext.
 *
 * This bridges the concrete bv-mcp types (CheckResult, CheckCategory, Finding)
 * to the generic scoring engine's string-keyed inputs.
 */
function buildGenericContext(
	results: CheckResult[],
	categoryScores: Record<CheckCategory, number>,
	allFindings: Finding[],
	context: DomainContext | undefined,
	config: ScoringConfig,
): GenericScoringContext {
	// --- Build weights map (flat importance values) ---
	const weights: Record<string, number> = {};

	if (context) {
		for (const category of Object.keys(context.weights) as CheckCategory[]) {
			weights[category] = context.weights[category].importance;
		}
	} else {
		// Merge core + protective from config; hardening categories get 0
		for (const [key, value] of Object.entries(config.coreWeights)) {
			weights[key] = value;
		}
		for (const [key, value] of Object.entries(config.protectiveWeights)) {
			weights[key] = value;
		}
		// Ensure hardening categories are in weights (with 0 from config defaults)
		for (const cat of Object.keys(CATEGORY_TIERS) as CheckCategory[]) {
			if (CATEGORY_TIERS[cat] === 'hardening' && !(cat in weights)) {
				weights[cat] = 0;
			}
		}
	}

	// --- Build missingControls map ---
	// Only mark a category as missing when an actual result exists and
	// scoreIndicatesMissingControl returns true. Absent categories must NOT
	// be marked missing — the original engine's critical gap ceiling check
	// requires an actual result (`result && scoreIndicatesMissingControl(...)`),
	// and absent categories default to 100 with no zeroing.
	const missingControls: Record<string, boolean> = {};
	const resultMap = new Map<CheckCategory, CheckResult>();
	for (const result of results) {
		resultMap.set(result.category, result);
		if (scoreIndicatesMissingControl(result.findings)) {
			missingControls[result.category] = true;
		}
	}

	// --- Build hardeningPassed map ---
	// The original engine iterates ALL hardening categories from CATEGORY_TIERS (not just
	// those with results). It uses hardeningCount = total hardening categories.
	// A category counts as "passed" only if result exists AND result.passed is true.
	// Categories without results don't count as passed but DO count toward the denominator.
	//
	// The generic engine only counts *submitted* keys in hardeningPassed toward the denominator.
	// To match: submit ALL hardening categories, marking passed=true only for those with passing results.
	const hardeningPassed: Record<string, boolean> = {};
	for (const cat of Object.keys(CATEGORY_TIERS) as CheckCategory[]) {
		if (CATEGORY_TIERS[cat] === 'hardening') {
			const result = resultMap.get(cat);
			// Submit all hardening categories so denominator = total hardening count.
			// Only mark as passed if an actual result was provided AND it passed.
			hardeningPassed[cat] = !!(result && result.passed);
		}
	}

	// --- Extract provider confidence from findings metadata ---
	const providerConfidence: Record<string, number> = {};
	for (const finding of allFindings) {
		const confidence = finding.metadata?.providerConfidence;
		if (typeof confidence === 'number' && Number.isFinite(confidence)) {
			// Use a synthetic key per finding to preserve the original per-finding averaging behavior.
			// The original engine averages ALL providerConfidence values across all findings.
			// The generic engine averages all values in the providerConfidence map.
			const key = `_finding_${Object.keys(providerConfidence).length}`;
			providerConfidence[key] = confidence;
		}
	}

	// --- Build finding severity counts ---
	// Critical penalty: original only counts findings with severity=critical AND confidence=verified.
	// Generic applies penalty when findingSeverityCounts.critical > 0.
	// To match: pass only verified critical findings as the critical count.
	const verifiedCriticalCount = allFindings.filter(
		(f) => f.severity === 'critical' && inferFindingConfidence(f) === 'verified',
	).length;

	// For critical penalty equivalence, use verified-only count as the "critical" count.
	// The original engine only applies the penalty for verified critical findings.
	const findingSeverityCounts: FindingSeverityCounts = {
		critical: verifiedCriticalCount,
		high: allFindings.filter((f) => f.severity === 'high').length,
		medium: allFindings.filter((f) => f.severity === 'medium').length,
		low: allFindings.filter((f) => f.severity === 'low').length,
		info: allFindings.filter((f) => f.severity === 'info').length,
	};

	// --- Critical categories ---
	const criticalCategories = context
		? PROFILE_CRITICAL_CATEGORIES[context.profile]
		: DEFAULT_CRITICAL_CATEGORIES;

	// --- Email bonus eligibility ---
	// Original engine requires actual SPF and DMARC results to exist for the bonus
	// (!!spfResult && !!dmarcResult). Absent DKIM qualifies (dkimNotDeterministicallyMissing = !dkimResult || ...).
	// Disable email bonus entirely when SPF or DMARC has no result to match original behavior.
	let emailBonusEligible = context ? PROFILE_EMAIL_BONUS_ELIGIBLE[context.profile] : true;
	if (!resultMap.has('spf') || !resultMap.has('dmarc')) {
		emailBonusEligible = false;
	}

	// --- Build the summary-compatible severity counts ---
	// The original summary uses ALL critical findings (not just verified) for the summary text.
	// We store the "display" counts separately and use them to override the summary after scoring.
	// (The findingSeverityCounts above has verifiedCriticalCount for the penalty calculation.)

	return {
		categoryScores: { ...categoryScores },
		tierMap: { ...CATEGORY_TIERS },
		weights,
		missingControls,
		hardeningPassed,
		criticalCategories: [...criticalCategories],
		emailBonusEligible,
		providerConfidence: Object.keys(providerConfidence).length > 0 ? providerConfidence : undefined,
		findingSeverityCounts,
	};
}

/**
 * Compute the overall scan score from individual check results using the three-tier formula.
 *
 * Delegates to `computeGenericScore` internally, building a `GenericScoringContext` from
 * the concrete `CheckResult[]` and optional `DomainContext`.
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

	// Build the generic context and delegate to the generic engine
	const genericContext = buildGenericContext(results, categoryScores, allFindings, context, cfg);
	const genericResult = computeGenericScore(genericContext, config);

	// --- Build summary using original logic ---
	// The original summary uses ALL critical findings (not just verified ones used for penalty).
	const criticalCount = allFindings.filter((f) => f.severity === 'critical').length;
	const highCount = allFindings.filter((f) => f.severity === 'high').length;
	const totalIssues = allFindings.filter((f) => f.severity !== 'info').length;

	let summary: string;
	if (totalIssues === 0) {
		summary = `Excellent! No security issues found. Grade: ${genericResult.grade}`;
	} else if (criticalCount > 0) {
		summary = `${criticalCount} critical issue(s) found requiring immediate attention. Grade: ${genericResult.grade}`;
	} else if (highCount > 0) {
		summary = `${highCount} high-severity issue(s) found. Grade: ${genericResult.grade}`;
	} else {
		summary = `${totalIssues} issue(s) found. Grade: ${genericResult.grade}`;
	}

	return {
		overall: genericResult.overall,
		grade: genericResult.grade,
		categoryScores,
		findings: allFindings,
		summary,
	};
}
