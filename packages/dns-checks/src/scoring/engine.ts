// SPDX-License-Identifier: BUSL-1.1

import {
	CATEGORY_TIERS,
	type CheckCategory,
	type CheckResult,
	type Finding,
	inferFindingConfidence,
	scoreIndicatesMissingControl,
	type ScanScore,
} from './model';
import type { DomainContext } from './profiles';
import { detectDomainContext, getProfileWeights, PROFILE_CRITICAL_CATEGORIES, PROFILE_EMAIL_BONUS_ELIGIBLE } from './profiles';
import type { ScoringConfig } from './config';
import { DEFAULT_SCORING_CONFIG } from './config';
import { buildEvidenceNote, computeScanEvidence, isEvidenceSufficient, EVIDENCE_SUFFICIENCY_THRESHOLD } from './evidence';
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
	dnssec: { importance: 10 },
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
	ptr: { importance: 1 },
	mx_reputation: { importance: 0 },
	srv: { importance: 0 },
	zone_hygiene: { importance: 0 },
	dane_https: { importance: 2 },
	svcb_https: { importance: 1 },
	subdomailing: { importance: 3 },
	brand_discovery: { importance: 0 },
	authoritative_dns_infra: { importance: 0 },
	dnskey_strength: { importance: 1 },
};

/** Core-tier importance weights (SPF, DMARC, DKIM, DNSSEC, SSL). Used by the three-tier scoring formula. */
export const CORE_WEIGHTS: Record<string, number> = {
	dmarc: 16,
	dkim: 10,
	spf: 10,
	dnssec: 10,
	ssl: 8,
	authoritative_dns_infra: 0,
};

/** Protective-tier importance weights. Used by the three-tier scoring formula. */
export const PROTECTIVE_WEIGHTS: Record<string, number> = {
	subdomain_takeover: 4,
	http_security: 3,
	mta_sts: 3,
	subdomailing: 3,
	mx: 2,
	caa: 2,
	ns: 2,
	lookalikes: 2,
	shadow_domains: 2,
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

/**
 * Narrow a {@link ScanScore} to one that carries a real measurement.
 *
 * `false` means the scan produced no gradeable result at all — the correct
 * response is to ABSTAIN (skip the rule, omit the entry, render "not measured"),
 * never to substitute a default. Substituting `0`/`'F'` is the fabricated-grade
 * defect this guard exists to prevent.
 */
export function isGraded(score: ScanScore): score is ScanScore & { overall: number; grade: string } {
	return score.overall !== null && score.grade !== null;
}

/** The 6 letters the NIST-aligned DISPLAY scale can emit. */
export type NistGrade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

/**
 * NIST-aligned 6-band thresholds — the SINGLE customer-facing DISPLAY scale that
 * BlackVeil products consolidated on (2026-06-29). This is intentionally DISTINCT
 * from the canonical 9-band {@link scoreToGrade}, which stays for internal logic,
 * back-compat, and cohort/percentile math (and any third-party lib consumer). The
 * score is unchanged; only which letter a customer-facing surface displays.
 */
export const NIST_GRADE_THRESHOLDS = {
	A_PLUS: 95,
	A: 90,
	B: 80,
	C: 70,
	D: 60,
} as const;

/** Map a 0-100 score to the NIST-aligned 6-band DISPLAY grade. Pure; no config. */
export function nistScoreToGrade(score: number): NistGrade {
	if (score >= NIST_GRADE_THRESHOLDS.A_PLUS) return 'A+';
	if (score >= NIST_GRADE_THRESHOLDS.A) return 'A';
	if (score >= NIST_GRADE_THRESHOLDS.B) return 'B';
	if (score >= NIST_GRADE_THRESHOLDS.C) return 'C';
	if (score >= NIST_GRADE_THRESHOLDS.D) return 'D';
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

	// --- Build transientFailures map ---
	// A check whose execution failed (checkStatus 'timeout'/'error') is INCONCLUSIVE — we
	// couldn't measure it. That is distinct from a genuinely-missing control (missingControl).
	// Exclude inconclusive categories from the weighted score (renormalized over the rest)
	// rather than scoring them 0, so a transient fetch/DNS failure doesn't make the overall
	// score fluctuate. See generic.ts: transientFailures keys are skipped in the tier partition.
	const transientFailures: Record<string, boolean> = {};
	for (const result of results) {
		if (result.checkStatus === 'timeout' || result.checkStatus === 'error') {
			transientFailures[result.category] = true;
		}
	}

	// A core/protective category that produced NO result at all was never measured — treat it
	// exactly like a transient/inconclusive failure: exclude it from the weighted tier so the
	// score renormalizes over what WAS measured, instead of letting generic.ts's `?? 100`
	// default award full unearned credit (which masked real findings — e.g. the scan_domain
	// roster omits lookalikes/shadow_domains, so those never-run protective categories were
	// silently scored a perfect 100). Hardening is intentionally left alone: its denominator
	// legitimately counts every hardening category (an unconfigured bonus is an unearned bonus,
	// handled via hardeningPassed), so a never-run hardening category must NOT be excluded here.
	for (const cat of Object.keys(CATEGORY_TIERS) as CheckCategory[]) {
		const tier = CATEGORY_TIERS[cat];
		if ((tier === 'core' || tier === 'protective') && !resultMap.has(cat)) {
			transientFailures[cat] = true;
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
			// Only mark as passed if an actual result was provided AND it passed AND
			// the score is >= 50. This prevents degraded checks (score forced to 0
			// but passed=true from timeout handling) from inflating hardening points.
			hardeningPassed[cat] = !!(result && result.passed && result.score >= 50);
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
	const verifiedCriticalCount = allFindings.filter((f) => f.severity === 'critical' && inferFindingConfidence(f) === 'verified').length;

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
	const criticalCategories = context ? PROFILE_CRITICAL_CATEGORIES[context.profile] : DEFAULT_CRITICAL_CATEGORIES;

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
		transientFailures,
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
	// Only categories that produced a conclusive result appear here. A category that was NEVER
	// run (absent from `results`) is "not measured", NOT a perfect 100 — seeding it to 100 both
	// showed a misleading phantom score (a never-run category read as clean) and, via the generic
	// engine's `?? 100` default, silently awarded it full weight, masking real findings the
	// dedicated deep-scan tools surface (e.g. lookalikes/shadow_domains are excluded from the
	// scan_domain roster). Transient (timeout/error) checks are likewise excluded. See
	// buildGenericContext, which excludes both classes from the weighted overall (renormalized).
	const categoryScores: Partial<Record<CheckCategory, number>> = {};
	const allFindings: Finding[] = [];

	const cfg = config ?? DEFAULT_SCORING_CONFIG;
	// The `?? EVIDENCE_SUFFICIENCY_THRESHOLD` fallback is deliberate — a consumer
	// vendoring an older copy of this package can hand us a config whose `thresholds`
	// predates this key, and a NaN comparison there would silently disable the gate.
	const evidenceThreshold = cfg.thresholds.evidenceSufficiency ?? EVIDENCE_SUFFICIENCY_THRESHOLD;

	if (results.length === 0) {
		// Zero submitted evidence is NEVER sufficient, unconditionally — this is not a
		// policy knob. A published SSOT must not hand a confident grade (the legacy
		// seeded 100/'A+') to a caller that submitted nothing to measure. See
		// evidence.ts's `isEvidenceSufficient` doc for the same invariant.
		const evidence = { attempted: 0, completed: 0, ratio: 0 };
		const evidenceNote = buildEvidenceNote(evidence, evidenceThreshold);
		return {
			overall: null,
			grade: null,
			categoryScores: categoryScores as Record<CheckCategory, number>,
			findings: [],
			summary: evidenceNote,
			evidence,
			evidenceInsufficient: true,
			evidenceNote,
		};
	}

	// Populate category scores from actual results. Transient (checkStatus 'timeout'/'error')
	// checks are INCONCLUSIVE — omitted from the category-score output (shown as n/a, never a
	// misleading 0) and from the finding counts; buildGenericContext also excludes them from the
	// weighted overall score via transientFailures.
	for (const result of results) {
		if (result.checkStatus === 'timeout' || result.checkStatus === 'error') {
			continue;
		}
		categoryScores[result.category] = result.score;
		allFindings.push(...result.findings);
	}

	// Build the generic context and delegate to the generic engine. `categoryScores` is a partial
	// map (never-run + transient categories are absent); the generic engine treats absent scored
	// keys via `transientFailures` exclusion, so the widening cast is runtime-safe.
	const genericContext = buildGenericContext(results, categoryScores as Record<CheckCategory, number>, allFindings, context, cfg);
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

	// --- Evidence-sufficiency gate ---
	// When most checks could not RUN, any letter grade would describe the scan's own
	// failure rather than the domain's posture. Withhold it. findings and categoryScores
	// are still returned: everything that WAS measured stays available to the caller.
	const evidence = computeScanEvidence(results);
	if (!isEvidenceSufficient(evidence, evidenceThreshold)) {
		const evidenceNote = buildEvidenceNote(evidence, evidenceThreshold);
		return {
			overall: null,
			grade: null,
			categoryScores: categoryScores as Record<CheckCategory, number>,
			findings: allFindings,
			summary: evidenceNote,
			tierBreakdown: genericResult.tierBreakdown,
			evidence,
			evidenceInsufficient: true,
			evidenceNote,
		};
	}

	return {
		overall: genericResult.overall,
		grade: genericResult.grade,
		categoryScores: categoryScores as Record<CheckCategory, number>,
		findings: allFindings,
		summary,
		tierBreakdown: genericResult.tierBreakdown,
		evidence,
	};
}

export interface ProfileAwareScanScore {
	score: ScanScore;
	context: DomainContext;
	profile: DomainContext['profile'];
	detectedProfile: DomainContext['profile'];
	scoringPolicyVersion: string;
}

export function computeProfileAwareScanScore(
	results: CheckResult[],
	options: { profile?: DomainContext['profile'] | 'auto'; config?: ScoringConfig } = {},
): ProfileAwareScanScore {
	const detectedContext = detectDomainContext(results);
	const explicitProfile = options.profile && options.profile !== 'auto' ? options.profile : null;
	const context: DomainContext = explicitProfile
		? {
				...detectedContext,
				profile: explicitProfile,
				signals: [...detectedContext.signals, `explicit profile override: ${explicitProfile}`],
				weights: getProfileWeights(explicitProfile, options.config),
			}
		: {
				...detectedContext,
				weights: getProfileWeights(detectedContext.profile, options.config),
			};

	return {
		score: computeScanScore(results, context, options.config),
		context,
		profile: context.profile,
		detectedProfile: detectedContext.profile,
		scoringPolicyVersion: 'dns-checks-scoring-v1',
	};
}
