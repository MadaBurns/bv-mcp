// SPDX-License-Identifier: MIT

import {
	CATEGORY_DISPLAY_WEIGHTS,
	type CheckCategory,
	type CheckResult,
	type Finding,
	inferFindingConfidence,
	type ScanScore,
} from './scoring-model';
import type { DomainContext } from './context-profiles';
import { PROFILE_CRITICAL_CATEGORIES, PROFILE_EMAIL_BONUS_ELIGIBLE } from './context-profiles';
import type { ScoringConfig } from './scoring-config';
import { DEFAULT_SCORING_CONFIG, toImportanceRecord } from './scoring-config';

interface ImportanceProfile {
	importance: number;
}

/**
 * Scanner-aligned importance weighting for the checks currently supported by this MCP server.
 * Values are sourced from blackveilsecurity.com score engine for overlapping checks.
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
};

function scoreIndicatesMissingControl(findings: Finding[]): boolean {
	return findings.some((finding) => {
		if (finding.severity !== 'critical' && finding.severity !== 'high') return false;
		const text = `${finding.title} ${finding.detail}`.toLowerCase();
		return /(no\s+.+\s+record|missing|required|not\s+found)/.test(text);
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
	if (score >= g.e) return 'E';
	return 'F';
}

/** Default critical categories used when no context is provided.
 * DNSSEC is excluded: its importance weight (2) already reflects its proportional
 * impact, and only ~30% of domains deploy it — capping the entire score at 64
 * for missing DNSSEC produces misleading results for well-configured domains. */
const DEFAULT_CRITICAL_CATEGORIES: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'ssl', 'subdomain_takeover'];

/**
 * Compute the overall scan score from individual check results.
 * Uses weighted average of category scores.
 *
 * When a `DomainContext` is provided, uses profile-specific weights,
 * critical gap categories, and email bonus eligibility instead of defaults.
 */
export function computeScanScore(results: CheckResult[], context?: DomainContext, config?: ScoringConfig): ScanScore {
	const partialScores: Partial<Record<CheckCategory, number>> = {};
	const allFindings: Finding[] = [];

	// CATEGORY_DISPLAY_WEIGHTS is Record<CheckCategory, number> — Object.keys returns string[], cast is safe
	for (const category of Object.keys(CATEGORY_DISPLAY_WEIGHTS) as CheckCategory[]) {
		partialScores[category] = 100;
	}

	// All CheckCategory keys are populated above — safe to widen from Partial
	const categoryScores = partialScores as Record<CheckCategory, number>;

	const cfg = config ?? DEFAULT_SCORING_CONFIG;
	const emailBonusImportance = cfg.thresholds.emailBonusImportance;
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

	for (const result of results) {
		categoryScores[result.category] = result.score;
		allFindings.push(...result.findings);
	}

	let earnedPoints = 0;
	let maxPoints = 0;

	// Use context-specific weights when provided, otherwise fall back to config defaults
	const activeWeights = context ? context.weights : toImportanceRecord(cfg.weights);

	// activeWeights is Record<CheckCategory, ImportanceProfile> — Object.keys returns string[], cast is safe
	for (const category of Object.keys(activeWeights) as CheckCategory[]) {
		const { importance } = activeWeights[category];
		maxPoints += importance;
		if (importance === 0) continue;

		const result = results.find((entry) => entry.category === category);
		const rawScore = result ? clampPercent(result.score) : 100;
		const effectiveScore = result && scoreIndicatesMissingControl(result.findings) ? 0 : rawScore;
		earnedPoints += (effectiveScore / 100) * importance;
	}

	// Email bonus: only awarded for profiles that are eligible (or when no context is provided)
	const emailBonusEligible = context ? PROFILE_EMAIL_BONUS_ELIGIBLE[context.profile] : true;

	const spfResult = results.find((result) => result.category === 'spf');
	const dkimResult = results.find((result) => result.category === 'dkim');
	const dmarcResult = results.find((result) => result.category === 'dmarc');
	const spfStrong = !!spfResult && !scoreIndicatesMissingControl(spfResult.findings) && spfResult.score >= spfStrongThreshold;
	const dkimPresent = !!dkimResult && !scoreIndicatesMissingControl(dkimResult.findings);
	const dmarcPresent = !!dmarcResult && !scoreIndicatesMissingControl(dmarcResult.findings);

	let emailBonus = 0;
	if (emailBonusEligible && spfStrong && dkimPresent && dmarcPresent && dmarcResult) {
		if (dmarcResult.score >= 90) {
			emailBonus = emailBonusImportance;
		} else if (dmarcResult.score >= 70) {
			emailBonus = Math.ceil(emailBonusImportance * 0.6);
		} else {
			emailBonus = Math.ceil(emailBonusImportance * 0.4);
		}
	}

	earnedPoints += emailBonus;
	if (emailBonus > 0) {
		maxPoints += emailBonusImportance;
	}

	const baseOverall = Math.round(maxPoints > 0 ? clampPercent((earnedPoints / maxPoints) * 100) : 0);
	const providerModifier = computeProviderConfidenceModifier(allFindings);
	const criticalCount = allFindings.filter((finding) => finding.severity === 'critical').length;
	const verifiedCriticalCount = allFindings.filter(
		(finding) => finding.severity === 'critical' && inferFindingConfidence(finding) === 'verified',
	).length;
	const criticalPenalty = verifiedCriticalCount > 0 ? criticalOverallPenalty : 0;
	const preCeiling = clampPercent(baseOverall + providerModifier - criticalPenalty);

	// Critical gap ceiling: cap score when foundational controls are missing
	const criticalCategories = context
		? PROFILE_CRITICAL_CATEGORIES[context.profile]
		: DEFAULT_CRITICAL_CATEGORIES;
	const hasCriticalGap = criticalCategories.some((cat) => {
		const result = results.find((r) => r.category === cat);
		return result && scoreIndicatesMissingControl(result.findings);
	});
	const overall = hasCriticalGap ? Math.min(preCeiling, criticalGapCeiling) : preCeiling;

	const grade = scoreToGrade(overall, config);

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