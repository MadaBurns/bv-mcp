// SPDX-License-Identifier: MIT

import {
	CATEGORY_DISPLAY_WEIGHTS,
	type CheckCategory,
	type CheckResult,
	type Finding,
	inferFindingConfidence,
	type ScanScore,
} from './scoring-model';

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
};

const EMAIL_BONUS_IMPORTANCE = 8;
const SPF_STRONG_THRESHOLD = 57;
const CRITICAL_OVERALL_PENALTY = 15;

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
export function scoreToGrade(score: number): string {
	if (score >= 90) return 'A+';
	if (score >= 85) return 'A';
	if (score >= 80) return 'B+';
	if (score >= 75) return 'B';
	if (score >= 70) return 'C+';
	if (score >= 65) return 'C';
	if (score >= 60) return 'D+';
	if (score >= 55) return 'D';
	if (score >= 50) return 'E';
	return 'F';
}

/**
 * Compute the overall scan score from individual check results.
 * Uses weighted average of category scores.
 */
export function computeScanScore(results: CheckResult[]): ScanScore {
	const partialScores: Partial<Record<CheckCategory, number>> = {};
	const allFindings: Finding[] = [];

	// CATEGORY_DISPLAY_WEIGHTS is Record<CheckCategory, number> — Object.keys returns string[], cast is safe
	for (const category of Object.keys(CATEGORY_DISPLAY_WEIGHTS) as CheckCategory[]) {
		partialScores[category] = 100;
	}

	// All CheckCategory keys are populated above — safe to widen from Partial
	const categoryScores = partialScores as Record<CheckCategory, number>;

	if (results.length === 0) {
		return {
			overall: 100,
			grade: scoreToGrade(100),
			categoryScores,
			findings: [],
			summary: `Excellent! No security issues found. Grade: ${scoreToGrade(100)}`,
		};
	}

	for (const result of results) {
		categoryScores[result.category] = result.score;
		allFindings.push(...result.findings);
	}

	let earnedPoints = 0;
	let maxPoints = 0;

	// IMPORTANCE_WEIGHTS is Record<CheckCategory, ImportanceProfile> — Object.keys returns string[], cast is safe
	for (const category of Object.keys(IMPORTANCE_WEIGHTS) as CheckCategory[]) {
		const { importance } = IMPORTANCE_WEIGHTS[category];
		maxPoints += importance;
		if (importance === 0) continue;

		const result = results.find((entry) => entry.category === category);
		const rawScore = result ? clampPercent(result.score) : 100;
		const effectiveScore = result && scoreIndicatesMissingControl(result.findings) ? 0 : rawScore;
		earnedPoints += (effectiveScore / 100) * importance;
	}

	const spfResult = results.find((result) => result.category === 'spf');
	const dkimResult = results.find((result) => result.category === 'dkim');
	const dmarcResult = results.find((result) => result.category === 'dmarc');
	const spfStrong = !!spfResult && !scoreIndicatesMissingControl(spfResult.findings) && spfResult.score >= SPF_STRONG_THRESHOLD;
	const dkimPresent = !!dkimResult && !scoreIndicatesMissingControl(dkimResult.findings);
	const dmarcPresent = !!dmarcResult && !scoreIndicatesMissingControl(dmarcResult.findings);

	let emailBonus = 0;
	if (spfStrong && dkimPresent && dmarcPresent && dmarcResult) {
		if (dmarcResult.score >= 90) {
			emailBonus = EMAIL_BONUS_IMPORTANCE;
		} else if (dmarcResult.score >= 70) {
			emailBonus = Math.ceil(EMAIL_BONUS_IMPORTANCE * 0.6);
		} else {
			emailBonus = Math.ceil(EMAIL_BONUS_IMPORTANCE * 0.4);
		}
	}

	earnedPoints += emailBonus;
	if (emailBonus > 0) {
		maxPoints += EMAIL_BONUS_IMPORTANCE;
	}

	const baseOverall = Math.round(maxPoints > 0 ? clampPercent((earnedPoints / maxPoints) * 100) : 0);
	const providerModifier = computeProviderConfidenceModifier(allFindings);
	const criticalCount = allFindings.filter((finding) => finding.severity === 'critical').length;
	const verifiedCriticalCount = allFindings.filter(
		(finding) => finding.severity === 'critical' && inferFindingConfidence(finding) === 'verified',
	).length;
	const criticalPenalty = verifiedCriticalCount > 0 ? CRITICAL_OVERALL_PENALTY : 0;
	const preCeiling = clampPercent(baseOverall + providerModifier - criticalPenalty);

	// Critical gap ceiling: cap score when foundational controls are missing
	const CRITICAL_GAP_CEILING = 64;
	const CRITICAL_CATEGORIES: CheckCategory[] = ['spf', 'dmarc', 'dkim', 'ssl', 'dnssec', 'subdomain_takeover'];
	const hasCriticalGap = CRITICAL_CATEGORIES.some((cat) => {
		const result = results.find((r) => r.category === cat);
		return result && scoreIndicatesMissingControl(result.findings);
	});
	const overall = hasCriticalGap ? Math.min(preCeiling, CRITICAL_GAP_CEILING) : preCeiling;

	const grade = scoreToGrade(overall);

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