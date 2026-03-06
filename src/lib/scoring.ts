/**
 * DNS Security Scoring Library
 *
 * Provides scoring weights, interfaces, and helper functions
 * for computing DNS security risk scores across all check categories.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingConfidence = 'deterministic' | 'heuristic' | 'verified';

export type CheckCategory = 'spf' | 'dmarc' | 'dkim' | 'dnssec' | 'ssl' | 'mta_sts' | 'ns' | 'caa' | 'subdomain_takeover' | 'mx';

export interface Finding {
	category: CheckCategory;
	title: string;
	severity: Severity;
	detail: string;
	metadata?: Record<string, unknown>;
}

export interface CheckResult {
	category: CheckCategory;
	passed: boolean;
	score: number; // 0-100
	findings: Finding[];
}

export interface ScanScore {
	overall: number; // 0-100
	grade: string; // A+ through F
	categoryScores: Record<CheckCategory, number>;
	findings: Finding[];
	summary: string;
}

interface ImportanceProfile {
	importance: number;
}

/** Display/UI weight distribution for categories. NOT used in scoring — see IMPORTANCE_WEIGHTS for actual scoring weights. Exists for category registry and display purposes only. */
export const CATEGORY_DISPLAY_WEIGHTS: Record<CheckCategory, number> = {
	spf: 0.15,
	dmarc: 0.15,
	dkim: 0.15,
	dnssec: 0.15,
	ssl: 0.15,
	mta_sts: 0.05,
	ns: 0.05,
	caa: 0.05,
	subdomain_takeover: 0.1,
	mx: 0,
};

/** Severity penalty multipliers applied to the category score */
export const SEVERITY_PENALTIES: Record<Severity, number> = {
	critical: 40,
	high: 25,
	medium: 15,
	low: 5,
	info: 0,
};

/**
 * Scanner-aligned importance weighting for the checks currently supported by this MCP server.
 * Values are sourced from blackveilsecurity.com score engine for overlapping checks.
 */
const IMPORTANCE_WEIGHTS: Record<CheckCategory, ImportanceProfile> = {
	spf: { importance: 19 },
	dmarc: { importance: 22 },
	dkim: { importance: 10 },
	dnssec: { importance: 3 },
	ssl: { importance: 8 },
	mta_sts: { importance: 3 },
	ns: { importance: 3 },
	caa: { importance: 2 },
	subdomain_takeover: { importance: 2 },
	mx: { importance: 0 },
};

const EMAIL_BONUS_IMPORTANCE = 5;
const SPF_STRONG_THRESHOLD = 57;
const CRITICAL_OVERALL_PENALTY = 15;

function scoreIndicatesMissingControl(findings: Finding[]): boolean {
	return findings.some((f) => {
		if (f.severity !== 'critical' && f.severity !== 'high') return false;
		const text = `${f.title} ${f.detail}`.toLowerCase();
		return /(no\s+.+\s+record|missing|required|not\s+found)/.test(text);
	});
}

function clampPercent(score: number): number {
	return Math.max(0, Math.min(100, score));
}

function isExplicitConfidence(value: unknown): value is FindingConfidence {
	return value === 'deterministic' || value === 'heuristic' || value === 'verified';
}

/**
 * Infer how strongly a finding can be trusted based on available evidence.
 * - verified: explicit proof (currently only supported on takeover checks)
 * - heuristic: signal-based or partial-evidence checks
 * - deterministic: direct record/protocol validation
 */
export function inferFindingConfidence(finding: Finding): FindingConfidence {
	const declared = finding.metadata?.confidence;
	if (isExplicitConfidence(declared)) return declared;

	if (finding.category === 'subdomain_takeover') {
		const status = finding.metadata?.verificationStatus;
		if (status === 'verified') return 'verified';
		return 'heuristic';
	}

	const text = `${finding.title} ${finding.detail}`.toLowerCase();
	if (
		text.includes('common selectors') ||
		text.includes('among tested selectors') ||
		text.includes('inferred') ||
		text.includes('manual review') ||
		text.includes('possible') ||
		text.includes('potential') ||
		text.includes('could indicate')
	) {
		return 'heuristic';
	}

	return 'deterministic';
}

function withConfidenceMetadata(finding: Finding): Finding {
	const confidence = inferFindingConfidence(finding);
	return {
		...finding,
		metadata: {
			...(finding.metadata ?? {}),
			confidence,
		},
	};
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
 * Compute the score for a single check category based on its findings.
 * Starts at 100 and deducts points based on finding severities.
 */
export function computeCategoryScore(findings: Finding[]): number {
	let score = 100;
	for (const finding of findings) {
		score -= SEVERITY_PENALTIES[finding.severity];
	}
	return Math.max(0, Math.min(100, score));
}

/**
 * Build a CheckResult from a category and its findings.
 */
export function buildCheckResult(category: CheckCategory, findings: Finding[]): CheckResult {
	const normalizedFindings = findings.map(withConfidenceMetadata);
	const score = computeCategoryScore(normalizedFindings);
	return {
		category,
		passed: score >= 50,
		score,
		findings: normalizedFindings,
	};
}

/**
 * Create a finding object with the given parameters.
 */
export function createFinding(
	category: CheckCategory,
	title: string,
	severity: Severity,
	detail: string,
	metadata?: Record<string, unknown>,
): Finding {
	return { category, title, severity, detail, ...(metadata ? { metadata } : {}) };
}

/**
 * Compute the overall scan score from individual check results.
 * Uses weighted average of category scores.
 */
export function computeScanScore(results: CheckResult[]): ScanScore {
	const partialScores: Partial<Record<CheckCategory, number>> = {};
	const allFindings: Finding[] = [];

	// Initialize all categories to 100 (perfect) by default
	for (const cat of Object.keys(CATEGORY_DISPLAY_WEIGHTS) as CheckCategory[]) {
		partialScores[cat] = 100;
	}

	// All CheckCategory keys are now populated — safe to treat as complete
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

	// Apply actual scores from results
	for (const result of results) {
		categoryScores[result.category] = result.score;
		allFindings.push(...result.findings);
	}

	let earnedPoints = 0;
	let maxPoints = 0;

	for (const cat of Object.keys(IMPORTANCE_WEIGHTS) as CheckCategory[]) {
		const { importance } = IMPORTANCE_WEIGHTS[cat];
		maxPoints += importance;
		if (importance === 0) continue;

		const result = results.find((r) => r.category === cat);
		const rawScore = result ? clampPercent(result.score) : 100;
		const effectiveScore = result && scoreIndicatesMissingControl(result.findings) ? 0 : rawScore;
		earnedPoints += (effectiveScore / 100) * importance;
	}

	const spfResult = results.find((r) => r.category === 'spf');
	const dkimResult = results.find((r) => r.category === 'dkim');
	const dmarcResult = results.find((r) => r.category === 'dmarc');
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
	const criticalCount = allFindings.filter((f) => f.severity === 'critical').length;
	const criticalPenalty = criticalCount > 0 ? CRITICAL_OVERALL_PENALTY : 0;
	const overall = clampPercent(baseOverall + providerModifier - criticalPenalty);

	const grade = scoreToGrade(overall);

	const highCount = allFindings.filter((f) => f.severity === 'high').length;
	const totalIssues = allFindings.filter((f) => f.severity !== 'info').length;

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
