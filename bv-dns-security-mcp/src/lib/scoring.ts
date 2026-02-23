/**
 * DNS Security Scoring Library
 *
 * Provides scoring weights, interfaces, and helper functions
 * for computing DNS security risk scores across all check categories.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type CheckCategory = 'spf' | 'dmarc' | 'dkim' | 'dnssec' | 'ssl' | 'mta_sts' | 'ns' | 'caa';

export interface Finding {
	category: CheckCategory;
	title: string;
	severity: Severity;
	detail: string;
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

/** Weights for each check category (must sum to 1.0) */
export const CATEGORY_WEIGHTS: Record<CheckCategory, number> = {
	spf: 0.15,
	dmarc: 0.15,
	dkim: 0.15,
	dnssec: 0.15,
	ssl: 0.15,
	mta_sts: 0.05,
	ns: 0.10,
	caa: 0.10,
};

/** Severity penalty multipliers applied to the category score */
export const SEVERITY_PENALTIES: Record<Severity, number> = {
	critical: 40,
	high: 25,
	medium: 15,
	low: 5,
	info: 0,
};

/** Map numeric score to letter grade */
export function scoreToGrade(score: number): string {
	if (score >= 95) return 'A+';
	if (score >= 90) return 'A';
	if (score >= 85) return 'A-';
	if (score >= 80) return 'B+';
	if (score >= 75) return 'B';
	if (score >= 70) return 'B-';
	if (score >= 65) return 'C+';
	if (score >= 60) return 'C';
	if (score >= 55) return 'C-';
	if (score >= 50) return 'D+';
	if (score >= 45) return 'D';
	if (score >= 40) return 'D-';
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
	const score = computeCategoryScore(findings);
	return {
		category,
		passed: score >= 50,
		score,
		findings,
	};
}

/**
 * Create a finding object with the given parameters.
 */
export function createFinding(category: CheckCategory, title: string, severity: Severity, detail: string): Finding {
	return { category, title, severity, detail };
}

/**
 * Compute the overall scan score from individual check results.
 * Uses weighted average of category scores.
 */
export function computeScanScore(results: CheckResult[]): ScanScore {
	const categoryScores = {} as Record<CheckCategory, number>;
	const allFindings: Finding[] = [];

	// Initialize all categories to 100 (perfect) by default
	for (const cat of Object.keys(CATEGORY_WEIGHTS) as CheckCategory[]) {
		categoryScores[cat] = 100;
	}

	// Apply actual scores from results
	for (const result of results) {
		categoryScores[result.category] = result.score;
		allFindings.push(...result.findings);
	}

	// Weighted average
	let overall = 0;
	for (const cat of Object.keys(CATEGORY_WEIGHTS) as CheckCategory[]) {
		overall += categoryScores[cat] * CATEGORY_WEIGHTS[cat];
	}
	overall = Math.round(Math.max(0, Math.min(100, overall)));

	const grade = scoreToGrade(overall);

	const criticalCount = allFindings.filter((f) => f.severity === 'critical').length;
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

