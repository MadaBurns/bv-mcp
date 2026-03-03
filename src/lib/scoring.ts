/**
 * DNS Security Scoring Library
 *
 * Provides scoring weights, interfaces, and helper functions
 * for computing DNS security risk scores across all check categories.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type CheckCategory = 'spf' | 'dmarc' | 'dkim' | 'dnssec' | 'ssl' | 'mta_sts' | 'ns' | 'caa' | 'subdomain_takeover' | 'mx';

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
	ns: { importance: 0 },
	caa: { importance: 0 },
	subdomain_takeover: { importance: 0 },
	mx: { importance: 0 },
};

const EMAIL_BONUS_IMPORTANCE = 5;
const SPF_STRONG_THRESHOLD = 57;

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

	if (results.length === 0) {
		for (const cat of Object.keys(CATEGORY_DISPLAY_WEIGHTS) as CheckCategory[]) {
			categoryScores[cat] = 100;
		}
		return {
			overall: 100,
			grade: scoreToGrade(100),
			categoryScores,
			findings: [],
			summary: `Excellent! No security issues found. Grade: ${scoreToGrade(100)}`,
		};
	}

	// Initialize all categories to 100 (perfect) by default
	for (const cat of Object.keys(CATEGORY_DISPLAY_WEIGHTS) as CheckCategory[]) {
		categoryScores[cat] = 100;
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

	const overall = Math.round(maxPoints > 0 ? clampPercent((earnedPoints / maxPoints) * 100) : 0);

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
