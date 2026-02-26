/**
 * DNS Security Scoring Library (npm package version)
 * Provides scoring weights, interfaces, and helper functions
 * for computing DNS security risk scores across all check categories.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type CheckCategory = 'spf' | 'dmarc' | 'dkim' | 'dnssec' | 'ssl' | 'mta_sts' | 'ns' | 'caa' | 'subdomain_takeover';

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

export const CATEGORY_WEIGHTS: Record<CheckCategory, number> = {
	spf: 0.15,
	dmarc: 0.15,
	dkim: 0.15,
	dnssec: 0.15,
	ssl: 0.15,
	mta_sts: 0.05,
	ns: 0.1,
	caa: 0.1,
	subdomain_takeover: 0.1,
};

export const SEVERITY_PENALTIES: Record<Severity, number> = {
	critical: 40,
	high: 25,
	medium: 15,
	low: 5,
	info: 0,
};

export function createFinding(category: CheckCategory, title: string, severity: Severity, detail: string): Finding {
	return { category, title, severity, detail };
}

export function buildCheckResult(category: CheckCategory, findings: Finding[]): CheckResult {
	const passed = findings.every((f) => f.severity !== 'critical' && f.severity !== 'high');
	const score = 100 - findings.reduce((acc, f) => acc + SEVERITY_PENALTIES[f.severity], 0);
	return { category, passed, score: Math.max(0, score), findings };
}

export function computeScanScore(checks: CheckResult[]): ScanScore {
	const categoryScores: Record<CheckCategory, number> = {
		spf: 0,
		dmarc: 0,
		dkim: 0,
		dnssec: 0,
		ssl: 0,
		mta_sts: 0,
		ns: 0,
		caa: 0,
		subdomain_takeover: 0,
	};
	let overall = 0;
	let findings: Finding[] = [];
	for (const check of checks) {
		categoryScores[check.category] = check.score;
		findings = findings.concat(check.findings);
		overall += CATEGORY_WEIGHTS[check.category] * check.score;
	}
	const grade = scoreToGrade(overall);
	const summary = `Overall Score: ${Math.round(overall)}/100 (${grade})`;
	return { overall: Math.round(overall), grade, categoryScores, findings, summary };
}

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
