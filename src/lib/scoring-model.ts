// SPDX-License-Identifier: BUSL-1.1

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingConfidence = 'deterministic' | 'heuristic' | 'verified';

export type CheckCategory =
	| 'spf'
	| 'dmarc'
	| 'dkim'
	| 'dnssec'
	| 'ssl'
	| 'mta_sts'
	| 'ns'
	| 'caa'
	| 'subdomain_takeover'
	| 'mx'
	| 'bimi'
	| 'tlsrpt'
	| 'lookalikes'
	| 'shadow_domains'
	| 'txt_hygiene'
	| 'http_security'
	| 'dane'
	| 'mx_reputation';

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
	score: number;
	findings: Finding[];
}

export interface ScanScore {
	overall: number;
	grade: string;
	categoryScores: Record<CheckCategory, number>;
	findings: Finding[];
	summary: string;
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
	bimi: 0,
	tlsrpt: 0.02,
	lookalikes: 0,
	shadow_domains: 0,
	txt_hygiene: 0,
	http_security: 0.05,
	dane: 0,
	mx_reputation: 0,
};

/** Severity penalty multipliers applied to the category score */
export const SEVERITY_PENALTIES: Record<Severity, number> = {
	critical: 40,
	high: 25,
	medium: 15,
	low: 5,
	info: 0,
};

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