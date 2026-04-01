// SPDX-License-Identifier: BUSL-1.1

import type { CheckCategory, CheckResult, Finding, Severity } from '../types';
import { CATEGORY_DISPLAY_WEIGHTS, SEVERITY_PENALTIES } from '../types';

export type { CheckCategory, CheckResult, Finding, Severity };
export { CATEGORY_DISPLAY_WEIGHTS, SEVERITY_PENALTIES };

export type { CategoryTier } from '../types';
export { CATEGORY_TIERS } from '../types';
export type { ScanScore } from '../types';

/** Display/UI weight distribution for categories — re-exported from types for convenience. */

/** Severity penalty multipliers — re-exported from types for convenience. */

export type FindingConfidence = 'deterministic' | 'heuristic' | 'verified';

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

/** Regex for detecting missing control patterns in finding text. */
const MISSING_CONTROL_REGEX = /(no\s+.+\s+record|missing|required|not\s+found)/i;

/**
 * Determine whether findings for a category indicate a fundamentally missing control.
 * Requires both a missing-control text pattern AND deterministic/verified confidence
 * to avoid false zeroing from heuristic checks (e.g., DKIM selector probing).
 */
export function scoreIndicatesMissingControl(findings: Finding[]): boolean {
	return findings.some((f) => {
		const isMissingPattern = MISSING_CONTROL_REGEX.test(f.detail) || MISSING_CONTROL_REGEX.test(f.title);
		const confidence = (f.metadata?.confidence as string) ?? inferFindingConfidence(f);
		return isMissingPattern
			&& (f.severity === 'critical' || f.severity === 'high')
			&& (confidence === 'deterministic' || confidence === 'verified');
	});
}

/**
 * Build a CheckResult from a category and its findings.
 * A check fails (passed=false) if the score is below 50, if findings indicate
 * a fundamentally missing security control (e.g., no SPF/DMARC record), or if
 * any finding carries explicit `missingControl: true` metadata.
 */
export function buildCheckResult(category: CheckCategory, findings: Finding[]): CheckResult {
	const normalizedFindings = findings.map(withConfidenceMetadata);
	const score = computeCategoryScore(normalizedFindings);
	const hasMissingControl = scoreIndicatesMissingControl(normalizedFindings)
		|| normalizedFindings.some((f) => f.metadata?.missingControl === true);
	const passed = score >= 50 && !hasMissingControl;
	return {
		category,
		passed,
		score: hasMissingControl ? 0 : score,
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
	// Sanitize detail to strip control characters and unsafe markdown/HTML chars
	const sanitized = detail
		.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
		.replace(/[`[\]<>]/g, ' ')
		.replace(/\s+/g, ' ')
		.trim();
	return { category, title, severity, detail: sanitized, ...(metadata ? { metadata } : {}) };
}
