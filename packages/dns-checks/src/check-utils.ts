// SPDX-License-Identifier: BUSL-1.1

import type { CheckCategory, CheckResult, Finding, FindingConfidence, Severity } from './types';
import { SEVERITY_PENALTIES } from './types';

// ── Output sanitization (inlined from src/lib/output-sanitize.ts) ──────────

/**
 * Characters that can inject HTML or dangerous markdown constructs.
 * Excludes `_` (common in DNS names like `_dmarc`, `_mta-sts`) and
 * `()` (used in natural-language detail text) which are safe in finding details.
 */
const DNS_DATA_UNSAFE = /[`*#[\]>|<]/g;

/**
 * Sanitize DNS-sourced data before it enters finding detail strings.
 * Strips C0 control characters (preserving tab/newline), replaces HTML/markdown
 * injection characters, but does NOT truncate — DNS data in findings can be
 * longer than display output.
 */
export function sanitizeDnsData(input: string): string {
	return input
		.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
		.replace(DNS_DATA_UNSAFE, ' ')
		.replace(/\s+/g, ' ')
		.trim();
}

// ── Confidence inference ───────────────────────────────────────────────────

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

// ── Score computation ──────────────────────────────────────────────────────

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
 * Determine whether findings indicate a fundamentally missing control.
 * Requires both a missing-control text pattern AND deterministic/verified confidence,
 * or explicit `missingControl: true` metadata.
 */
function hasMissingControl(findings: Finding[]): boolean {
	return findings.some((f) => {
		if (f.metadata?.missingControl === true) return true;
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
 * a fundamentally missing security control, or if any finding carries explicit
 * `missingControl: true` metadata.
 */
export function buildCheckResult(category: CheckCategory, findings: Finding[]): CheckResult {
	const normalizedFindings = findings.map(withConfidenceMetadata);
	const score = computeCategoryScore(normalizedFindings);
	const passed = score >= 50 && !hasMissingControl(normalizedFindings);
	return {
		category,
		passed,
		score: passed ? score : 0,
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
	return { category, title, severity, detail: sanitizeDnsData(detail), ...(metadata ? { metadata } : {}) };
}
