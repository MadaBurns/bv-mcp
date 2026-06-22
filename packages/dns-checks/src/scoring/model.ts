// SPDX-License-Identifier: BUSL-1.1

import type { CheckCategory, CheckResult, CheckStatus, Finding, Severity } from '../types';
import { CATEGORY_DISPLAY_WEIGHTS, CATEGORY_PENALTY_CAPS, SEVERITY_PENALTIES } from '../types';
import { sanitizeFindingMetadata, sanitizeStructuredString } from './metadata-sanitize';

export type { CheckCategory, CheckResult, CheckStatus, Finding, Severity };
export { CATEGORY_DISPLAY_WEIGHTS, CATEGORY_PENALTY_CAPS, SEVERITY_PENALTIES };

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
 *
 * When `category` is supplied and present in `CATEGORY_PENALTY_CAPS`, the
 * total penalty is capped before clamping — this preserves discriminative
 * power between "many same-class findings" and "single catastrophic finding"
 * in categories like `subdomain_takeover` where a single upstream resource
 * deletion can produce many same-class findings (e.g., one AWS NLB deletion
 * orphaning 9 subdomains). Categories without a cap retain the legacy
 * uncapped-then-clamped behavior.
 *
 * Backwards-compatible: omitting `category` keeps the original behavior.
 */
export function computeCategoryScore(findings: Finding[], category?: CheckCategory): number {
	let penalty = 0;
	for (const finding of findings) {
		// `penaltyOverride` decouples the displayed severity from the score penalty:
		// a finding can carry a triage-facing severity label (e.g. DNSSEC `high`)
		// while applying a different, fixed deduction. Honored only when numeric;
		// anything else falls back to the severity default.
		const override = finding.metadata?.penaltyOverride;
		penalty += typeof override === 'number' ? override : SEVERITY_PENALTIES[finding.severity];
	}
	if (category !== undefined) {
		const cap = CATEGORY_PENALTY_CAPS[category];
		if (cap !== undefined && penalty > cap) {
			penalty = cap;
		}
	}
	return Math.max(0, Math.min(100, 100 - penalty));
}

/**
 * Regex for detecting missing control patterns in finding text.
 * The "no … record" gap is a bounded `[^\r\n]{1,64}` (not `.+\s+`): the old
 * `.+\s+record` had two overlapping unbounded quantifiers, giving polynomial
 * backtracking on a long no-"record" string (CWE-1333 / js/polynomial-redos).
 * The bound is well above any real finding phrase ("No SPF record found").
 */
const MISSING_CONTROL_REGEX = /(no\s+[^\r\n]{1,64}\srecord|missing|required|not\s+found)/i;

/**
 * Determine whether findings for a category indicate a fundamentally missing control.
 * Requires both a missing-control text pattern AND deterministic/verified confidence
 * to avoid false zeroing from heuristic checks (e.g., DKIM selector probing).
 */
export function scoreIndicatesMissingControl(findings: Finding[]): boolean {
	return findings.some((f) => {
		const isMissingPattern = MISSING_CONTROL_REGEX.test(f.detail) || MISSING_CONTROL_REGEX.test(f.title);
		const confidence = (f.metadata?.confidence as string) ?? inferFindingConfidence(f);
		return (
			isMissingPattern &&
			(f.severity === 'critical' || f.severity === 'high') &&
			(confidence === 'deterministic' || confidence === 'verified')
		);
	});
}

/**
 * Build a CheckResult from a category and its findings.
 * A check fails (passed=false) if the score is below 50, if findings indicate
 * a fundamentally missing security control (e.g., no SPF/DMARC record), or if
 * any finding carries explicit `missingControl: true` metadata.
 */
export function buildCheckResult(category: CheckCategory, findings: Finding[], controlPresent?: boolean): CheckResult {
	const normalizedFindings = findings.map(withConfidenceMetadata);
	const score = computeCategoryScore(normalizedFindings, category);
	const hasMissingControl =
		scoreIndicatesMissingControl(normalizedFindings) || normalizedFindings.some((f) => f.metadata?.missingControl === true);
	const passed = score >= 50 && !hasMissingControl;
	return {
		category,
		passed,
		score: hasMissingControl ? 0 : score,
		findings: normalizedFindings,
		// Only set when the caller provides a determination; left absent (undefined) otherwise so
		// consumers can distinguish "definitively absent" (false) from "not determined" (undefined).
		...(controlPresent === undefined ? {} : { controlPresent }),
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
	// Sanitize detail with the shared structured-string sanitizer used by metadata,
	// so both LLM-facing channels stay in lockstep.
	const sanitized = sanitizeStructuredString(detail);
	// F7 (OWASP LLM01): metadata reaches the LLM verbatim via the MCP
	// `structuredContent` channel, so sanitize attacker-influenceable STRING values
	// here at the chokepoint (control bytes, code-fence/markdown injection, over-long
	// strings) while preserving numeric/boolean/enum fields scoring & formatters rely
	// on. Generalizes the per-tool F7 opt-ins (`src/lib/sanitize-upstream.ts`).
	const sanitizedMetadata = sanitizeFindingMetadata(metadata);
	return { category, title, severity, detail: sanitized, ...(sanitizedMetadata ? { metadata: sanitizedMetadata } : {}) };
}
