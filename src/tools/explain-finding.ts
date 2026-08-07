// SPDX-License-Identifier: BUSL-1.1

/**
 * Explain Finding tool.
 * Provides static explanations for DNS security findings.
 * No AI binding required - uses a built-in knowledge base.
 */

import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';

import {
	CATEGORY_FALLBACK_IMPACT,
	CATEGORY_TO_CHECKTYPE,
	DEFAULT_EXPLANATION,
	DETAIL_SIGNATURES,
	type DetailSignatureRule,
	EXPLANATIONS,
	type ExplanationTemplate,
	type ImpactNarrative,
	SEVERITY_FALLBACK_IMPACT,
	SPECIFIC_IMPACT_RULES,
} from './explain-finding-data';

export interface ExplanationResult {
	checkType: string;
	status: string;
	details?: string;
	title: string;
	severity: string;
	explanation: string;
	impact?: string;
	adverseConsequences?: string;
	recommendation: string;
	references: string[];
	/**
	 * Id of the {@link DETAIL_SIGNATURES} rule that matched `details`, when one did.
	 * Absent means the answer came from the coarse checkType+status bucket, so the
	 * caller knows the guidance is general rather than finding-specific.
	 */
	matchedSignature?: string;
}

type ExplanationEntry = ExplanationTemplate;

/**
 * Statuses for which a finding-signature match must NOT be applied.
 *
 * A passing or informational result can still carry detail text that mentions a
 * mechanism ("SPF record uses \"~all\" (soft fail) which is the recommended
 * setting when DMARC enforcement is active"), and swapping in the corresponding
 * defect explanation would turn a clean result into a fabricated problem.
 */
const NON_ACTIONABLE_STATUSES = new Set(['pass', 'passed', 'ok', 'info', 'informational', 'n/a', 'na', 'skipped']);

/**
 * Find the finding signature matching a caller-supplied `details` string.
 *
 * This is the fix for the tool's core defect: `details` is documented as "the
 * additional detail from the check result" but was previously discarded, so a
 * lookup-limit SPF finding got the bucket's "multiple records / broad IP range"
 * remediation — confident, specific and wrong.
 *
 * @param checkType Check type (any case).
 * @param status Caller-supplied status or severity.
 * @param details Finding detail text; matching is skipped when absent/blank.
 * @returns The first matching rule, or undefined when nothing is recognised.
 */
export function resolveDetailSignature(
	checkType: string,
	status: string | undefined,
	details: string | undefined,
): DetailSignatureRule | undefined {
	const detail = details?.trim();
	if (!detail) return undefined;
	if (status && NON_ACTIONABLE_STATUSES.has(status.toLowerCase())) return undefined;

	const normalizedType = checkType.toUpperCase();
	const normalizedStatus = status?.toLowerCase();

	for (const rule of DETAIL_SIGNATURES) {
		if (rule.checkType !== normalizedType) continue;
		if (rule.statuses && (!normalizedStatus || !rule.statuses.includes(normalizedStatus))) continue;
		if (!rule.pattern.test(detail)) continue;
		return rule;
	}

	return undefined;
}

function matchesRule(ruleValues: string[] | undefined, source: string): boolean {
	if (!ruleValues || ruleValues.length === 0) return true;
	return ruleValues.some((value) => source.includes(value));
}

function resolveSpecificNarrative(params: { checkType?: string; title?: string; detail?: string }): ImpactNarrative | undefined {
	const checkType = params.checkType?.toUpperCase();
	const title = params.title?.toLowerCase() ?? '';
	const detail = params.detail?.toLowerCase() ?? '';

	for (const rule of SPECIFIC_IMPACT_RULES) {
		if (rule.checkType && checkType && rule.checkType !== checkType) continue;
		if (!matchesRule(rule.titleIncludes, title)) continue;
		if (!matchesRule(rule.detailIncludes, detail)) continue;
		return {
			impact: rule.impact,
			adverseConsequences: rule.adverseConsequences,
		};
	}

	return undefined;
}

function getNarrativeFromEntry(entry: ExplanationEntry | undefined): ImpactNarrative | undefined {
	if (!entry) return undefined;
	if (!entry.impact && !entry.adverseConsequences) return undefined;
	return {
		impact: entry.impact,
		adverseConsequences: entry.adverseConsequences,
	};
}

/**
 * Resolve impact/adverse-consequence narrative for a finding context.
 * Uses explicit explanation entries first, then category, then severity fallback.
 */
export function resolveImpactNarrative(params: {
	checkType?: string;
	category?: string;
	status?: string;
	severity?: string;
	title?: string;
	detail?: string;
}): ImpactNarrative {
	const normalizedCheckType = params.checkType?.toUpperCase();
	const normalizedStatus = params.status?.toUpperCase();
	const normalizedSeverity = params.severity?.toLowerCase();
	const derivedCheckType = params.category ? CATEGORY_TO_CHECKTYPE[params.category.toLowerCase()] : undefined;

	// A recognised finding signature is the most precise source available: it
	// describes THIS finding rather than the bucket it falls into, so it outranks
	// even the exact TYPE_STATUS entry (whose narrative describes the bucket's
	// enumerated example causes).
	const signatureType = normalizedCheckType ?? derivedCheckType;
	if (signatureType) {
		const signature = resolveDetailSignature(signatureType, params.status ?? params.severity, params.detail);
		if (signature) {
			return {
				impact: signature.template.impact,
				adverseConsequences: signature.template.adverseConsequences,
			};
		}
	}

	if (normalizedCheckType && normalizedStatus) {
		const narrative = getNarrativeFromEntry(EXPLANATIONS[`${normalizedCheckType}_${normalizedStatus}`]);
		if (narrative) return narrative;
	}

	if (derivedCheckType && normalizedStatus) {
		const narrative = getNarrativeFromEntry(EXPLANATIONS[`${derivedCheckType}_${normalizedStatus}`]);
		if (narrative) return narrative;
	}

	// Title/detail-aware specific rules are MORE precise than the generic
	// per-(type,severity) EXPLANATIONS entries, so resolve them before the
	// severity-keyed lookup below.
	const specificNarrative = resolveSpecificNarrative({
		checkType: normalizedCheckType ?? derivedCheckType,
		title: params.title,
		detail: params.detail,
	});
	if (specificNarrative) return specificNarrative;

	if (normalizedCheckType && normalizedSeverity) {
		const narrative = getNarrativeFromEntry(EXPLANATIONS[`${normalizedCheckType}_${normalizedSeverity.toUpperCase()}`]);
		if (narrative) return narrative;
	}

	if (derivedCheckType && normalizedSeverity) {
		const narrative = getNarrativeFromEntry(EXPLANATIONS[`${derivedCheckType}_${normalizedSeverity.toUpperCase()}`]);
		if (narrative) return narrative;
	}

	if (normalizedCheckType && CATEGORY_FALLBACK_IMPACT[normalizedCheckType]) {
		return CATEGORY_FALLBACK_IMPACT[normalizedCheckType];
	}

	if (derivedCheckType && CATEGORY_FALLBACK_IMPACT[derivedCheckType]) {
		return CATEGORY_FALLBACK_IMPACT[derivedCheckType];
	}

	if (normalizedSeverity && SEVERITY_FALLBACK_IMPACT[normalizedSeverity]) {
		return SEVERITY_FALLBACK_IMPACT[normalizedSeverity];
	}

	return {};
}

export function explainFinding(checkType: string, status: string, details?: string): ExplanationResult {
	const normalizedType = checkType.toUpperCase();
	const key = `${normalizedType}_${status.toUpperCase()}`;

	// Exact checkType_STATUS lookup only. We deliberately do NOT fall back across
	// status families (e.g. a "high" severity finding must not resolve a "_FAIL"
	// entry): FAIL/MISSING entries assert the control is ABSENT, whereas a severity
	// finding usually means the control is PRESENT but weak — mapping between them
	// would surface a confident falsehood (e.g. "No DKIM Records Found" for a
	// weak-key finding). Known severity-status content is provided by explicit
	// TYPE_SEVERITY entries in EXPLANATIONS; unknown combinations fall to DEFAULT.
	const baseEntry: ExplanationTemplate | undefined = EXPLANATIONS[key];

	// `details` is the caller's disambiguator within the bucket. When it names a
	// signature we recognise, that signature REPLACES the bucket wording wholesale
	// (title, explanation, impact, consequences, recommendation, references) — a
	// partial merge would leave bucket narrative describing a different defect.
	const signature = resolveDetailSignature(normalizedType, status, details);

	// Severity keeps tracking the caller's status (via the bucket entry) rather
	// than the signature, so a signature can serve the same defect reported at
	// different severities without contradicting the status echoed back.
	const severity = baseEntry?.severity ?? DEFAULT_EXPLANATION.severity;

	let entry: ExplanationTemplate;
	if (signature) {
		entry = { ...signature.template, severity };
	} else if (details?.trim() && (baseEntry?.genericExplanation || baseEntry?.genericRecommendation)) {
		// Detail supplied but unrecognised: fall back to wording that asserts no
		// specific cause. Abstaining beats inventing one — the bucket's default
		// text names example causes that may have nothing to do with this finding.
		entry = {
			...baseEntry,
			explanation: baseEntry.genericExplanation ?? baseEntry.explanation,
			recommendation: baseEntry.genericRecommendation ?? baseEntry.recommendation,
		};
	} else {
		entry = baseEntry ?? DEFAULT_EXPLANATION;
	}

	const narrative = resolveImpactNarrative({ checkType: normalizedType, status, detail: details });

	// Fields are copied explicitly rather than spread: `genericExplanation` /
	// `genericRecommendation` are authoring inputs, not part of the tool's output
	// contract, and must not leak into structuredContent.
	return {
		checkType: normalizedType,
		status,
		details,
		title: entry.title,
		severity,
		explanation: entry.explanation,
		recommendation: entry.recommendation,
		references: entry.references,
		impact: entry.impact ?? narrative.impact,
		adverseConsequences: entry.adverseConsequences ?? narrative.adverseConsequences,
		...(signature ? { matchedSignature: signature.id } : {}),
	};
}

export function formatExplanation(result: ExplanationResult, format: OutputFormat = 'full'): string {
	if (format === 'compact') {
		const lines = [
			`${result.title} (${result.checkType} | ${result.status})`,
			sanitizeOutputText(result.explanation, 200),
			`Recommendation: ${sanitizeOutputText(result.recommendation, 200)}`,
		];
		return lines.join('\n');
	}

	const lines = [`## ${result.title}`, `**Check Type:** ${result.checkType} | **Status:** ${result.status}`, ''];

	lines.push(`### What this means`, result.explanation, '');

	if (result.impact) {
		lines.push(`### Potential Impact`, result.impact, '');
	}

	if (result.adverseConsequences) {
		lines.push(`### Adverse Consequences`, result.adverseConsequences, '');
	}

	lines.push(`### Recommendation`, result.recommendation, '', `### References`, ...result.references.map((reference) => `- ${reference}`));
	return lines.join('\n');
}
