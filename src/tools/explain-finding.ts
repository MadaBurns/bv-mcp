// SPDX-License-Identifier: BUSL-1.1

/**
 * Explain Finding tool.
 * Provides static explanations for DNS security findings.
 * No AI binding required - uses a built-in knowledge base.
 */

import {
	CATEGORY_FALLBACK_IMPACT,
	CATEGORY_TO_CHECKTYPE,
	DEFAULT_EXPLANATION,
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
}

type ExplanationEntry = ExplanationTemplate;

function matchesRule(ruleValues: string[] | undefined, source: string): boolean {
	if (!ruleValues || ruleValues.length === 0) return true;
	return ruleValues.some((value) => source.includes(value));
}

function resolveSpecificNarrative(params: {
	checkType?: string;
	title?: string;
	detail?: string;
}): ImpactNarrative | undefined {
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

	if (normalizedCheckType && normalizedStatus) {
		const narrative = getNarrativeFromEntry(EXPLANATIONS[`${normalizedCheckType}_${normalizedStatus}`]);
		if (narrative) return narrative;
	}

	if (normalizedCheckType && normalizedSeverity) {
		const narrative = getNarrativeFromEntry(EXPLANATIONS[`${normalizedCheckType}_${normalizedSeverity.toUpperCase()}`]);
		if (narrative) return narrative;
	}

	if (derivedCheckType && normalizedStatus) {
		const narrative = getNarrativeFromEntry(EXPLANATIONS[`${derivedCheckType}_${normalizedStatus}`]);
		if (narrative) return narrative;
	}

	if (derivedCheckType && normalizedSeverity) {
		const narrative = getNarrativeFromEntry(EXPLANATIONS[`${derivedCheckType}_${normalizedSeverity.toUpperCase()}`]);
		if (narrative) return narrative;
	}

	const specificNarrative = resolveSpecificNarrative({
		checkType: normalizedCheckType ?? derivedCheckType,
		title: params.title,
		detail: params.detail,
	});
	if (specificNarrative) return specificNarrative;

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

	// 1. Try checkType_STATUS key
	let entry: ExplanationTemplate | undefined = EXPLANATIONS[key];

	// 2. Fall back to default
	if (!entry) {
		entry = DEFAULT_EXPLANATION;
	}

	const narrative = resolveImpactNarrative({ checkType: normalizedType, status, detail: details });

	return {
		checkType: normalizedType,
		status,
		details,
		...entry,
		impact: entry.impact ?? narrative.impact,
		adverseConsequences: entry.adverseConsequences ?? narrative.adverseConsequences,
	};
}

export function formatExplanation(result: ExplanationResult): string {
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
