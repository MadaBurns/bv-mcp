// SPDX-License-Identifier: BUSL-1.1

/**
 * Category interaction scoring — post-scoring adjustments for correlated weaknesses.
 *
 * Applied after computeScanScore() as a separate penalty layer.
 * Does NOT modify categoryScores — only adjusts the overall score.
 * Existing compare_baseline CI/CD workflows continue to work identically.
 */

import type { CheckCategory, ScanScore } from './scoring-model';
import { scoreToGrade } from './scoring-engine';
import type { ScoringConfig } from './scoring-config';

/** A condition that must be met for an interaction rule to fire. */
interface InteractionCondition {
	category: CheckCategory;
	/** Maximum category score for the condition to be true (score <= maxScore). */
	maxScore?: number;
	/** Minimum category score for the condition to be true (score >= minScore). */
	minScore?: number;
}

/** An interaction rule that applies a penalty when all conditions are met. */
export interface InteractionRule {
	/** Unique identifier for the interaction. */
	id: string;
	/** All conditions must be satisfied for the penalty to apply. */
	conditions: InteractionCondition[];
	/** Additional points deducted from the overall score. */
	overallPenalty: number;
	/** Human-readable explanation of the interaction effect. */
	narrative: string;
}

/** Result of applying interaction rules to a scan score. */
export interface InteractionEffect {
	ruleId: string;
	penalty: number;
	narrative: string;
}

/** Interaction rules — correlated weaknesses that amplify risk. */
export const INTERACTION_RULES: InteractionRule[] = [
	{
		id: 'weak_dkim_permissive_dmarc',
		conditions: [
			{ category: 'dkim', maxScore: 40 },
			{ category: 'dmarc', maxScore: 60 },
		],
		overallPenalty: 5,
		narrative: 'Weak DKIM combined with permissive DMARC creates multiplicative spoofing risk — attackers can forge messages that pass relaxed alignment checks.',
	},
	{
		id: 'no_spf_no_dmarc',
		conditions: [
			{ category: 'spf', maxScore: 0 },
			{ category: 'dmarc', maxScore: 0 },
		],
		overallPenalty: 10,
		narrative: 'Complete absence of both SPF and DMARC means any server can send as this domain with no detection mechanism.',
	},
	{
		id: 'weak_dnssec_enforcing_dmarc',
		conditions: [
			{ category: 'dmarc', minScore: 80 },
			{ category: 'dnssec', maxScore: 40 },
		],
		overallPenalty: 3,
		narrative: 'Strong email authentication is in place but DNSSEC is weak or absent — DNS tampering could undermine authentication records.',
	},
	{
		id: 'no_spf_no_dkim',
		conditions: [
			{ category: 'spf', maxScore: 0 },
			{ category: 'dkim', maxScore: 0 },
		],
		overallPenalty: 5,
		narrative: 'Neither SPF nor DKIM is configured — DMARC alignment cannot be satisfied through either mechanism, making enforcement ineffective even if DMARC is published.',
	},
	{
		id: 'weak_ssl_no_http_security',
		conditions: [
			{ category: 'ssl', maxScore: 40 },
			{ category: 'http_security', maxScore: 30 },
		],
		overallPenalty: 3,
		narrative: 'Weak SSL/TLS combined with missing HTTP security headers exposes the domain to man-in-the-middle attacks and content injection.',
	},
];

/** Check if a single condition is satisfied by the category scores. */
function conditionMet(condition: InteractionCondition, categoryScores: Record<string, number>): boolean {
	const score = categoryScores[condition.category];
	if (score === undefined) return false;

	if (condition.maxScore !== undefined && score > condition.maxScore) return false;
	if (condition.minScore !== undefined && score < condition.minScore) return false;

	return true;
}

/**
 * Apply interaction penalties to a scan score.
 *
 * This is a post-scoring adjustment — categoryScores remain unchanged,
 * only the overall score and grade are updated.
 *
 * @param score - The computed scan score from computeScanScore()
 * @param config - Optional scoring config for grade computation
 * @returns Updated score with interaction penalties applied, plus the list of triggered effects
 */
export function applyInteractionPenalties(
	score: ScanScore,
	config?: ScoringConfig,
): { adjustedScore: ScanScore; effects: InteractionEffect[] } {
	const effects: InteractionEffect[] = [];
	let totalPenalty = 0;

	for (const rule of INTERACTION_RULES) {
		const allMet = rule.conditions.every((c) => conditionMet(c, score.categoryScores));
		if (allMet) {
			effects.push({
				ruleId: rule.id,
				penalty: rule.overallPenalty,
				narrative: rule.narrative,
			});
			totalPenalty += rule.overallPenalty;
		}
	}

	if (totalPenalty === 0) {
		return { adjustedScore: score, effects };
	}

	const adjustedOverall = Math.max(0, score.overall - totalPenalty);
	const adjustedGrade = scoreToGrade(adjustedOverall, config);

	// Update summary if grade changed
	let summary = score.summary;
	if (adjustedGrade !== score.grade) {
		summary = summary.replace(`Grade: ${score.grade}`, `Grade: ${adjustedGrade}`);
	}

	return {
		adjustedScore: {
			...score,
			overall: adjustedOverall,
			grade: adjustedGrade,
			summary,
		},
		effects,
	};
}
