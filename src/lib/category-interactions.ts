// SPDX-License-Identifier: BUSL-1.1

/**
 * Category interaction scoring — post-scoring adjustments for correlated weaknesses.
 *
 * Applied after computeScanScore() as a separate penalty layer.
 * Does NOT modify categoryScores — only adjusts the overall score.
 * Existing compare_baseline CI/CD workflows continue to work identically.
 */

import type { CheckCategory, ScanScore } from '@blackveil/dns-checks/scoring';
import { scoreToGrade } from '@blackveil/dns-checks/scoring';
import type { ScoringConfig } from '@blackveil/dns-checks/scoring';

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
		narrative:
			'Weak DKIM combined with permissive DMARC creates multiplicative spoofing risk — attackers can forge messages that pass relaxed alignment checks.',
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
		// Score-penalty counterpart to the DMARC label-escalation in
		// scan/post-processing.ts (`escalateDmarcForImpersonation`). Both fire on the
		// SAME signal — active `lookalikes` impersonation — so a critical DMARC label
		// never ships without a matching score consequence (and vice versa).
		//
		// Ordering matters: interaction rules run AFTER post-processing + scoring, so
		// `dmarc` here is the POST-escalation category score. When impersonation is
		// present the escalation rewrites the weak-DMARC finding to `critical`, which
		// drops the dmarc category to 0 (no record, missing-control) or ~45 (p=none,
		// critical penalty) — both <= 60. So `dmarc <= 60` reliably captures exactly
		// the escalated cases, including p=none (whose UN-escalated score is ~70-80 and
		// would otherwise slip past this threshold). Without impersonation the lookalikes
		// gate below fails and neither mechanism fires.
		id: 'impersonation_weak_dmarc',
		conditions: [
			// Task 7b (2026-07-27) — what satisfies this condition today, stated
			// precisely, because two earlier revisions of this comment were wrong.
			//
			// The `lookalikes` category drops to/below 85 when the check emits a
			// finding above `info`. Since Task 7b that happens on the
			// THREAT-OBSERVATION axis (`metadata.findingAxis ===
			// 'threat_observation'`): a #264-calibrated observation about a
			// confusable domain's infrastructure (e.g. live MX on a disposable
			// provider), plus the aggregate HIGH summary. ATTRIBUTION-axis findings
			// (`'attribution'`) are capped at `info` for every non-`owned_by_seed`
			// verdict and cannot move the score.
			//
			// CORRECTION (fix round 1, F3): the previous revision claimed that under
			// Task 7 "every lookalikes finding was capped at info", so this rule was
			// dead code. That was FALSE. The recon CT-corroboration finding in
			// check-lookalikes.ts emits `'medium'` and has never been routed through
			// the ownership gate, so on an operator deploy with the BV_RECON binding
			// this condition was satisfiable throughout — the earlier revision
			// before THAT one, claiming it fired whenever a calibrated medium/high
			// lookalike was found, was the one closer to the truth. What Task 7
			// actually broke was the DNS-derived path (per-candidate and summary
			// findings), which is what 7b restored. Nor is it true, as that revision
			// also claimed, that an owned-by-seed candidate "can never trigger this
			// rule": the recon finding is scoped to the SCANNED domain and fires
			// independently of any candidate's ownership verdict. What IS true: no
			// finding this rule keys on makes an ownership claim about a third
			// party's domain.
			{ category: 'lookalikes', maxScore: 85 },
			// Weak/absent DMARC, as left by the escalation pass (see above).
			{ category: 'dmarc', maxScore: 60 },
		],
		overallPenalty: 8,
		narrative:
			'Active lookalike/impersonation domains were detected while DMARC enforcement is weak or absent — receivers will not reject spoofed mail, turning a monitoring gap into an exploitable impersonation channel.',
	},
	{
		id: 'weak_dnssec_enforcing_dmarc',
		conditions: [
			{ category: 'dmarc', minScore: 80 },
			{ category: 'dnssec', maxScore: 40 },
		],
		overallPenalty: 3,
		narrative:
			'Strong email authentication is in place but DNSSEC is weak or absent — DNS tampering could undermine authentication records.',
	},
	{
		id: 'no_spf_no_dkim',
		conditions: [
			{ category: 'spf', maxScore: 0 },
			{ category: 'dkim', maxScore: 0 },
		],
		overallPenalty: 5,
		narrative:
			'Neither SPF nor DKIM is configured — DMARC alignment cannot be satisfied through either mechanism, making enforcement ineffective even if DMARC is published.',
	},
	{
		id: 'weak_ssl_no_http_security',
		conditions: [
			{ category: 'ssl', maxScore: 40 },
			{ category: 'http_security', maxScore: 30 },
		],
		overallPenalty: 3,
		narrative:
			'Weak SSL/TLS combined with missing HTTP security headers exposes the domain to man-in-the-middle attacks and content injection.',
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
	// An ungraded score has nothing to penalise. Returning it untouched keeps
	// `null` propagating rather than turning it into NaN via `null - penalty`.
	if (score.overall === null || score.grade === null) {
		return { adjustedScore: score, effects: [] };
	}

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
