// SPDX-License-Identifier: BUSL-1.1

/**
 * End-to-end composition test for the DMARC impersonation escalation feature.
 *
 * It exercises the REAL pipeline in order —
 *   applyScanPostProcessing (label escalation)
 *     -> computeScanScore (category + tier scoring)
 *       -> applyInteractionPenalties (overall-score penalty)
 * — to prove the two new mechanisms stay coherent: a `critical` DMARC label never
 * ships without the matching `impersonation_weak_dmarc` score penalty, and vice
 * versa. Unit tests in scan-post-processing.spec.ts and category-interactions.spec.ts
 * cover each mechanism in isolation; this guards their COMPOSITION, where the
 * label-vs-score divergence the audit set out to kill would otherwise hide —
 * especially for p=none, whose un-escalated DMARC score (~70-80) slips past the
 * rule's `dmarc <= 60` threshold until escalation drops it.
 */

import { describe, it, expect } from 'vitest';
import { type CheckResult, buildCheckResult, createFinding } from '../src/lib/scoring';
import { computeScanScore } from '@blackveil/dns-checks/scoring';
import { applyInteractionPenalties } from '../src/lib/category-interactions';

const mailMx = (): CheckResult => buildCheckResult('mx', [createFinding('mx', 'MX records found', 'info', '2 MX records configured.')]);

const noDmarc = (): CheckResult =>
	buildCheckResult('dmarc', [createFinding('dmarc', 'No DMARC record found', 'high', 'No DMARC record found at _dmarc.example.com.')]);

/** A realistic p=none record: monitoring-only policy + the usual relaxed-alignment lows. */
const pNoneDmarc = (): CheckResult =>
	buildCheckResult('dmarc', [
		createFinding('dmarc', 'DMARC policy set to none', 'medium', 'DMARC policy is "none" which only monitors.'),
		createFinding('dmarc', 'Relaxed DKIM alignment', 'low', 'adkim relaxed.'),
		createFinding('dmarc', 'Relaxed SPF alignment', 'low', 'aspf relaxed.'),
	]);

const activeLookalikes = (): CheckResult =>
	buildCheckResult('lookalikes', [
		createFinding('lookalikes', 'Active lookalike domain detected', 'medium', 'examp1e.com resolves with mail infrastructure.'),
	]);

const cleanLookalikes = (): CheckResult =>
	buildCheckResult('lookalikes', [createFinding('lookalikes', 'No active lookalike domains detected', 'info', 'No active registrations.')]);

async function runPipeline(results: CheckResult[]) {
	const { applyScanPostProcessing } = await import('../src/tools/scan/post-processing');
	const post = await applyScanPostProcessing('example.com', results);
	// No DomainContext → default scoring, where DEFAULT_CRITICAL_CATEGORIES includes
	// dmarc at full core weight (the mail-domain-equivalent default).
	const score = computeScanScore(post);
	const { adjustedScore, effects } = applyInteractionPenalties(score);
	const dmarc = post.find((r) => r.category === 'dmarc');
	const ruleFired = effects.some((e) => e.ruleId === 'impersonation_weak_dmarc');
	return { post, dmarc, overall: adjustedScore.overall, ruleFired, effects };
}

describe('DMARC impersonation escalation — full pipeline coherence', () => {
	it('no-DMARC + impersonation (#5): critical label AND the rule fires AND scores below the no-impersonation case (#2)', async () => {
		const withImpersonation = await runPipeline([mailMx(), noDmarc(), activeLookalikes()]);
		const without = await runPipeline([mailMx(), noDmarc(), cleanLookalikes()]);

		// #5: label escalated to critical, score penalty applied.
		expect(withImpersonation.dmarc?.findings[0].severity).toBe('critical');
		expect(withImpersonation.ruleFired).toBe(true);

		// #2: routine sender — demoted high, rule does NOT fire.
		expect(without.dmarc?.findings[0].severity).toBe('high');
		expect(without.ruleFired).toBe(false);

		// The justified-critical case must score strictly worse.
		expect(withImpersonation.overall).toBeLessThan(without.overall);
	});

	it('p=none + impersonation: critical label AND the rule fires (escalation drops dmarc score under the <=60 threshold)', async () => {
		const result = await runPipeline([mailMx(), pNoneDmarc(), activeLookalikes()]);
		const none = result.dmarc?.findings.find((f) => f.title === 'DMARC policy set to none');
		expect(none?.severity).toBe('critical');
		expect(result.ruleFired).toBe(true);
	});

	it('p=none WITHOUT impersonation: stays medium, rule does not fire, and the un-escalated dmarc score is above the rule threshold', async () => {
		const result = await runPipeline([mailMx(), pNoneDmarc(), cleanLookalikes()]);
		const none = result.dmarc?.findings.find((f) => f.title === 'DMARC policy set to none');
		expect(none?.severity).toBe('medium');
		expect(result.ruleFired).toBe(false);

		// Documents WHY the escalation-first ordering matters: an un-escalated p=none
		// scores ABOVE 60, so the score-based rule alone would miss it. Coherence comes
		// from escalation running first and lowering this score.
		const dmarcScore = computeScanScore(result.post).categoryScores.dmarc;
		expect(dmarcScore).toBeGreaterThan(60);
	});
});
