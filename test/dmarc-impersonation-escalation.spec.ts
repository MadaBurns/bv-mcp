// SPDX-License-Identifier: BUSL-1.1

/**
 * End-to-end composition test for the DMARC impersonation escalation feature.
 *
 * It exercises the REAL pipeline in order —
 *   applyScanPostProcessing (label escalation)
 *     -> computeScanScore (category + tier scoring)
 * — to prove the escalation stays coherent with the score: a `critical` DMARC label
 * is reflected in the package-computed DMARC category score (and therefore the
 * overall) because escalation runs BEFORE scoring. Scoring model 2.0.0 removed the
 * post-scoring `impersonation_weak_dmarc` penalty layer, so the escalated finding is
 * the ONLY route by which impersonation moves the score. Unit tests in
 * scan-post-processing.spec.ts cover the escalation in isolation; this guards the
 * COMPOSITION, especially for p=none, whose un-escalated DMARC score stays high
 * until escalation drops it.
 */

import { assert, describe, it, expect } from 'vitest';
import { type CheckResult, buildCheckResult, createFinding } from '../src/lib/scoring';
import { computeScanScore } from '@blackveil/dns-checks/scoring';

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
	const dmarc = post.find((r) => r.category === 'dmarc');
	return { post, dmarc, overall: score.overall, dmarcScore: score.categoryScores.dmarc };
}

describe('DMARC impersonation escalation — full pipeline coherence', () => {
	it('no-DMARC + impersonation (#5): critical label AND scores below the no-impersonation case (#2)', async () => {
		const withImpersonation = await runPipeline([mailMx(), noDmarc(), activeLookalikes()]);
		const without = await runPipeline([mailMx(), noDmarc(), cleanLookalikes()]);

		// #5: label escalated to critical.
		expect(withImpersonation.dmarc?.findings[0].severity).toBe('critical');

		// #2: routine sender — demoted high.
		expect(without.dmarc?.findings[0].severity).toBe('high');

		// The justified-critical case must score strictly worse.
		assert(typeof withImpersonation.overall === 'number');
		assert(typeof without.overall === 'number');
		expect(withImpersonation.overall).toBeLessThan(without.overall);
	});

	it('p=none + impersonation: critical label AND a lower dmarc score than the un-escalated case', async () => {
		const result = await runPipeline([mailMx(), pNoneDmarc(), activeLookalikes()]);
		const clean = await runPipeline([mailMx(), pNoneDmarc(), cleanLookalikes()]);
		const none = result.dmarc?.findings.find((f) => f.title === 'DMARC policy set to none');
		expect(none?.severity).toBe('critical');
		assert(typeof result.dmarcScore === 'number');
		assert(typeof clean.dmarcScore === 'number');
		expect(result.dmarcScore).toBeLessThan(clean.dmarcScore);
	});

	it('p=none WITHOUT impersonation: stays medium and the un-escalated dmarc score stays above 60', async () => {
		const result = await runPipeline([mailMx(), pNoneDmarc(), cleanLookalikes()]);
		const none = result.dmarc?.findings.find((f) => f.title === 'DMARC policy set to none');
		expect(none?.severity).toBe('medium');

		// Documents WHY the escalation-first ordering matters: an un-escalated p=none
		// scores ABOVE 60; only the escalation lowers the score.
		expect(result.dmarcScore).toBeGreaterThan(60);
	});
});
