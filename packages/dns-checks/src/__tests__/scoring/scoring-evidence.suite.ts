// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared scoring-evidence test suite — the single source of truth for these tests.
 *
 * Run against BOTH import surfaces so source↔built (dist/DTS) drift is caught:
 *   - packages/dns-checks/src/__tests__/scoring/scoring-evidence.spec.ts → source (`../../scoring`)
 *   - test/scoring-evidence.spec.ts → built package (`@blackveil/dns-checks/scoring`)
 *
 * The two thin spec files inject their respective module; the assertions live
 * here once, so the trees can't drift apart. NOT a `.spec.ts`/`.test.ts`, so
 * neither vitest run collects it directly.
 */

import { describe, expect, it } from 'vitest';
import type { CheckCategory, CheckResult, CheckStatus } from '../../scoring';

/** The scoring module under test — source or built package, injected by the caller. */
type ScoringModule = typeof import('../../scoring');

export function defineScoringEvidenceSuite(s: ScoringModule): void {
	const { computeScanEvidence, isEvidenceSufficient, buildEvidenceNote, EVIDENCE_SUFFICIENCY_THRESHOLD, DEFAULT_SCORING_CONFIG } = s;

	/** Minimal CheckResult with an explicit execution status. No findings — evidence counts execution, not content. */
	function res(category: CheckCategory, status: CheckStatus | undefined): CheckResult {
		const base = { category, passed: status === 'completed' || status === undefined, score: 100, findings: [] as CheckResult['findings'] };
		return status === undefined ? base : { ...base, checkStatus: status };
	}

	describe('scoring-evidence', () => {
		it('counts completed vs attempted, treating an ABSENT checkStatus as completed', () => {
			const evidence = computeScanEvidence([
				res('spf', 'completed'),
				res('dmarc', undefined),
				res('dnssec', 'timeout'),
				res('ssl', 'error'),
			]);
			expect(evidence.attempted).toBe(4);
			expect(evidence.completed).toBe(2);
			expect(evidence.ratio).toBeCloseTo(0.5, 10);
		});

		it('reports ratio 0 for an empty result set (spec D2.2)', () => {
			expect(computeScanEvidence([])).toEqual({ attempted: 0, completed: 0, ratio: 0 });
		});

		it('reports ratio 1 when every check completed', () => {
			const evidence = computeScanEvidence([res('spf', 'completed'), res('dmarc', 'completed')]);
			expect(evidence.ratio).toBe(1);
		});

		it('exposes the threshold as a single named constant of 0.6', () => {
			expect(EVIDENCE_SUFFICIENCY_THRESHOLD).toBe(0.6);
			expect(DEFAULT_SCORING_CONFIG.thresholds.evidenceSufficiency).toBe(EVIDENCE_SUFFICIENCY_THRESHOLD);
		});

		it('is sufficient AT the threshold and insufficient just below it (gate is strict-less-than)', () => {
			// 12/20 = 0.60 exactly → sufficient. 11/20 = 0.55 → insufficient.
			expect(isEvidenceSufficient({ attempted: 20, completed: 12, ratio: 0.6 })).toBe(true);
			expect(isEvidenceSufficient({ attempted: 20, completed: 11, ratio: 0.55 })).toBe(false);
		});

		it('treats an EMPTY result set as INSUFFICIENT at the default threshold — zero evidence can never earn a grade (DD1 as overridden)', () => {
			// ratio 0 sits below every threshold in the NORMAL (0, 1] range — including the
			// default — and there is deliberately no `attempted === 0` carve-out inside this
			// predicate: this package is a published SSOT, and the legacy seeded-100/'A+' for
			// an empty submission handed the best possible grade to a caller that provided
			// zero evidence. NOTE: this predicate alone is NOT the sole enforcement — a
			// threshold of exactly `0` makes `ratio >= threshold` true even for zero evidence
			// (`0 >= 0`). `computeScanScore`'s own `results.length === 0` branch is what
			// actually makes the empty case unconditional, independent of any configured
			// threshold; see the engine-level "ungrades the empty set even at threshold 0" test.
			expect(isEvidenceSufficient({ attempted: 0, completed: 0, ratio: 0 })).toBe(false);
			// Holds for the default AND for an explicit non-zero threshold.
			expect(isEvidenceSufficient(computeScanEvidence([]), 0.6)).toBe(false);
		});

		it('honours an explicit threshold argument over the default', () => {
			const evidence = { attempted: 10, completed: 7, ratio: 0.7 };
			expect(isEvidenceSufficient(evidence, 0.6)).toBe(true);
			expect(isEvidenceSufficient(evidence, 0.8)).toBe(false);
		});

		it('builds a note naming the real counts, the percentage and the threshold', () => {
			const note = buildEvidenceNote({ attempted: 19, completed: 4, ratio: 4 / 19 }, 0.6);
			expect(note).toContain('4 of 19');
			expect(note).toContain('21%');
			expect(note).toContain('60%');
			// It must read as a measurement gap, not a security verdict.
			expect(note).toContain('not a security verdict');
		});

		it('never states an achieved percentage that rounds up to (or past) the threshold it claims to be below', () => {
			// 119/200 = 0.595 → Math.round gives 60%, which reads as "60% is below the
			// 60% threshold" — a self-contradiction. The achieved percentage must be
			// floored so a note claiming "below the threshold" never names a percentage
			// that equals or exceeds it.
			const note = buildEvidenceNote({ attempted: 200, completed: 119, ratio: 119 / 200 }, 0.6);
			expect(note).toContain('119 of 200');
			expect(note).toContain('59%');
			expect(note).not.toContain('60%,');
			expect(note).toContain('60% evidence threshold');
		});

		it('gives the zero-submission case its own sentence, not "Only 0 of 0 checks completed (0%)... Re-run the scan"', () => {
			// The percentage-based prose is awkward and borderline-nonsensical for zero
			// submitted checks (there's no scan to re-run, no partial coverage to name).
			const note = buildEvidenceNote({ attempted: 0, completed: 0, ratio: 0 }, 0.6);
			expect(note).toBe(
				'No checks were submitted for scoring, so no grade can be issued. This is a measurement gap, not a security verdict.',
			);
			expect(note).not.toContain('Only 0 of 0');
			expect(note).not.toContain('Re-run the scan');
		});
	});
}
