// SPDX-License-Identifier: BUSL-1.1

/**
 * Scan evidence accounting — how much of a scan actually completed.
 *
 * The scanner's failure mode this module exists to remove: when most checks could
 * not run, the engine still emitted a confident letter grade, so a scan that
 * measured almost nothing was presented as a scan of a domain that HAS almost
 * nothing. Two states must stay strictly separate:
 *
 *   - INCONCLUSIVE     — we could not measure it (`checkStatus` 'timeout' | 'error')
 *   - NOT APPLICABLE   — we measured, and the control genuinely does not apply
 *
 * This module owns the first. It is deliberately dependency-free (only `../types`)
 * so `scoring/config.ts` can reference the threshold constant without an import
 * cycle.
 *
 * Runtime-agnostic, Workers-safe: no Node APIs.
 */

import type { CheckResult, ScanEvidence } from '../types';

export type { ScanEvidence };

/**
 * The single source of truth for the evidence-sufficiency cut-off: a scan must
 * complete at least 60% of its attempted checks to receive a grade.
 *
 * This is NOT a scoring cut-point. It does not change what any grade means; it
 * only decides whether a grade is emitted at all. Grade bands, category weights
 * and the check matrix are untouched by it.
 *
 * Override at runtime via `SCORING_CONFIG` → `thresholds.evidenceSufficiency`
 * (clamped to [0, 1] by `parseScoringConfig`). Never compare against a numeric
 * literal at a call site.
 */
export const EVIDENCE_SUFFICIENCY_THRESHOLD = 0.6;

/** Count how much of a scan completed. See {@link ScanEvidence}. */
export function computeScanEvidence(results: CheckResult[]): ScanEvidence {
	const attempted = results.length;
	let completed = 0;
	for (const result of results) {
		if (result.checkStatus === undefined || result.checkStatus === 'completed') {
			completed += 1;
		}
	}
	return { attempted, completed, ratio: attempted === 0 ? 0 : completed / attempted };
}

/**
 * Whether a scan measured enough to be graded.
 *
 * `attempted === 0` yields `ratio: 0`, which is below every valid threshold, so
 * an empty result set is NEVER sufficient evidence. This is deliberate: the
 * legacy behaviour (`computeScanScore([])` → seeded 100 / 'A+') handed the best
 * possible grade to a caller that submitted zero evidence, and this package is a
 * published SSOT — an external consumer must not be able to obtain a confident
 * grade from nothing. Production scan paths are unaffected (they back-fill all
 * 19 categories, so `attempted` is never 0 there).
 */
export function isEvidenceSufficient(evidence: ScanEvidence, threshold: number = EVIDENCE_SUFFICIENCY_THRESHOLD): boolean {
	return evidence.ratio >= threshold;
}

/** Human-readable explanation for an ungraded scan. Safe to render verbatim in a customer report. */
export function buildEvidenceNote(evidence: ScanEvidence, threshold: number): string {
	const pct = Math.round(evidence.ratio * 100);
	const minPct = Math.round(threshold * 100);
	return (
		`Only ${evidence.completed} of ${evidence.attempted} checks completed (${pct}%), below the ${minPct}% evidence threshold. ` +
		`No grade is reported: this is a measurement gap, not a security verdict. Re-run the scan.`
	);
}
