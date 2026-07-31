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

import type { CheckResult, CheckStatus, ScanEvidence } from '../types';

export type { ScanEvidence };

/**
 * The single source of truth for "was this check genuinely measured?" — the predicate every
 * other measured/unmeasured question in this package (the evidence gate, per-category
 * inclusion in the weighted score, profile-detection's failure ratio) must share.
 *
 * Allowlist semantics, deliberately: `undefined` or `'completed'` means measured; anything
 * else means NOT measured. This is the opposite shape from a denylist
 * (`status !== 'timeout' && status !== 'error'`), and the difference is load-bearing. The
 * `CheckStatus` union is closed to `'completed' | 'timeout' | 'error'`, but a `CheckResult`
 * re-read from an untrusted source (e.g. `JSON.parse` of a cached KV entry with no Zod
 * revalidation) can carry a string outside that union at runtime — a version-skewed deploy is
 * enough. A denylist treats that unknown value as measured (it matches neither excluded
 * literal) and lets it enter the weighted score at full weight with whatever score/finding
 * data happens to be attached — `computeGenericScore`'s `categoryScores[key] ?? 100` will even
 * award full credit for a garbage/missing score. The allowlist form treats anything that
 * isn't affirmatively `'completed'` (or absent, meaning "ran normally") as unmeasured, which is
 * the safe default for a governing invariant of "an incomplete measurement must never produce
 * a confident output."
 *
 * Accepts a widened `string` input (not just `CheckStatus`) so a status read from an
 * untrusted/unvalidated source is representable at call sites without an `as any` cast.
 */
export function isCheckMeasured(checkStatus: CheckStatus | string | undefined): boolean {
	return checkStatus === undefined || checkStatus === 'completed';
}

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
		if (isCheckMeasured(result.checkStatus)) {
			completed += 1;
		}
	}
	return { attempted, completed, ratio: attempted === 0 ? 0 : completed / attempted };
}

/**
 * Whether a scan measured enough to be graded.
 *
 * `attempted === 0` yields `ratio: 0`, which is below every threshold in the
 * NORMAL (0, 1] operating range — but NOT below a threshold of exactly `0`:
 * `0 >= 0` is `true`, so this predicate alone would call zero evidence
 * "sufficient" for a caller that configures `evidenceSufficiency: 0`. There is
 * deliberately no `attempted === 0` carve-out inside this function; instead
 * `computeScanScore`'s own `results.length === 0` branch enforces "zero
 * evidence is NEVER sufficient" unconditionally, independent of whatever
 * threshold a config supplies — see the engine-level test pinning this. The
 * legacy behaviour (`computeScanScore([])` → seeded 100 / 'A+') handed the
 * best possible grade to a caller that submitted zero evidence, and this
 * package is a published SSOT — an external consumer must not be able to
 * obtain a confident grade from nothing, not even via a `0` threshold.
 * Production scan paths are unaffected (they back-fill all 19 categories, so
 * `attempted` is never 0 there).
 */
export function isEvidenceSufficient(evidence: ScanEvidence, threshold: number = EVIDENCE_SUFFICIENCY_THRESHOLD): boolean {
	return evidence.ratio >= threshold;
}

/** Human-readable explanation for an ungraded scan. Safe to render verbatim in a customer report. */
export function buildEvidenceNote(evidence: ScanEvidence, threshold: number): string {
	// The zero-submission case gets its OWN sentence rather than falling through to the
	// percentage-based prose below: "Only 0 of 0 checks completed (0%)... Re-run the
	// scan." is an awkward, borderline-nonsensical thing to hand a customer — there is
	// no scan to re-run, no partial coverage to describe, just an empty submission.
	if (evidence.attempted === 0) {
		return 'No checks were submitted for scoring, so no grade can be issued. This is a measurement gap, not a security verdict.';
	}

	// Floor the achieved percentage (never round it up): this note only renders when
	// evidence is insufficient, so it always claims the achieved percentage is BELOW
	// the threshold percentage. Rounding both the same way can make the two collide
	// at the boundary (e.g. 119/200 = 59.5% rounds to "60%", which self-contradicts
	// "60% is below the 60% threshold"). The threshold percentage stays rounded — it
	// is a configured value, not a measurement, so there is no boundary hazard there.
	const pct = Math.floor(evidence.ratio * 100);
	const minPct = Math.round(threshold * 100);
	return (
		`Only ${evidence.completed} of ${evidence.attempted} checks completed (${pct}%), below the ${minPct}% evidence threshold. ` +
		`No grade is reported: this is a measurement gap, not a security verdict. Re-run the scan.`
	);
}
