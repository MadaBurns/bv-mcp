// SPDX-License-Identifier: BUSL-1.1

/**
 * The single vocabulary for "this scan produced no grade", and the single place
 * a `score/grade` pair is turned into display text.
 *
 * A deliberately tiny leaf module (no imports) so every formatter in `src/tools/`
 * can depend on it without an import cycle through the scan orchestrator.
 */

/**
 * The SINGLE rendered token for a scan that produced no grade. One constant so
 * the same state cannot render one way in one report and another way elsewhere.
 * Deliberately NOT the retired N/A sentinel — that reads as "not applicable", a
 * different state already tracked by `notApplicableCategories`.
 */
export const UNGRADED_DISPLAY = 'not measured';

/**
 * Render a score/grade pair, abstaining when either half is missing.
 *
 * Every customer-visible formatter MUST route through this rather than
 * interpolating `${score}/100 (${grade})` itself. Interpolating a `number | null`
 * directly is invisible to TypeScript — `${null}` is legal under strict — and
 * four shipped tools printed `null/100 (null)` into client reports with
 * typecheck, lint and every spec green. `test/audits/ungraded-representation`
 * enforces this as a corpus-wide rule.
 *
 * A score of `0` with a real grade is a MEASUREMENT and renders normally; only
 * `null` means "never measured".
 */
export function formatScoreGrade(score: number | null | undefined, grade: string | null | undefined): string {
	if (score === null || score === undefined || grade === null || grade === undefined) return UNGRADED_DISPLAY;
	return `${score}/100 (${grade})`;
}
