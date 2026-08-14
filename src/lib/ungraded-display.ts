// SPDX-License-Identifier: BUSL-1.1

/**
 * The single vocabulary for "this scan produced no grade", and the single place
 * a `score/grade` pair is turned into display text.
 *
 * A deliberately tiny module whose ONLY import is the external
 * `@blackveil/dns-checks` package, so every formatter in `src/tools/` can depend
 * on it without an import cycle through the scan orchestrator. That property is
 * about the `src/` import graph, and an external-package edge cannot join it:
 * `packages/dns-checks/src` imports nothing outside relative paths, `zod`, and
 * (in its own tests) `vitest` — it has no edge back into `src/` at all, so it
 * cannot reach the orchestrator. The rule to preserve is therefore narrower than
 * "no imports": no `src/`-relative import may be added here. Pinned by
 * `test/audits/completed-evidence-cross-package-parity.audit.test.ts` (LEG 3).
 *
 * `isCompletedCheck`/`hasCompletedEvidence`/`normalizeCheckStatus` below are the
 * SSOT for "did this check/scan produce usable evidence" on the `src/` side —
 * `test/audits/completed-evidence-predicate-ssot.audit.test.ts` bans any other
 * `src/` module from re-deriving the same check, including this file itself.
 *
 * ACROSS the package boundary there is now ONE implementation, not a twin. This
 * module used to re-derive the comparison independently of
 * `packages/dns-checks/src/scoring/evidence.ts` (`computeScanEvidence`'s
 * per-result completed/attempted accounting), justified on the grounds that no
 * shared import was possible. That justification no longer holds: the package
 * exports the predicate as `isCheckMeasured` on the
 * `@blackveil/dns-checks/scoring` subpath this repo ALREADY consumes
 * (`src/lib/adaptive-weights.ts`, `src/lib/category-interactions.ts`,
 * `src/lib/scoring.ts`), so `isCompletedCheck` DELEGATES to it. The dependency
 * direction is unchanged and correct — `src/` depends on the published package,
 * never the reverse. A change to what "completed" means is now made once, in the
 * package, and reaches this side automatically; the type union itself is
 * likewise imported (`CheckStatus`) rather than hand-copied, so a new member
 * cannot appear on one side of the boundary only.
 */

import type { CheckStatus } from '@blackveil/dns-checks/scoring';
import { isCheckMeasured, nistScoreToGrade } from '@blackveil/dns-checks/scoring';

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

/**
 * The SINGLE customer-facing display grade — the NIST-aligned 6-band letter
 * (`nistScoreToGrade`), recomputed from the unchanged 0–100 score.
 *
 * Two grade scales legitimately coexist (v3.26.0+, #461): the canonical 9-band
 * `scoreToGrade` is the INTERNAL/SSOT scale (`compare_baseline` ordering,
 * `analyze_drift`, `map_compliance`, `generate_fix_plan`, cohort percentiles,
 * `ScanScore.grade`), and this 6-band scale is what a CUSTOMER is shown. The
 * defect class to prevent is not their coexistence — it is two customer-visible
 * surfaces reading DIFFERENT scales and disagreeing on screen about one domain.
 *
 * That has now happened twice. #640: the maturity cap read the 9-band while the
 * report displayed the 6-band, so github.com at 67 printed grade D beside
 * "Stage 4 — Hardened" (9-band C → no cap fired). And `/badge/:domain` rendered
 * `score.grade` — the 9-band letter — so the same domain at 67 showed **C** on
 * its badge and **D** in its report. Both are fixed by consuming THIS function
 * rather than re-deriving a letter, so a display surface cannot drift from the
 * band shown everywhere else.
 *
 * Scores are unchanged by the display scale; only the letter is.
 *
 * Returns `null` when the scan was never graded — callers MUST render
 * {@link UNGRADED_DISPLAY} rather than substitute a letter. Mapping an unscored
 * scan onto `nistScoreToGrade(0)` here would fabricate an 'F' for a domain that
 * does not resolve, which is the exact defect the evidence gate exists to
 * remove. The `grade === null` half of the guard is load-bearing independently
 * of `overall`: it is the engine's own "this was not graded" signal.
 */
export function displayGradeFor(score: { overall: number | null; grade: string | null }): string | null {
	if (score.overall === null || score.grade === null) return null;
	return nistScoreToGrade(score.overall);
}

/**
 * Did this scan attempt any checks at all?
 *
 * The SINGLE spelling of "was anything attempted", shared by
 * `StructuredScanResult.measured` (its documented meaning there — see
 * `hasCompletedEvidence`'s doc below) and by the never-ran (`checks: []`)
 * branch every `assessed`/`caveat` computation in `map_compliance`,
 * `generate_fix_plan`, `map_csc_products`, and `compare_baseline` special-cases.
 * None of those four surfaces use `isMeasured` alone as their assessed/measured
 * predicate any more — a total-outage scan (`checks.length > 0`, but every
 * check's `checkStatus` is `'timeout' | 'error'`) is `isMeasured: true` despite
 * carrying zero usable evidence, which is exactly the gap `hasCompletedEvidence`
 * closes. `isMeasured` still answers a real, narrower question — "did anything
 * run at all" — used to distinguish the never-ran case from both of the other
 * two states.
 *
 * `buildNonResolvingResult` (NXDOMAIN) and `buildDnsBrokenResult`
 * (SERVFAIL/DNSSEC-bogus) emit `checks: []`; `buildUnscoredResult` does NOT — its
 * checks ran and only the scoring bundle failed, so its per-check results stay
 * genuinely evaluable. This predicate keeps those two cases apart.
 *
 * Deliberately typed on the array's length alone (`readonly unknown[]`) rather
 * than on `CheckResult[]`, so this predicate adds no edge to `src/`'s scan
 * orchestrator — the leaf property the file-level doc describes. (The file does
 * import from the external `@blackveil/dns-checks` package; that edge cannot
 * reach the orchestrator, see the file-level doc.)
 */
export function isMeasured(checks: readonly unknown[]): boolean {
	return checks.length > 0;
}

/**
 * Minimal shape this module needs from a check result to answer "did anything
 * complete" — a local structural type instead of importing `CheckResult`, so
 * this file keeps no edge into `src/`'s scan orchestrator.
 *
 * The status TYPE is the package's `CheckStatus`, not a hand-copied
 * `'completed' | 'timeout' | 'error'` literal union. That copy was the second
 * half of the same cross-boundary duplication `isCompletedCheck` had: a new
 * union member added in the package would leave a re-spelled local union
 * silently narrower, and the resulting `CheckResult` would fail to typecheck
 * here — or worse, be narrowed away — while the package considered it valid.
 * Importing the union makes such a member a COMPILE-time event on this side.
 */
interface CheckStatusBearer {
	readonly checkStatus?: CheckStatus;
}

/**
 * There are THREE distinct states a scan's checks can be in, and each is
 * answered by a DIFFERENT predicate:
 *
 * 1. No checks at all — the scan never ran (NXDOMAIN, broken zone;
 *    `checks: []`). `isMeasured` answers "attempted anything at all?" and is
 *    `false` here.
 * 2. Checks were attempted but none of them COMPLETED — a total DoH/network
 *    outage where every `CheckResult` carries a transient
 *    `checkStatus: 'timeout' | 'error'` (the `buildDnsErrorResult`/`safeCheck`
 *    shape). `isMeasured` is `true` here (`checks.length > 0`) even though
 *    there is zero usable evidence — this is precisely the gap that let
 *    `generate_fix_plan`/`map_csc_products`/`compare_baseline` claim a
 *    confident `assessed: true` for a domain nobody actually measured.
 * 3. At least one check produced COMPLETED evidence — `checkStatus` absent
 *    (legacy shape, treated as completed) or `'completed'`. This is the only
 *    state in which a consumer has anything real to grade, count, or price.
 *
 * `isMeasured` answers "was anything ATTEMPTED" (state 1 vs. states 2+3).
 * `hasCompletedEvidence` answers "is there any USABLE evidence" (state 3 vs.
 * states 1+2) — the predicate a surface must use before it claims it
 * assessed a domain. `scan_domain`'s own `StructuredScanResult.measured`
 * field is a deliberate, documented exception: it means "attempted anything"
 * by contract, disambiguated on the wire via `evidence` counts and
 * `evidenceInsufficient` rather than by switching predicates.
 */
export function hasCompletedEvidence(checks: readonly CheckStatusBearer[]): boolean {
	return checks.some(isCompletedCheck);
}

/**
 * The per-check half of {@link hasCompletedEvidence} — "did THIS check produce
 * usable evidence" (`checkStatus` absent/`'completed'`) rather than "did ANY
 * check in a collection". Exported so a caller that needs the individual
 * check-level partition (e.g. `matchedResults.filter(isCompletedCheck)` to
 * separate completed evidence from transient noise within one control's
 * matched categories) shares the exact same predicate `hasCompletedEvidence`
 * uses internally, instead of re-deriving it — see `test/audits/*evidence*`
 * for the ban on re-spelling this check.
 *
 * The rule itself is NOT spelled here. This is a thin object-shape adapter over
 * the package's `isCheckMeasured`, which owns the semantics: an ALLOWLIST
 * (`undefined | 'completed'` counts as measured), deliberately not a denylist
 * (`!== 'timeout' && !== 'error'`). Both forms agree while `CheckStatus` is a
 * closed 3-member union, but they diverge the moment a new member is added — a
 * denylist silently treats an unrecognized future status as "completed", which
 * is the exact defect this evidence campaign exists to prevent. Because the two
 * layers now share ONE implementation, that divergence can no longer happen
 * BETWEEN them either; the only difference is the argument shape (a check
 * object here, a bare status value there). Pinned by
 * `test/audits/completed-evidence-cross-package-parity.audit.test.ts`, which
 * asserts both behavioural parity and that this body delegates rather than
 * re-deriving.
 */
export function isCompletedCheck(check: CheckStatusBearer): boolean {
	return isCheckMeasured(check.checkStatus);
}

/**
 * The VALUE-normalizing twin of `isCompletedCheck`'s BOOLEAN question — same
 * `undefined → 'completed'` rule, spelled for a caller that needs the concrete
 * status string rather than yes/no. The only known consumer is
 * `StructuredScanResult.checkStatuses` (`format-report.ts`), which is
 * customer-facing and contractually typed `Record<string, 'completed' | 'timeout' | 'error'>`
 * — it cannot carry `undefined`, so an absent `checkStatus` must be normalized
 * to a concrete member before it can go on the wire. Keeping this in ONE place
 * (rather than re-deriving `?? 'completed'` at the call site) is what stops the
 * absent-means-completed premise from being restated per-surface.
 *
 * This is a VALUE normalization, not the boolean predicate, so it does not
 * delegate to `isCheckMeasured` — there is nothing in the package that maps a
 * status to a status. It does share the premise, and the union it is typed on
 * is the package's `CheckStatus` rather than a hand-copied literal union, so a
 * new member added upstream surfaces here as a compile error at the call sites
 * that pinned the old three (notably `format-report.ts`'s wire contract) rather
 * than passing silently.
 */
export function normalizeCheckStatus(checkStatus: CheckStatus | undefined): CheckStatus {
	return checkStatus ?? 'completed';
}
