// SPDX-License-Identifier: BUSL-1.1

/**
 * The single vocabulary for "this scan produced no grade", and the single place
 * a `score/grade` pair is turned into display text.
 *
 * A deliberately tiny leaf module (no imports) so every formatter in `src/tools/`
 * can depend on it without an import cycle through the scan orchestrator.
 *
 * `isCompletedCheck`/`hasCompletedEvidence`/`normalizeCheckStatus` below are the
 * SSOT for "did this check/scan produce usable evidence" on the `src/` side only —
 * `test/audits/completed-evidence-predicate-ssot.audit.test.ts` bans any other
 * `src/` module from re-deriving the same check. `packages/dns-checks/src/scoring/evidence.ts`
 * (`computeScanEvidence`'s per-result completed/attempted accounting) is a
 * DELIBERATE, KNOWN twin on the other side of the package boundary — it is a
 * published SSOT vendored by another repo and frozen for this campaign, so it
 * cannot import from `src/`, and this module cannot be vendored into it
 * without inverting the dependency direction (`src/` already depends on
 * `@blackveil/dns-checks`, not the other way around). The two are kept in
 * semantic lockstep by hand, not by a shared import; a change to what
 * "completed" means must be applied to BOTH deliberately.
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
 * Deliberately typed on the array's length alone (`readonly unknown[]`) so this
 * stays an import-free leaf module with no edge to the scan orchestrator.
 */
export function isMeasured(checks: readonly unknown[]): boolean {
	return checks.length > 0;
}

/**
 * Minimal shape this leaf module needs from a check result to answer "did
 * anything complete" — a local structural type instead of importing
 * `CheckResult`, so this file stays a zero-import leaf with no edge to the
 * scan orchestrator.
 */
interface CheckStatusBearer {
	readonly checkStatus?: 'completed' | 'timeout' | 'error';
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
 * Deliberately an ALLOWLIST (`undefined | 'completed'` counts as completed),
 * not a denylist (`!== 'timeout' && !== 'error'`). Both forms agree today
 * because `CheckStatus` is a closed 3-member union, but they diverge the
 * moment a new member is added: a denylist silently treats an unrecognized
 * future status as "completed" (wrong — an incomplete measurement must never
 * read as confident evidence, the campaign invariant this whole module
 * exists to protect), while this allowlist correctly treats it as NOT
 * completed until a maintainer deliberately adds it here.
 */
export function isCompletedCheck(check: CheckStatusBearer): boolean {
	return check.checkStatus === undefined || check.checkStatus === 'completed';
}

/**
 * The VALUE-normalizing twin of `isCompletedCheck`'s BOOLEAN question — same
 * `undefined → 'completed'` rule, spelled for a caller that needs the concrete
 * status string rather than yes/no. The only known consumer is
 * `StructuredScanResult.checkStatuses` (`format-report.ts`), which is
 * customer-facing and contractually typed `Record<string, 'completed' | 'timeout' | 'error'>`
 * — it cannot carry `undefined`, so an absent `checkStatus` must be normalized
 * to a concrete member before it can go on the wire. Sharing this rule with
 * `isCompletedCheck` (rather than re-deriving `?? 'completed'` at the call
 * site) is what keeps the two in lockstep if a new `CheckStatus` member is
 * ever added.
 */
export function normalizeCheckStatus(checkStatus: 'completed' | 'timeout' | 'error' | undefined): 'completed' | 'timeout' | 'error' {
	return checkStatus ?? 'completed';
}
