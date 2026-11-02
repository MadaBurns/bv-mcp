// SPDX-License-Identifier: BUSL-1.1

/** Shared result-rebuild helpers for scan post-processing. Every `buildCheckResult` call in the post-processing modules goes through `rebuildPreservingSignals` (#994). */

import { type CheckResult, type Finding, buildCheckResult } from '../../lib/scoring';
import { isCompletedCheck } from '../../lib/ungraded-display';

export function upsertCheckResult(results: CheckResult[], updated: CheckResult): CheckResult[] {
	return results.map((result) => (result.category === updated.category ? updated : result));
}

/**
 * THE ONE PLACE in post-processing that may call `buildCheckResult` (#994).
 *
 * `buildCheckResult(category, findings)` compiles cleanly against a FIVE-argument
 * signature, so every rebuild in post-processing silently discarded `controlPresent`,
 * `recordPresent` and `metadata` — the structured signals the SGE evaluator, the
 * profile detector and the per-check UI read. Nothing failed; the signals just
 * stopped existing one stage after they were measured. On `health.govt.nz` that
 * turned `spfAll: '-all'` and `mtaStsMode: 'enforce'` into NOT MEASURED and made
 * `sge_quickscan` assert a cause ("its policy file could not be fetched or
 * parsed") that nothing observed.
 *
 * Why a wholesale carry-forward is the CORRECT answer here, rather than a
 * per-site judgement call: `passed`/`score` are OUTPUTS — derived from the
 * findings, so they must be, and are, recomputed. The three signals are INPUTS:
 * they record what the probe OBSERVED (was a record published, is the control
 * active, what qualifier did the record carry). Every post-processing adjustment
 * rewrites finding SEVERITY and PROSE to express APPLICABILITY — "this control
 * does not apply to a non-mail domain", "this gap is worse because lookalikes
 * exist". None of them re-measures anything, so none of them can invalidate an
 * observation. If an adjustment is ever added that genuinely changes what the
 * result MEANS (re-probing, or re-attributing the result to a different name),
 * it must override the signal explicitly at its own call site rather than lean
 * on this helper — carrying forward an observation the adjustment has just
 * falsified would be the mirror-image defect.
 *
 * `undefined` propagates as `undefined`: `buildCheckResult` omits the key
 * entirely for an undefined argument, so "not determined" never becomes a
 * fabricated `false`, and a measured `false` never decays to "not determined".
 *
 * Enforced by `test/scan-post-processing-build-chokepoint.audit.test.ts`, which
 * fails on any new bare `buildCheckResult(` call in the post-processing modules.
 */
export function rebuildPreservingSignals(source: CheckResult, adjusted: Finding[]): CheckResult {
	return buildCheckResult(source.category, adjusted, source.controlPresent, source.recordPresent, source.metadata);
}

/**
 * Rebuild a post-processed result — but NEVER resurrect one that abstained.
 *
 * Every adjustment below reshapes findings and then re-derives the result with
 * `buildCheckResult`, which recomputes `passed`/`score` from the findings alone
 * and carries neither `checkStatus` nor `partial`. Feed it an ABSTENTION (score
 * 0, `partial: true`, `checkStatus: 'error'`, findings all `info`) and it hands
 * back a confident `score: 100, passed: true` — the exact false pass #948
 * removed from `check_dkim` and `check_subdomain_takeover`, re-created one stage
 * later. `dkim` sits in three of these category lists, so the leak is reachable
 * on any no-MX / SPF `-all` domain whose DKIM queries all threw: the check
 * abstains, post-processing scores it 100, and `isCheckMeasured` then counts the
 * category as measured instead of renormalising it out.
 *
 * An unmeasured result has no real finding to downgrade in the first place, so
 * returning it untouched is both the safe and the correct answer. Measured-ness
 * is asked through `isCompletedCheck`, the `src/`-side SSOT —
 * `completed-evidence-predicate-ssot.audit.test.ts` bans re-deriving it here.
 */
export function rebuildUnlessAbstained(result: CheckResult, adjusted: Finding[]): CheckResult {
	if (!isCompletedCheck(result)) return result;
	// `rebuildPreservingSignals`, never a bare `buildCheckResult` — see #994 and the
	// helper's own note. The abstention early-return above already carries the whole
	// original object (signals included) through untouched.
	return rebuildPreservingSignals(result, adjusted);
}

/**
 * Retract a DECLARED `metadata.missingControl: true` when a finding is downgraded to
 * "not applicable". Spread the result into the downgraded finding.
 *
 * `findingsIndicateMissingControl` honours a declared `true` with NO severity gate, so
 * a finding rewritten to `info` / "not applicable" but still carrying the declaration
 * kept zeroing its category and failing `passed` — the prose said "expected" while the
 * score said "absent". `missingControl: false` is the scoring layer's own "measured,
 * not a missing control" declaration (it outranks the prose regex in both directions).
 * Undeclared findings get no patch: they already fall through to the severity-gated
 * prose inference, which `info` clears.
 */
export function notApplicableMetadata(finding: Finding): { metadata?: Finding['metadata'] } {
	return finding.metadata?.missingControl === true ? { metadata: { ...finding.metadata, missingControl: false } } : {};
}
