// SPDX-License-Identifier: BUSL-1.1

/**
 * Control PRESENCE and APPLICABILITY — the shared vocabulary every surface that
 * publishes a per-control verdict must speak.
 *
 * Two tools answer "does this domain have control X" for a customer:
 * `map_compliance` (the reporting surface, #705) and `compare_baseline` (the
 * policy gate customers wire into CI, #706). Both had the SAME defect, fixed
 * three months apart, because the predicate lived privately inside the first
 * one. Duplicating it a third time is how the two surfaces drift on what
 * "satisfied" and "applicable" mean — so it lives here, once, and both import it.
 */

import type { CheckResult } from './scoring';
import { isCompletedCheck } from './ungraded-display';
import { isCategoryNonApplicable } from '../tools/scan/format-report';

/**
 * Did this check observe a definitive, UNREBUTTED absence of the control's record?
 *
 * `recordPresent` is the observational answer to "was the artifact published at
 * all", and is documented as score-neutral precisely so a consumer like this one
 * can read it without perturbing scoring. Only an explicit `false` counts:
 * `undefined` means the check does not report the signal (spf, dkim, ssl, ns and
 * http_security never set it) or that the query failed, and absence of a signal is
 * not evidence of absence.
 *
 * `recordPresent === false` is NOT sufficient on its own. `check-dnssec` documents
 * a legitimate `recordPresent: false` + `controlPresent: true` state: a zone that
 * validates while publishing no DNSKEY/DS of its own, because its ccTLD registry
 * signed it. That zone IS cryptographically protected, so failing it on missing
 * records would trade a false PASS for a false FAIL. An affirmative
 * `controlPresent` therefore REBUTS the absence, and only unrebutted evidence of
 * absence disqualifies.
 */
export function isUnrebuttedAbsence(result: CheckResult): boolean {
	return result.recordPresent === false && result.controlPresent !== true;
}

/**
 * Does this completed check actually satisfy the control it is mapped to?
 *
 * `passed` alone is NOT the answer, and reading it as one was the defect this
 * predicate closes. `passed` records whether the check PENALIZED the domain; a
 * control that is absent but carries no penalty under the active profile still
 * returns `passed: true`. Mapping that onto a compliance verdict published "NIST
 * 800-177 §5.1 DNSSEC — PASS" for domains with no DNSSEC at all, alongside the same
 * scan's own high-severity "DNSSEC not enabled" finding (#705); mapping it onto a
 * policy gate passed `require_dnssec: true` on every unsigned zone in a customer's
 * portfolio (#706).
 */
export function isSatisfiedControl(result: CheckResult): boolean {
	if (!result.passed) return false;
	return !isUnrebuttedAbsence(result);
}

/**
 * The scan-shaped input `notApplicableCategoriesFor` reads. Deliberately
 * structural and permissive rather than `ScanDomainResult`: hand-built results
 * (tests, external library consumers) reach these tools too, and a missing
 * `score`/`context` must degrade to "everything is applicable", never throw.
 */
export interface ApplicabilityScan {
	checks: readonly CheckResult[];
	score?: { categoryScores?: Record<string, number> } | null;
	context?: { profile?: string } | null;
}

/**
 * The categories THIS SCAN declared not applicable, via its own applicability pass.
 *
 * Not a second opinion: `isCategoryNonApplicable` in `tools/scan/format-report.ts`
 * is the single source `categoryScores` and `notApplicableCategories` both derive
 * from, and it is consumed here rather than re-derived. This is the guard that
 * stops a presence rule from becoming the same defect with the opposite sign — a
 * `web_only`/`non_mail` domain legitimately publishes no MTA-STS policy, and
 * failing it on absence would report a domain that accepts no mail as breaching a
 * mail control.
 *
 * Only COMPLETED checks are considered: a timed-out/errored check is a measurement
 * failure, never a deliberate N/A.
 */
export function notApplicableCategoriesFor(scan: ApplicabilityScan): string[] {
	const profile = scan.context?.profile ?? 'mail_enabled';
	const categoryScores: Record<string, number> = scan.score?.categoryScores ?? {};
	return scan.checks
		.filter((check) => isCompletedCheck(check) && isCategoryNonApplicable(check, check.category, profile, categoryScores[check.category]))
		.map((check) => check.category);
}
