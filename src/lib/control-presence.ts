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

import type { CheckResult, Finding, Severity } from './scoring';
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
 * The severities that DISQUALIFY a control from being reported satisfied.
 *
 * Mirrors the scored penalties (`SEVERITY_PENALTIES`: critical −40, high −25,
 * medium −15, low −5, info 0) — everything the model charges more than a nominal
 * −5 for. `low` and `info` are deliberately OUT: a compliance surface that failed
 * a control on any advisory finding would fail nearly every real domain, and the
 * `low` band is where the checks put "worth knowing" rather than "not in effect".
 */
const DISQUALIFYING_SEVERITIES: ReadonlySet<Severity> = new Set<Severity>(['critical', 'high', 'medium']);

/**
 * Did this check MEASURE the finding it is reporting, or merely fail to look?
 *
 * `inconclusive: true` / `errorKind` on a finding's metadata is the codified marker
 * for "the probe never reached the origin" — a WAF challenge, an auth-gated
 * endpoint, a stalled policy fetch, a lame delegation. CLAUDE.md is emphatic that
 * this is NOT the same statement as "the control is absent", and the distinction
 * runs in BOTH directions: such a finding is no more evidence that a control is
 * unsatisfied than it is evidence that it is present.
 */
function isMeasuredFinding(finding: Finding): boolean {
	const metadata = finding.metadata;
	if (!metadata) return true;
	return metadata.inconclusive !== true && metadata.errorKind === undefined;
}

/**
 * Did this check flag a MEASURED defect at medium severity or worse?
 *
 * Exported so a consumer can attribute a non-satisfied verdict honestly — the
 * "no evidence the control is in effect" wording is false for a control that is
 * plainly in effect and merely deficient.
 *
 * Two carve-outs, both load-bearing:
 *
 * 1. **`info` never trips the floor.** The scan's post-processing deliberately
 *    downgrades email-auth findings to `info` for a non-mail domain under an
 *    enforcing parent DMARC, and DKIM/MTA-STS/BIMI findings to `info` under an SPF
 *    `noSendPolicy`. Those downgrades exist precisely so a legitimately
 *    inapplicable control is not charged for absence, and they are rewritten onto
 *    the `CheckResult` (via `buildCheckResult`) BEFORE either consumer sees it — so
 *    the severity read here is the final, post-downgrade one. A floor reading
 *    pre-downgrade severity would convert the false PASS this closes into a false
 *    FAIL on exactly the domains that fix protected.
 * 2. **An UNMEASURED finding never trips the floor** — see {@link isMeasuredFinding}.
 *    A floor that fired on a WAF-intercepted probe would publish a confident FAIL
 *    for a control nobody looked at, which is the mirror defect: `map_compliance`
 *    carries a whole `not_assessed` status rather than say that, and
 *    `compare_baseline` a whole `inconclusiveRules` channel. Those channels are
 *    driven by `checkStatus`, upstream of this predicate, and must stay the ones
 *    that answer for an unmeasured control.
 */
export function hasDisqualifyingFinding(result: CheckResult): boolean {
	return result.findings.some((finding) => DISQUALIFYING_SEVERITIES.has(finding.severity) && isMeasuredFinding(finding));
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
 *
 * ⚠️ **The `recordPresent` clause alone does not close it (#726).** Only 9 checks
 * emit `recordPresent`; for the five that never do — `spf`, `dkim`, `ssl`, `ns`,
 * `http_security` — `isUnrebuttedAbsence` is structurally `false`, so the predicate
 * silently degraded back to bare `passed`, the very thing #705/#706 removed. That is
 * not theoretical: measured against `wiz.io` on 2026-08-20, `map_compliance`
 * published "PCI DSS 4.0 — 5/5, 100%" with control 6.4.2 (Web Application Firewall /
 * CSP, `requirePass`, backed solely by `http_security`) as PASS — while the SAME
 * scan raised two medium `http_security` findings, "CSP allows unsafe-inline
 * scripts" and "CSP allows unsafe-eval", scored the category 65, and rated the
 * resulting `xss_injection` attack path HIGH. A CSP permitting both inline script
 * and dynamic code execution is substantially no XSS protection, and we certified it.
 *
 * The third clause is therefore a SEVERITY FLOOR, and it is deliberately general
 * rather than a patch to 6.4.2: **a control cannot be satisfied by a check the same
 * scan flags at medium or worse.** It closes all five unguarded checks at once and
 * needs no per-check signal to be added. Where it and the presence clauses disagree
 * the answer is the same either way — not satisfied — so ordering is immaterial;
 * they are separate clauses because they answer different questions ("was anything
 * published" vs "is what was published doing the job").
 */
export function isSatisfiedControl(result: CheckResult): boolean {
	if (!result.passed) return false;
	if (isUnrebuttedAbsence(result)) return false;
	if (hasDisqualifyingFinding(result)) return false;
	return true;
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
