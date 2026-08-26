// SPDX-License-Identifier: BUSL-1.1

/**
 * Baseline comparison tool (compliance enforcement).
 *
 * Here "baseline" is a **policy/requirements OBJECT** — grade/score floors,
 * `require_*` control flags, and `max_*_findings` caps — answering
 * "does this domain meet these required controls?" for org-level enforcement.
 *
 * This is NOT a prior-scan reference. For drift-over-time against a previous
 * ScanScore (or the literal `"cached"`), use the `analyze_drift` tool, whose
 * `baseline` parameter is a string, not this object.
 */

import type { OutputFormat } from '../handlers/tool-args';
import type { CheckCategory, Finding } from '../lib/scoring';
import { hasCompletedEvidence } from '../lib/ungraded-display';
// Shared with `map_compliance` (#705) — see `lib/control-presence.ts`. The two
// surfaces answer the same customer question ("does this domain have control X")
// and must not drift on what "satisfied" and "applicable" mean.
import { hasDisqualifyingFinding, isSatisfiedControl, notApplicableCategoriesFor } from '../lib/control-presence';
import type { ScanDomainResult } from './scan-domain';

const GRADE_ORDER = ['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'E', 'F'] as const;

const CATEGORY_REQUIREMENTS: Array<{ key: keyof PolicyBaseline; category: CheckCategory; label: string }> = [
	{ key: 'require_spf', category: 'spf', label: 'SPF' },
	{ key: 'require_dkim', category: 'dkim', label: 'DKIM' },
	{ key: 'require_dnssec', category: 'dnssec', label: 'DNSSEC' },
	{ key: 'require_mta_sts', category: 'mta_sts', label: 'MTA-STS' },
	{ key: 'require_caa', category: 'caa', label: 'CAA' },
];

/** A single baseline rule violation. */
export interface BaselineViolation {
	rule: string;
	message: string;
	expected: string | number | boolean;
	actual: string | number | boolean;
}

/** Result of comparing one scan against one baseline. */
export interface BaselineResult {
	domain: string;
	/**
	 * `true` = every evaluated rule met. `false` = at least one violated.
	 * `null` = INCONCLUSIVE: at least one requested rule could not be evaluated
	 * because the scan produced no measurement. A policy gate must treat `null`
	 * as "re-run", never as a pass and never as a fail.
	 */
	passed: boolean | null;
	violations: BaselineViolation[];
	/**
	 * Rules the caller requested that could not be evaluated — because the scan
	 * produced no measurement, OR because the control does not apply to this domain
	 * (see {@link BaselineResult.notApplicableRules}). One channel, because a gate
	 * consumer's decision is the same for both: `passed` is `null`, re-run or
	 * reconsider the policy — never read as a pass and never as a fail.
	 */
	inconclusiveRules: string[];
	/**
	 * The SUBSET of `inconclusiveRules` abstained on because the scan's own
	 * applicability pass declared the category not applicable to this domain — a
	 * `web_only`/`non_mail` domain legitimately publishes no MTA-STS policy.
	 *
	 * Reported separately ONLY so the prose can attribute the abstention honestly:
	 * "no measurement available" is false here — the scan measured the category
	 * perfectly well; the control simply has nothing to apply to. The verdict channel
	 * remains `inconclusiveRules`/`passed`, which consumers should keep gating on.
	 */
	notApplicableRules: string[];
	checkedRules: number;
	scoringProfile?: string;
	timestamp: string;
}

/** User-defined policy baseline. */
export interface PolicyBaseline {
	grade?: string;
	score?: number;
	require_dmarc_enforce?: boolean;
	require_spf?: boolean;
	require_dkim?: boolean;
	require_dnssec?: boolean;
	require_mta_sts?: boolean;
	require_caa?: boolean;
	max_critical_findings?: number;
	max_high_findings?: number;
}

function gradeWorseThan(actual: string, minimum: string): boolean {
	const actualIndex = GRADE_ORDER.indexOf(actual as (typeof GRADE_ORDER)[number]);
	const minimumIndex = GRADE_ORDER.indexOf(minimum as (typeof GRADE_ORDER)[number]);
	if (actualIndex === -1 || minimumIndex === -1) return false;
	return actualIndex > minimumIndex;
}

/**
 * Is the required control actually IN EFFECT on this domain?
 *
 * This used to be `check?.passed ?? false`, and `passed` records whether the check
 * PENALIZED the domain — not whether the control exists (#706). `require_dnssec`,
 * `require_caa` and `require_mta_sts` all leave `passed: true` on absence (a graded
 * finding, deliberately no `missingControl`, so the category still scores 60), so a
 * customer gate `require_dnssec: true` PASSED every unsigned domain in the portfolio
 * while the same scan raised a high-severity "DNSSEC not enabled".
 *
 * `isSatisfiedControl` is the SHARED predicate `map_compliance` grades on — including
 * its generic affirmative-control rebuttal for split-signal or legacy results. The
 * current DNSSEC check requires AD + DNSKEY + DS and does not emit a false/true pair.
 * A missing `CheckResult` is unchanged: no evidence the control is in effect, so a
 * rule requiring it is not met.
 */
function categorySatisfied(scan: ScanDomainResult, category: CheckCategory): boolean {
	const check = scan.checks.find((value) => value.category === category);
	return check !== undefined && isSatisfiedControl(check);
}

/**
 * WHY a required control is not satisfied — absent, or present-but-deficient (#726).
 *
 * `isSatisfiedControl` gained a severity floor: a control cannot be satisfied by a
 * check the same scan flags at medium or worse. That is a second, structurally
 * different reason to violate a `require_*` rule, and collapsing the two into the
 * original wording makes the gate lie about the remediation. "the scan found no
 * evidence it is in effect" is FLATLY false for a domain publishing a working SPF
 * record with an over-permissive trust surface — it sends the customer hunting for a
 * missing record they will not find, and the next thing they distrust is the gate.
 */
function unsatisfiedReason(scan: ScanDomainResult, category: CheckCategory, label: string): string {
	const check = scan.checks.find((value) => value.category === category);
	if (check !== undefined && hasDisqualifyingFinding(check)) {
		return `${label} is required, and this scan flags it at medium severity or worse — a control the same scan reports as deficient does not satisfy the requirement`;
	}
	return `${label} is required but the scan found no evidence it is in effect`;
}

function dmarcEnforced(scan: ScanDomainResult): boolean {
	const dmarcCheck = scan.checks.find((value) => value.category === 'dmarc');
	if (!dmarcCheck) return false;

	const hasNonePolicyFinding = dmarcCheck.findings.some((finding: Finding) => {
		const text = `${finding.title} ${finding.detail}`.toLowerCase();
		return finding.severity !== 'info' && (text.includes('p=none') || text.includes('policy is none'));
	});

	return dmarcCheck.passed && !hasNonePolicyFinding;
}

/** Compare a scan result against a policy baseline. */
export function compareBaseline(scan: ScanDomainResult, baseline: PolicyBaseline): BaselineResult {
	const violations: BaselineViolation[] = [];
	const inconclusiveRules: string[] = [];
	const notApplicableRules: string[] = [];
	let checkedRules = 0;

	// An ungraded scan carries no grade/score to evaluate, so the rule is recorded as
	// INCONCLUSIVE rather than evaluated against a null. Coercion here fails in OPPOSITE
	// directions on the same scan — `GRADE_ORDER.indexOf(null)` is -1 so `gradeWorseThan`
	// silently PASSES, while `null < 50` coerces to `0 < 50` and FAILS — meaning whichever
	// rule the caller happened to configure decided the verdict of a CI/CD policy gate.
	// Merely skipping is not sufficient either: a skipped rule still yields `passed: true`,
	// which a pipeline testing `passed === true` reads as "policy met".
	if (baseline.grade !== undefined) {
		if (scan.score.grade === null) {
			inconclusiveRules.push('grade');
		} else {
			checkedRules++;
			if (gradeWorseThan(scan.score.grade, baseline.grade)) {
				violations.push({
					rule: 'grade',
					message: `Grade ${scan.score.grade} is below minimum ${baseline.grade}`,
					expected: baseline.grade,
					actual: scan.score.grade,
				});
			}
		}
	}

	if (baseline.score !== undefined) {
		if (scan.score.overall === null) {
			inconclusiveRules.push('score');
		} else {
			checkedRules++;
			if (scan.score.overall < baseline.score) {
				violations.push({
					rule: 'score',
					message: `Score ${scan.score.overall} is below minimum ${baseline.score}`,
					expected: baseline.score,
					actual: scan.score.overall,
				});
			}
		}
	}

	// The control and finding-cap rules read `scan.checks` / `scan.score.findings`.
	// When the scan ran ZERO checks (`buildNonResolvingResult` for NXDOMAIN and
	// `buildDnsBrokenResult` for SERVFAIL/DNSSEC-bogus both emit `checks: []` AND
	// `findings: []`) those arrays are empty because nothing was measured, not
	// because the controls are absent. Evaluating them anyway turned absence into a
	// confident policy verdict in BOTH directions: `categoryPassed`'s
	// `check?.passed ?? false` produced "SPF is required but check did not pass",
	// while `max_critical_findings: 0` counted an empty array and PASSED — "zero
	// criticals" asserted about a domain nobody scanned.
	//
	// `buildUnscoredResult` is deliberately NOT in this bucket: its checks ran and
	// only the scoring bundle failed, so its per-check results stay genuinely
	// evaluable. A measured scan whose SPF check simply failed is a real breach and
	// must still FAIL — only the nothing-ran case abstains.
	//
	// `isMeasured` (`checks.length > 0`) is the WRONG predicate here: a total
	// DoH/network outage where every attempted check carries a transient
	// `checkStatus: 'timeout' | 'error'` (`buildDnsErrorResult`/`safeCheck`) is
	// `checks.length > 0` too, and `categoryPassed`'s `check?.passed ?? false`
	// read each transient check's `passed: false` as a genuine control failure —
	// manufacturing confident violations from zero completed evidence, exactly
	// the pathology `passed: null` above exists to remove. `hasCompletedEvidence`
	// requires at least one check to have actually COMPLETED (`checkStatus`
	// absent or `'completed'`), so an all-transient outage abstains the same way
	// a zero-check scan does.
	const scanMeasured = hasCompletedEvidence(scan.checks);

	if (baseline.require_dmarc_enforce) {
		if (!scanMeasured) {
			inconclusiveRules.push('require_dmarc_enforce');
		} else {
			checkedRules++;
			if (!dmarcEnforced(scan)) {
				violations.push({
					rule: 'require_dmarc_enforce',
					message: 'DMARC enforcement (p=quarantine or p=reject) is required but not met',
					expected: true,
					actual: false,
				});
			}
		}
	}

	// The scan's own applicability pass, consumed rather than re-derived — the same
	// `notApplicableCategoriesFor` call `map_compliance` makes. Without it, grading the
	// control rules on PRESENCE would newly report `require_mta_sts` as VIOLATED against
	// a `web_only`/`non_mail` domain that accepts no mail and therefore legitimately
	// publishes no MTA-STS policy: the #706 defect wearing the opposite sign.
	const notApplicableCategories = new Set(notApplicableCategoriesFor(scan));

	for (const requirement of CATEGORY_REQUIREMENTS) {
		if (baseline[requirement.key]) {
			if (!scanMeasured) {
				inconclusiveRules.push(requirement.key);
			} else if (notApplicableCategories.has(requirement.category)) {
				// NOT a pass. "The rule cannot be evaluated on this domain" and "the rule
				// passed" are different statements, and a gate keyed on `passed === true`
				// must be able to tell them apart — silently passing an inapplicable rule
				// is the same confident-verdict-from-no-evidence pathology as the rest of
				// this channel. It also stays OUT of `checkedRules`, so the denominator
				// never counts a rule nobody could answer.
				inconclusiveRules.push(requirement.key);
				notApplicableRules.push(requirement.key);
			} else {
				checkedRules++;
				if (!categorySatisfied(scan, requirement.category)) {
					violations.push({
						rule: requirement.key,
						message: unsatisfiedReason(scan, requirement.category, requirement.label),
						expected: true,
						actual: false,
					});
				}
			}
		}
	}

	if (baseline.max_critical_findings !== undefined) {
		if (!scanMeasured) {
			inconclusiveRules.push('max_critical_findings');
		} else {
			checkedRules++;
			const criticalCount = scan.score.findings.filter((finding: Finding) => finding.severity === 'critical').length;
			if (criticalCount > baseline.max_critical_findings) {
				violations.push({
					rule: 'max_critical_findings',
					message: `${criticalCount} critical findings exceed maximum of ${baseline.max_critical_findings}`,
					expected: baseline.max_critical_findings,
					actual: criticalCount,
				});
			}
		}
	}

	if (baseline.max_high_findings !== undefined) {
		if (!scanMeasured) {
			inconclusiveRules.push('max_high_findings');
		} else {
			checkedRules++;
			const highCount = scan.score.findings.filter((finding: Finding) => finding.severity === 'high').length;
			if (highCount > baseline.max_high_findings) {
				violations.push({
					rule: 'max_high_findings',
					message: `${highCount} high findings exceed maximum of ${baseline.max_high_findings}`,
					expected: baseline.max_high_findings,
					actual: highCount,
				});
			}
		}
	}

	return {
		domain: scan.domain,
		// An unevaluatable rule poisons the whole verdict: reporting `passed: true`
		// because the failing rule was skipped is exactly the confident-output-from-
		// incomplete-measurement pathology this change exists to remove.
		passed: inconclusiveRules.length > 0 ? null : violations.length === 0,
		violations,
		inconclusiveRules,
		notApplicableRules,
		checkedRules,
		scoringProfile: scan.context?.profile,
		timestamp: new Date().toISOString(),
	};
}

/** Format baseline result as readable markdown text for MCP clients. */
export function formatBaselineResult(result: BaselineResult, format: OutputFormat = 'full'): string {
	const verdict = result.passed === null ? 'INCONCLUSIVE' : result.passed ? 'PASS' : 'FAIL';

	// The two abstention CAUSES get their own line. Both are "not evaluated", but
	// "no measurement available" is FALSE for an inapplicable category — that scan
	// measured the category fine and the control simply has nothing to apply to.
	// Collapsing them would tell a `web_only` customer their MTA-STS was unmeasured
	// and send them to re-run a scan that will keep returning the same thing.
	// `notApplicableRules` is a SUBSET of `inconclusiveRules`, so it is subtracted
	// rather than appended.
	const notApplicable = result.notApplicableRules ?? [];
	const unmeasuredRules = result.inconclusiveRules.filter((rule) => !notApplicable.includes(rule));

	if (format === 'compact') {
		const lines = [`Baseline: ${result.domain} — ${verdict} (${result.violations.length}/${result.checkedRules} violated)`];
		if (unmeasuredRules.length > 0) {
			lines.push(`- not evaluated (no measurement available): ${unmeasuredRules.join(', ')}`);
		}
		if (notApplicable.length > 0) {
			lines.push(`- not evaluated (does not apply to this domain): ${notApplicable.join(', ')}`);
		}
		for (const v of result.violations) {
			lines.push(`- ${v.rule}: expected ${v.expected}, got ${v.actual}`);
		}
		return lines.join('\n');
	}

	const lines: string[] = [];

	lines.push(`## Baseline Comparison: ${result.domain}`);
	lines.push(`**Result:** ${verdict}`);
	lines.push(`**Rules checked:** ${result.checkedRules}`);
	lines.push(`**Violations:** ${result.violations.length}`);
	if (unmeasuredRules.length > 0) {
		// Deliberately attributes the abstention to the MISSING MEASUREMENT, not to the
		// customer's domain. `passed: null` fires for two causes: the domain genuinely
		// not resolving, AND `buildUnscoredResult`, where the domain resolved and its
		// checks ran but OUR scoring bundle failed. "domain was not measured" is false
		// in the second case and blames the customer for a scanner-side outage —
		// scan_domain's own nextStep for that path says "the scoring service is
		// degraded — check the deployment."
		lines.push(`**Not evaluated (no measurement available for this scan):** ${unmeasuredRules.join(', ')}`);
	}
	if (notApplicable.length > 0) {
		lines.push(`**Not evaluated (does not apply to this domain):** ${notApplicable.join(', ')}`);
	}
	lines.push('');

	if (result.violations.length === 0) {
		lines.push(result.passed === null ? 'No verdict: one or more rules could not be evaluated.' : 'All baseline rules met.');
		return lines.join('\n');
	}

	lines.push('### Violations');
	for (const violation of result.violations) {
		lines.push(`- **${violation.rule}** - ${violation.message}`);
		lines.push(`  Expected: ${violation.expected} | Actual: ${violation.actual}`);
	}

	return lines.join('\n');
}
