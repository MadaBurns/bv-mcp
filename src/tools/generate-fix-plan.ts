// SPDX-License-Identifier: BUSL-1.1

/**
 * Generate a prioritized remediation fix plan from scan results.
 *
 * Scans the domain (using cache), inspects non-info findings,
 * and produces an ordered list of action items with effort,
 * impact, and dependency information.
 */

import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';
import type { CheckResult, Finding, Severity, CheckCategory } from '@blackveil/dns-checks/scoring';
import { IMPORTANCE_WEIGHTS, isGraded } from '@blackveil/dns-checks/scoring';
import { scanDomain } from './scan-domain';
import type { ScanRuntimeOptions } from './scan/post-processing';
import { formatScoreGrade, hasCompletedEvidence, UNGRADED_DISPLAY } from '../lib/ungraded-display';
import { isDnsErrorFinding } from '../lib/dns-error-result';

/** A single remediation action in a fix plan. */
export interface FixAction {
	priority: number;
	category: CheckCategory;
	action: string;
	severity: Severity;
	effort: 'low' | 'medium' | 'high';
	impact: 'critical' | 'high' | 'medium' | 'low';
	dependencies: string[];
	findingTitle: string;
}

/** Full fix plan result. */
export interface FixPlanResult {
	domain: string;
	/** `null` when the scan produced no gradeable measurement. Never a coerced 0. */
	score: number | null;
	/** `null` when the scan produced no gradeable measurement. Never a fabricated letter. */
	grade: string | null;
	/**
	 * `null` when no checks ran. The three degraded scan builders all hardcode
	 * `maturity.stage = 0` as a placeholder, and stage 0 means "Unprotected" — a
	 * posture verdict. Copying it through renders "Maturity Stage: 0/4" for a
	 * domain nobody looked at, and puts a chartable 0 on the wire.
	 */
	maturityStage: number | null;
	totalActions: number;
	actions: FixAction[];
	/**
	 * Did any check run? `totalActions: 0` means two very different things — a
	 * clean domain, or a domain that was never examined. Machine consumers must
	 * gate on this before reading zero actions as a clean bill of health.
	 */
	assessed: boolean;
	/** Populated only when `assessed` is false; `null` otherwise. */
	caveat: string | null;
	/**
	 * Categories whose OWN check failed transiently (`checkStatus: 'error' |
	 * 'timeout'`) and were therefore excluded from `actions` — filtering out a
	 * transient error's synthetic "check error" finding must not silently read
	 * as "nothing to fix" for that category (that is a fabricated clean bill of
	 * health, not a real one). `[]` when nothing was excluded this way, INCLUDING
	 * the whole-scan-unassessed case (`assessed: false`) — that failure mode is
	 * already fully covered by `caveat`, so listing every category here too would
	 * duplicate the same fact in two places with two different wordings.
	 */
	transientCategories: CheckCategory[];
}

/**
 * The single wording of the "nothing was examined" qualifier, carried on BOTH
 * surfaces — the prose a customer reads and the `caveat` field a machine consumes.
 */
export const UNASSESSED_FIX_PLAN_CAVEAT =
	'No checks ran for this domain, so no remediation actions could be planned. This is an absence of evidence, not a clean bill of health.';

/**
 * A SEPARATE wording from {@link UNASSESSED_FIX_PLAN_CAVEAT} for a different
 * failure mode. `UNASSESSED_FIX_PLAN_CAVEAT` describes "no checks ran"
 * (NXDOMAIN, broken zone — `checks: []`). This describes "checks ran, none of
 * them finished" — a total DoH/network outage where every attempted check
 * carries a transient `checkStatus: 'timeout'`/`'error'`
 * (`buildDnsErrorResult`/`safeCheck`). Saying "no checks ran" there would be
 * false — N checks DID run, and each one's own "check error" finding would
 * otherwise be mistaken for a real remediation item (see
 * `generateFixPlan`'s `hasEvidence` gate). Mirrors `map_compliance`'s
 * `buildAllTransientCaveat`.
 */
export function buildAllTransientFixPlanCaveat(attempted: number): string {
	return (
		`${attempted} check${attempted === 1 ? '' : 's'} ${attempted === 1 ? 'was' : 'were'} attempted for this domain, ` +
		`but none of them completed (transient DNS/network failure) — no remediation actions could be planned from this scan. ` +
		`This is different from no checks running at all: retry once the transient condition clears.`
	);
}

/** Severity to numeric weight for priority computation. */
const SEVERITY_WEIGHT: Record<Severity, number> = {
	critical: 40,
	high: 25,
	medium: 15,
	low: 5,
	info: 0,
};

/** Category to effort estimate. */
const EFFORT_MAP: Partial<Record<CheckCategory, 'low' | 'medium' | 'high'>> = {
	spf: 'low',
	dmarc: 'low',
	dkim: 'medium',
	dnssec: 'high',
	ssl: 'medium',
	mta_sts: 'medium',
	ns: 'high',
	caa: 'low',
	bimi: 'medium',
	tlsrpt: 'low',
	http_security: 'medium',
	dane: 'high',
	mx: 'medium',
	subdomain_takeover: 'high',
};

/** Category dependencies — what should be set up first. */
const DEPENDENCY_MAP: Partial<Record<CheckCategory, string[]>> = {
	dmarc: ['Set up SPF first', 'Set up DKIM first'],
	bimi: ['DMARC enforcement (p=quarantine or p=reject) required'],
	mta_sts: ['Ensure MX records are configured'],
	dane: ['DNSSEC must be enabled first'],
	dkim: ['Provider-specific configuration required'],
};

/** Map severity to impact label. */
function severityToImpact(severity: Severity): 'critical' | 'high' | 'medium' | 'low' {
	switch (severity) {
		case 'critical':
			return 'critical';
		case 'high':
			return 'high';
		case 'medium':
			return 'medium';
		default:
			return 'low';
	}
}

/** Generate a human-readable action description from a finding. */
function findingToAction(finding: Finding): string {
	const title = finding.title.toLowerCase();

	if (title.includes('missing') || title.includes('no ') || title.includes('not found')) {
		return `Add ${finding.category.toUpperCase()} record — ${finding.detail}`;
	}
	if (title.includes('weak') || title.includes('permissive') || title.includes('not enforc')) {
		return `Strengthen ${finding.category.toUpperCase()} configuration — ${finding.detail}`;
	}
	if (title.includes('expired') || title.includes('expir')) {
		return `Renew ${finding.category.toUpperCase()} — ${finding.detail}`;
	}
	return `Fix ${finding.category.toUpperCase()}: ${finding.title} — ${finding.detail}`;
}

/**
 * Evaluate a fix plan from check results (pure function).
 * Exported for direct unit testing without needing to mock scanDomain.
 * Modeled on `evaluateCompliance`/`evaluateCscProducts`.
 */
export function evaluateFixPlan(
	checkResults: CheckResult[],
	domain: string,
	score: number | null,
	grade: string | null,
	maturityStage: number | null,
): FixPlanResult {
	// `isMeasured` (`checks.length > 0`) cannot tell "19 healthy checks" apart
	// from "19 checks that all timed out" — both are truthy. A total
	// DoH/network outage where every attempted check carries a transient
	// `checkStatus: 'timeout' | 'error'` previously read as `assessed: true`
	// and turned each check's own "check error" finding into a bogus
	// remediation action ("Fix DMARC: DMARC check error — Check failed: ...")
	// — confident output manufactured from zero completed evidence.
	// `hasCompletedEvidence` requires at least one check to have actually
	// COMPLETED, so an all-transient outage abstains the same way a
	// zero-check scan does.
	const hasEvidence = hasCompletedEvidence(checkResults);
	// Even when SOME categories completed (`hasEvidence: true`), an individual
	// category's OWN check can still have failed transiently. There are TWO
	// distinct producers of that shape, and only one of them tags the finding:
	// `buildDnsErrorResult` (used by tools with their own top-level DNS-error
	// handling, e.g. check-dmarc.ts) sets BOTH `checkStatus: 'error'` AND
	// `metadata.errorKind: 'dns_error'`. `safeCheck` — scan_domain's OWN
	// orchestrator-level catch, `src/tools/scan-domain.ts`'s `safeCheck()`,
	// which is what actually runs during a real production scan for any check
	// that doesn't have its own internal DNS-error handling — sets
	// `checkStatus: 'error' | 'timeout'` but NEVER `errorKind`. A per-finding
	// `errorKind` filter alone therefore misses every safeCheck-produced
	// transient: `checkStatus: 'timeout'` would render as an action
	// ("Fix DMARC: DMARC check timed out — ...") in the SAME plan that also
	// lists that category under `transientCategories` — self-contradictory
	// output. Filtering on `checkStatus` at the CHECK level first (mirrors
	// `map_compliance`'s `completed` filter and this file's own
	// `transientCategories` below) catches BOTH producers regardless of
	// whether the errorKind marker was set.
	//
	// The `isDnsErrorFinding` filter is kept as a SECOND, independent guard —
	// not redundant with the checkStatus filter above. A check can COMPLETE
	// (`checkStatus` absent/'completed') and still attach an errorKind-tagged
	// finding for a narrower reason than a full check failure — e.g.
	// `discover-brand-domains.ts`'s "Brand-domain discovery could not
	// complete" finding, emitted when every discovery SIGNAL failed but the
	// check itself ran to completion. That finding would survive the
	// checkStatus filter (the check completed) but must still never become a
	// fix action, so both filters stay in force.
	const actionableFindings = hasEvidence
		? checkResults
				.filter((c) => c.checkStatus !== 'error' && c.checkStatus !== 'timeout')
				.flatMap((check: CheckResult) => check.findings)
				.filter((f: Finding) => f.severity !== 'info' && !isDnsErrorFinding(f))
		: [];

	const actions: FixAction[] = actionableFindings.map((finding: Finding) => {
		const importanceWeight = IMPORTANCE_WEIGHTS[finding.category]?.importance ?? 0;
		const severityWeight = SEVERITY_WEIGHT[finding.severity];
		const priority = importanceWeight * severityWeight;

		return {
			priority,
			category: finding.category,
			action: findingToAction(finding),
			severity: finding.severity,
			effort: EFFORT_MAP[finding.category] ?? 'medium',
			impact: severityToImpact(finding.severity),
			dependencies: DEPENDENCY_MAP[finding.category] ?? [],
			findingTitle: finding.title,
		};
	});

	// Sort by priority descending (highest impact first)
	actions.sort((a, b) => b.priority - a.priority);

	// Two independent questions, each answered by its own shared primitive.
	// `assessed`: is there any COMPLETED evidence (drives the caveat and the
	// zero-actions wording)? `isGraded`: did the scan produce a real overall
	// score — the three degraded builders and an all-inconclusive scan alike
	// hardcode or derive a placeholder `maturity.stage` that is not a posture
	// measurement.
	const assessed = hasEvidence;
	const caveat = assessed
		? null
		: checkResults.length === 0
			? UNASSESSED_FIX_PLAN_CAVEAT
			: buildAllTransientFixPlanCaveat(checkResults.length);

	// The categories excluded from `actionableFindings` above because their OWN
	// check never completed. Only computed when `assessed` is true — the
	// all-transient/never-ran case is already fully represented by `caveat`,
	// and listing every category here too would just restate the same fact in
	// a second vocabulary.
	const transientCategories: CheckCategory[] = assessed
		? checkResults.filter((c) => c.checkStatus === 'error' || c.checkStatus === 'timeout').map((c) => c.category)
		: [];

	return {
		domain,
		score,
		grade,
		maturityStage,
		totalActions: actions.length,
		actions,
		assessed,
		caveat,
		transientCategories,
	};
}

/**
 * Generate a prioritized fix plan for a domain.
 *
 * @param domain - Validated, sanitized domain
 * @param kv - Optional KV namespace for caching
 * @param runtimeOptions - Scan runtime options
 * @returns Prioritized fix plan
 */
export async function generateFixPlan(domain: string, kv?: KVNamespace, runtimeOptions?: ScanRuntimeOptions): Promise<FixPlanResult> {
	const scanResult = await scanDomain(domain, kv, runtimeOptions);

	return evaluateFixPlan(
		scanResult.checks,
		domain,
		scanResult.score.overall,
		scanResult.score.grade,
		isGraded(scanResult.score) ? scanResult.maturity.stage : null,
	);
}

/**
 * Note for categories excluded from `actions` because their own check failed
 * transiently (see `FixPlanResult.transientCategories`). Shared by both format
 * modes so the two surfaces cannot describe the same exclusion two ways.
 */
function transientCategoriesNote(categories: CheckCategory[]): string {
	const n = categories.length;
	return `${n} categor${n === 1 ? 'y' : 'ies'} could not be assessed (transient check failure, not a clean result): ${categories.join(', ')}.`;
}

/** Format a fix plan as a human-readable text report. */
export function formatFixPlan(plan: FixPlanResult, format: OutputFormat = 'full'): string {
	const lines: string[] = [];

	if (format === 'compact') {
		lines.push(`Fix Plan: ${plan.domain} — ${formatScoreGrade(plan.score, plan.grade)}, ${plan.totalActions} actions`);
		if (plan.actions.length === 0) {
			// `caveat` is REQUIRED on `FixPlanResult`, so the real producer
			// (`generateFixPlan`) always states which reason applies whenever
			// `!assessed`. Falling back to `UNASSESSED_FIX_PLAN_CAVEAT` specifically
			// is the same silent-wrong-prose shape closed elsewhere this fix round
			// (map_csc_products, map_compliance): a fabricated/hand-built plan with
			// a somehow-unset `caveat` would render the never-ran-specific text
			// even for an all-transient state. The only genuinely safe fallback
			// here makes no specific claim.
			if (!plan.assessed) {
				lines.push(plan.caveat ?? 'This domain could not be assessed.');
			} else if (plan.transientCategories.length > 0) {
				// Zero actions here does NOT mean a clean bill of health — some
				// category was never actually measured. Say so instead of reading
				// as "No actionable findings" (see the full-mode branch below).
				lines.push(transientCategoriesNote(plan.transientCategories));
			} else {
				lines.push('No actionable findings.');
			}
			return lines.join('\n');
		}
		const maxShow = 5;
		const shown = plan.actions.slice(0, maxShow);
		for (let i = 0; i < shown.length; i++) {
			const a = shown[i];
			lines.push(`${i + 1}. [${a.severity.toUpperCase()}] ${a.category.toUpperCase()}: ${sanitizeOutputText(a.action, 150)} (${a.effort})`);
		}
		if (plan.actions.length > maxShow) {
			lines.push(`... and ${plan.actions.length - maxShow} more`);
		}
		if (plan.transientCategories.length > 0) {
			lines.push(transientCategoriesNote(plan.transientCategories));
		}
		return lines.join('\n');
	}

	const maturity = plan.maturityStage === null ? UNGRADED_DISPLAY : `${plan.maturityStage}/4`;
	lines.push(`# Fix Plan: ${plan.domain}`);
	lines.push(`Score: ${formatScoreGrade(plan.score, plan.grade)} | Maturity Stage: ${maturity}`);
	lines.push(`${plan.totalActions} remediation action${plan.totalActions !== 1 ? 's' : ''} identified`);
	lines.push('');

	if (plan.actions.length === 0) {
		// Zero actions is only good news when something was actually examined.
		// See the compact-mode fallback above for why this does NOT fall back to
		// `UNASSESSED_FIX_PLAN_CAVEAT` specifically.
		if (!plan.assessed) {
			lines.push(plan.caveat ?? 'This domain could not be assessed.');
		} else if (plan.transientCategories.length > 0) {
			lines.push(transientCategoriesNote(plan.transientCategories));
		} else {
			lines.push('No actionable findings. Domain security posture is strong.');
		}
		return lines.join('\n');
	}

	for (let i = 0; i < plan.actions.length; i++) {
		const action = plan.actions[i];
		const num = i + 1;
		lines.push(`## ${num}. [${action.severity.toUpperCase()}] ${action.category.toUpperCase()}`);
		lines.push(`Action: ${action.action}`);
		lines.push(`Effort: ${action.effort} | Impact: ${action.impact}`);
		if (action.dependencies.length > 0) {
			lines.push(`Dependencies: ${action.dependencies.join('; ')}`);
		}
		lines.push('');
	}

	if (plan.transientCategories.length > 0) {
		lines.push(transientCategoriesNote(plan.transientCategories));
	}

	return lines.join('\n');
}
