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
 * Generate a prioritized fix plan for a domain.
 *
 * @param domain - Validated, sanitized domain
 * @param kv - Optional KV namespace for caching
 * @param runtimeOptions - Scan runtime options
 * @returns Prioritized fix plan
 */
export async function generateFixPlan(domain: string, kv?: KVNamespace, runtimeOptions?: ScanRuntimeOptions): Promise<FixPlanResult> {
	const scanResult = await scanDomain(domain, kv, runtimeOptions);

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
	const hasEvidence = hasCompletedEvidence(scanResult.checks);
	const actionableFindings = hasEvidence
		? scanResult.checks.flatMap((check: CheckResult) => check.findings).filter((f: Finding) => f.severity !== 'info')
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
		: scanResult.checks.length === 0
			? UNASSESSED_FIX_PLAN_CAVEAT
			: buildAllTransientFixPlanCaveat(scanResult.checks.length);

	return {
		domain,
		score: scanResult.score.overall,
		grade: scanResult.score.grade,
		// `indeterminate` (#574): a GRADED scan whose maturity ladder abstained because
		// a load-bearing check was never measured carries a placeholder stage, exactly
		// like a degraded builder's — so it is withheld here too, or "Maturity Stage:
		// 0/4" renders a posture verdict nobody measured.
		maturityStage: isGraded(scanResult.score) && scanResult.maturity.indeterminate !== true ? scanResult.maturity.stage : null,
		totalActions: actions.length,
		actions,
		assessed,
		caveat,
	};
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
			lines.push(plan.assessed ? 'No actionable findings.' : (plan.caveat ?? 'This domain could not be assessed.'));
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
		lines.push(
			plan.assessed ? 'No actionable findings. Domain security posture is strong.' : (plan.caveat ?? 'This domain could not be assessed.'),
		);
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

	return lines.join('\n');
}
