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
import { formatScoreGrade, isMeasured, UNGRADED_DISPLAY } from '../lib/ungraded-display';

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

	const actionableFindings = scanResult.checks
		.flatMap((check: CheckResult) => check.findings)
		.filter((f: Finding) => f.severity !== 'info');

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
	// `assessed`: did anything run at all (drives the caveat and the zero-actions
	// wording)? `isGraded`: did the scan produce a real overall score — the three
	// degraded builders and an all-inconclusive scan alike hardcode or derive a
	// placeholder `maturity.stage` that is not a posture measurement.
	const assessed = isMeasured(scanResult.checks);

	return {
		domain,
		score: scanResult.score.overall,
		grade: scanResult.score.grade,
		maturityStage: isGraded(scanResult.score) ? scanResult.maturity.stage : null,
		totalActions: actions.length,
		actions,
		assessed,
		caveat: assessed ? null : UNASSESSED_FIX_PLAN_CAVEAT,
	};
}

/** Format a fix plan as a human-readable text report. */
export function formatFixPlan(plan: FixPlanResult, format: OutputFormat = 'full'): string {
	const lines: string[] = [];

	if (format === 'compact') {
		lines.push(`Fix Plan: ${plan.domain} — ${formatScoreGrade(plan.score, plan.grade)}, ${plan.totalActions} actions`);
		if (plan.actions.length === 0) {
			lines.push(plan.assessed ? 'No actionable findings.' : (plan.caveat ?? UNASSESSED_FIX_PLAN_CAVEAT));
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
		lines.push(plan.assessed ? 'No actionable findings. Domain security posture is strong.' : (plan.caveat ?? UNASSESSED_FIX_PLAN_CAVEAT));
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
