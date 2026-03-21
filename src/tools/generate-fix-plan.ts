// SPDX-License-Identifier: BUSL-1.1

/**
 * Generate a prioritized remediation fix plan from scan results.
 *
 * Scans the domain (using cache), inspects non-info findings,
 * and produces an ordered list of action items with effort,
 * impact, and dependency information.
 */

import type { CheckResult, Finding, Severity, CheckCategory } from '../lib/scoring-model';
import { IMPORTANCE_WEIGHTS } from '../lib/scoring-engine';
import { scanDomain } from './scan-domain';
import type { ScanRuntimeOptions } from './scan/post-processing';

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
	score: number;
	grade: string;
	maturityStage: number;
	totalActions: number;
	actions: FixAction[];
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
		case 'critical': return 'critical';
		case 'high': return 'high';
		case 'medium': return 'medium';
		default: return 'low';
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
export async function generateFixPlan(
	domain: string,
	kv?: KVNamespace,
	runtimeOptions?: ScanRuntimeOptions,
): Promise<FixPlanResult> {
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

	return {
		domain,
		score: scanResult.score.overall,
		grade: scanResult.score.grade,
		maturityStage: scanResult.maturity.stage,
		totalActions: actions.length,
		actions,
	};
}

/** Format a fix plan as a human-readable text report. */
export function formatFixPlan(plan: FixPlanResult): string {
	const lines: string[] = [];

	lines.push(`# Fix Plan: ${plan.domain}`);
	lines.push(`Score: ${plan.score}/100 (${plan.grade}) | Maturity Stage: ${plan.maturityStage}/4`);
	lines.push(`${plan.totalActions} remediation action${plan.totalActions !== 1 ? 's' : ''} identified`);
	lines.push('');

	if (plan.actions.length === 0) {
		lines.push('No actionable findings. Domain security posture is strong.');
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
