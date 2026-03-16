// SPDX-License-Identifier: BUSL-1.1

/**
 * Baseline comparison tool.
 * Compares a scan result against a policy floor for org-level enforcement.
 */

import type { CheckCategory } from '../lib/scoring';
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
	passed: boolean;
	violations: BaselineViolation[];
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

function categoryPassed(scan: ScanDomainResult, category: CheckCategory): boolean {
	const check = scan.checks.find((value) => value.category === category);
	return check?.passed ?? false;
}

function dmarcEnforced(scan: ScanDomainResult): boolean {
	const dmarcCheck = scan.checks.find((value) => value.category === 'dmarc');
	if (!dmarcCheck) return false;

	const hasNonePolicyFinding = dmarcCheck.findings.some((finding) => {
		const text = `${finding.title} ${finding.detail}`.toLowerCase();
		return finding.severity !== 'info' && (text.includes('p=none') || text.includes('policy is none'));
	});

	return dmarcCheck.passed && !hasNonePolicyFinding;
}

/** Compare a scan result against a policy baseline. */
export function compareBaseline(scan: ScanDomainResult, baseline: PolicyBaseline): BaselineResult {
	const violations: BaselineViolation[] = [];
	let checkedRules = 0;

	if (baseline.grade !== undefined) {
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

	if (baseline.score !== undefined) {
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

	if (baseline.require_dmarc_enforce) {
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

	for (const requirement of CATEGORY_REQUIREMENTS) {
		if (baseline[requirement.key]) {
			checkedRules++;
			if (!categoryPassed(scan, requirement.category)) {
				violations.push({
					rule: requirement.key,
					message: `${requirement.label} is required but check did not pass`,
					expected: true,
					actual: false,
				});
			}
		}
	}

	if (baseline.max_critical_findings !== undefined) {
		checkedRules++;
		const criticalCount = scan.score.findings.filter((finding) => finding.severity === 'critical').length;
		if (criticalCount > baseline.max_critical_findings) {
			violations.push({
				rule: 'max_critical_findings',
				message: `${criticalCount} critical findings exceed maximum of ${baseline.max_critical_findings}`,
				expected: baseline.max_critical_findings,
				actual: criticalCount,
			});
		}
	}

	if (baseline.max_high_findings !== undefined) {
		checkedRules++;
		const highCount = scan.score.findings.filter((finding) => finding.severity === 'high').length;
		if (highCount > baseline.max_high_findings) {
			violations.push({
				rule: 'max_high_findings',
				message: `${highCount} high findings exceed maximum of ${baseline.max_high_findings}`,
				expected: baseline.max_high_findings,
				actual: highCount,
			});
		}
	}

	return {
		domain: scan.domain,
		passed: violations.length === 0,
		violations,
		checkedRules,
		scoringProfile: scan.context?.profile,
		timestamp: new Date().toISOString(),
	};
}

/** Format baseline result as readable markdown text for MCP clients. */
export function formatBaselineResult(result: BaselineResult): string {
	const lines: string[] = [];

	lines.push(`## Baseline Comparison: ${result.domain}`);
	lines.push(`**Result:** ${result.passed ? 'PASS' : 'FAIL'}`);
	lines.push(`**Rules checked:** ${result.checkedRules}`);
	lines.push(`**Violations:** ${result.violations.length}`);
	lines.push('');

	if (result.violations.length === 0) {
		lines.push('All baseline rules met.');
		return lines.join('\n');
	}

	lines.push('### Violations');
	for (const violation of result.violations) {
		lines.push(`- **${violation.rule}** - ${violation.message}`);
		lines.push(`  Expected: ${violation.expected} | Actual: ${violation.actual}`);
	}

	return lines.join('\n');
}
