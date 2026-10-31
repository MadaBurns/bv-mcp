// SPDX-License-Identifier: BUSL-1.1

/**
 * Text and structured rendering of `scan_domain`'s NON-SCORING web posture section (US-16 T10).
 *
 * The section is printed after the scored findings under its own heading, and says in words that
 * it does not affect the score or grade. A check that produced no measurement is printed as "not
 * assessed" with its reason, never as a pass.
 */

import type { CheckResult, Finding } from '../../lib/scoring';
import type { OutputFormat } from '../../handlers/tool-args';
import { sanitizeOutputText } from '../../lib/output-sanitize';
import { isCompletedCheck } from '../../lib/ungraded-display';
import type { WebPostureSection } from './web-posture';

export const WEB_POSTURE_HEADING = 'Not graded: web posture';
export const WEB_POSTURE_DISCLAIMER = 'These checks are informational only. They do not affect the score or grade above.';

function isIssue(finding: Finding): boolean {
	return finding.severity !== 'info';
}

function isNotAssessed(finding: Finding): boolean {
	return finding.metadata?.notAssessed === true;
}

function issueCountLabel(count: number): string {
	if (count === 0) return 'no issues found';
	return count === 1 ? '1 issue' : `${count} issues`;
}

function statusLabel(result: CheckResult): string {
	return isCompletedCheck(result) ? issueCountLabel(result.findings.filter(isIssue).length) : 'not assessed';
}

function statusIcon(result: CheckResult): string {
	if (!isCompletedCheck(result)) return '∅';
	return result.findings.some(isIssue) ? '⚠' : '✓';
}

function notAssessedReason(result: CheckResult): string {
	const finding = result.findings.find(isNotAssessed) ?? result.findings[0];
	return finding === undefined ? '' : ` — ${sanitizeOutputText(finding.detail, 200)}`;
}

function issueLines(finding: Finding): string[] {
	return [
		`    [${finding.severity.toUpperCase()}] ${sanitizeOutputText(finding.title, 120)}`,
		`      ${sanitizeOutputText(finding.detail)}`,
	];
}

function notAssessedPartLine(finding: Finding): string {
	return `    Not assessed: ${sanitizeOutputText(finding.title, 120)}`;
}

function fullLines(result: CheckResult): string[] {
	const head = `  ${statusIcon(result)} ${result.category.toUpperCase().padEnd(14)} ${statusLabel(result)}`;
	if (!isCompletedCheck(result)) return [`${head}${notAssessedReason(result)}`];
	return [head, ...result.findings.filter(isIssue).flatMap(issueLines), ...result.findings.filter(isNotAssessed).map(notAssessedPartLine)];
}

function compactIssue(finding: Finding): string {
	return `[${finding.severity.toUpperCase()}] ${sanitizeOutputText(finding.title, 120)}`;
}

function compactLine(result: CheckResult): string {
	const head = `  ${result.category.toUpperCase()}: ${statusLabel(result)}`;
	const issues = isCompletedCheck(result) ? result.findings.filter(isIssue) : [];
	return issues.length === 0 ? head : `${head} — ${issues.map(compactIssue).join('; ')}`;
}

/**
 * The structured `webPosture` field, emitted only when the caller opts in (`scan_domain` does) and
 * the scan carries a section. Opt-in keeps multi-domain tools (batch_scan, compare_domains) at
 * their current structured size.
 */
export function structuredWebPosture(
	section: WebPostureSection | undefined,
	enrichment: { includeWebPosture?: boolean } | undefined,
): { webPosture?: WebPostureSection } {
	return enrichment?.includeWebPosture === true && section !== undefined ? { webPosture: section } : {};
}

/**
 * The lines to append after the scored findings. Empty when the scan carries no section (the
 * kill switch is off, the scan short-circuited, or the result predates the section).
 */
export function formatWebPostureSection(section: WebPostureSection | undefined, format: OutputFormat = 'full'): string[] {
	if (section === undefined) return [];
	if (format === 'compact') return ['', `${WEB_POSTURE_HEADING} (does not affect the score or grade)`, ...section.results.map(compactLine)];
	return ['', WEB_POSTURE_HEADING, '-'.repeat(30), WEB_POSTURE_DISCLAIMER, ...section.results.flatMap(fullLines)];
}
