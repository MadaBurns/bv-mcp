// SPDX-License-Identifier: BUSL-1.1

/**
 * Drift analysis tool.
 * Compares a domain's current security posture against a previous baseline ScanScore.
 * Diffs score, findings, and category scores, then classifies drift direction.
 */

import type { OutputFormat } from '../handlers/tool-args';
import type { Finding, ScanScore } from '../lib/scoring-model';
import { sanitizeOutputText } from '../lib/output-sanitize';

/** Overall drift direction classification. */
export type DriftClassification = 'improving' | 'stable' | 'regressing' | 'mixed';

/** A finding that appeared or disappeared between baseline and current. */
export interface DriftFinding {
	category: string;
	title: string;
	severity: string;
	detail: string;
}

/** Full drift analysis report. */
export interface DriftReport {
	domain: string;
	classification: DriftClassification;
	scoreDelta: number;
	gradeChange: { from: string; to: string };
	categoryDeltas: Record<string, { from: number; to: number; delta: number }>;
	improvements: DriftFinding[];
	regressions: DriftFinding[];
	changed: Array<DriftFinding & { previousSeverity: string }>;
	timestamp: string;
}

/** Build a unique key for matching findings across snapshots. */
function findingKey(f: { category: string; title: string }): string {
	return `${f.category}::${f.title}`;
}

/**
 * Classify the overall drift direction.
 *
 * @param scoreDelta - Current score minus baseline score
 * @param newCriticalHighCount - Number of new critical/high findings (regressions)
 * @param resolvedCount - Number of resolved findings (improvements)
 */
export function classifyDrift(scoreDelta: number, newCriticalHighCount: number, resolvedCount: number): DriftClassification {
	const hasRegressions = newCriticalHighCount > 0;
	const hasImprovements = resolvedCount > 0 || scoreDelta > 2;

	// Mixed: both regressions and improvements present
	if (hasRegressions && hasImprovements) return 'mixed';

	// Regressing: score dropped significantly or has critical/high regressions with no improvements
	if (scoreDelta < -2 || (hasRegressions && !hasImprovements)) return 'regressing';

	// Improving: score increased significantly and no critical/high regressions
	if (scoreDelta > 2 && !hasRegressions) return 'improving';

	// Stable: within threshold and no regressions
	return 'stable';
}

/**
 * Compute drift between a baseline and current ScanScore.
 *
 * Matches findings by `category + title`. New findings (in current but not baseline)
 * are regressions; missing findings (in baseline but not current) are improvements.
 * Same finding with different severity is reported as changed.
 */
export function computeDrift(domain: string, baseline: ScanScore, current: ScanScore): DriftReport {
	const scoreDelta = current.overall - baseline.overall;
	const gradeChange = { from: baseline.grade, to: current.grade };

	// --- Category deltas (only changed categories) ---
	const allCategories = new Set([
		...Object.keys(baseline.categoryScores ?? {}),
		...Object.keys(current.categoryScores ?? {}),
	]);
	const categoryDeltas: DriftReport['categoryDeltas'] = {};
	for (const cat of allCategories) {
		const baseVal = (baseline.categoryScores as Record<string, number>)?.[cat] ?? 0;
		const curVal = (current.categoryScores as Record<string, number>)?.[cat] ?? 0;
		if (baseVal !== curVal) {
			categoryDeltas[cat] = { from: baseVal, to: curVal, delta: curVal - baseVal };
		}
	}

	// --- Finding diffs ---
	const baselineMap = new Map<string, Finding>();
	for (const f of baseline.findings ?? []) {
		baselineMap.set(findingKey(f), f);
	}
	const currentMap = new Map<string, Finding>();
	for (const f of current.findings ?? []) {
		currentMap.set(findingKey(f), f);
	}

	const improvements: DriftFinding[] = [];
	const regressions: DriftFinding[] = [];
	const changed: DriftReport['changed'] = [];

	// Findings in baseline but not in current → improvements (resolved)
	for (const [key, f] of baselineMap) {
		const cur = currentMap.get(key);
		if (!cur) {
			improvements.push({ category: f.category, title: f.title, severity: f.severity, detail: f.detail });
		} else if (cur.severity !== f.severity) {
			changed.push({
				category: f.category,
				title: f.title,
				severity: cur.severity,
				detail: cur.detail,
				previousSeverity: f.severity,
			});
		}
	}

	// Findings in current but not in baseline → regressions (new issues)
	for (const [key, f] of currentMap) {
		if (!baselineMap.has(key)) {
			regressions.push({ category: f.category, title: f.title, severity: f.severity, detail: f.detail });
		}
	}

	// Count critical/high regressions for classification
	const newCriticalHighCount = regressions.filter((f) => f.severity === 'critical' || f.severity === 'high').length;

	const classification = classifyDrift(scoreDelta, newCriticalHighCount, improvements.length);

	return {
		domain,
		classification,
		scoreDelta,
		gradeChange,
		categoryDeltas,
		improvements,
		regressions,
		changed,
		timestamp: new Date().toISOString(),
	};
}

/** Format a drift report as readable text for MCP clients. */
export function formatDriftReport(report: DriftReport, format: OutputFormat = 'full'): string {
	if (format === 'compact') {
		return formatDriftCompact(report);
	}
	return formatDriftFull(report);
}

function formatDriftCompact(report: DriftReport): string {
	const lines: string[] = [];
	const arrow = report.scoreDelta > 0 ? '+' : '';
	lines.push(`Drift: ${report.domain} — ${report.classification.toUpperCase()} (${arrow}${report.scoreDelta} pts, ${report.gradeChange.from} -> ${report.gradeChange.to})`);

	if (Object.keys(report.categoryDeltas).length > 0) {
		const deltas = Object.entries(report.categoryDeltas)
			.map(([cat, d]) => `${cat}: ${d.from}->${d.to}`)
			.join(', ');
		lines.push(`Categories: ${deltas}`);
	}

	if (report.improvements.length > 0) {
		lines.push(`Resolved (${report.improvements.length}): ${report.improvements.map((f) => sanitizeOutputText(f.title, 60)).join(', ')}`);
	}
	if (report.regressions.length > 0) {
		lines.push(`New issues (${report.regressions.length}): ${report.regressions.map((f) => `[${f.severity.toUpperCase()}] ${sanitizeOutputText(f.title, 60)}`).join(', ')}`);
	}
	if (report.changed.length > 0) {
		lines.push(`Changed (${report.changed.length}): ${report.changed.map((f) => `${sanitizeOutputText(f.title, 60)} (${f.previousSeverity}->${f.severity})`).join(', ')}`);
	}

	return lines.join('\n');
}

function formatDriftFull(report: DriftReport): string {
	const lines: string[] = [];
	const arrow = report.scoreDelta > 0 ? '+' : '';

	lines.push(`## Drift Analysis: ${report.domain}`);
	lines.push('');
	lines.push(`**Classification:** ${report.classification.toUpperCase()}`);
	lines.push(`**Score:** ${arrow}${report.scoreDelta} pts (${report.gradeChange.from} → ${report.gradeChange.to})`);
	lines.push('');

	// Category deltas
	const deltaEntries = Object.entries(report.categoryDeltas);
	if (deltaEntries.length > 0) {
		lines.push('### Category Changes');
		for (const [cat, d] of deltaEntries) {
			const catArrow = d.delta > 0 ? '📈' : '📉';
			lines.push(`- ${catArrow} **${cat}**: ${d.from} → ${d.to} (${d.delta > 0 ? '+' : ''}${d.delta})`);
		}
		lines.push('');
	}

	// Improvements
	if (report.improvements.length > 0) {
		lines.push('### ✅ Resolved Findings');
		for (const f of report.improvements) {
			lines.push(`- **[${f.severity.toUpperCase()}]** ${sanitizeOutputText(f.title, 120)}`);
			lines.push(`  ${sanitizeOutputText(f.detail, 200)}`);
		}
		lines.push('');
	}

	// Regressions
	if (report.regressions.length > 0) {
		lines.push('### ❌ New Findings');
		for (const f of report.regressions) {
			lines.push(`- **[${f.severity.toUpperCase()}]** ${sanitizeOutputText(f.title, 120)}`);
			lines.push(`  ${sanitizeOutputText(f.detail, 200)}`);
		}
		lines.push('');
	}

	// Changed severity
	if (report.changed.length > 0) {
		lines.push('### 🔄 Severity Changes');
		for (const f of report.changed) {
			lines.push(`- **${sanitizeOutputText(f.title, 120)}**: ${f.previousSeverity} → ${f.severity}`);
		}
		lines.push('');
	}

	// Summary
	if (report.improvements.length === 0 && report.regressions.length === 0 && report.changed.length === 0) {
		lines.push('No individual finding changes detected.');
	}

	return lines.join('\n');
}
