// SPDX-License-Identifier: BUSL-1.1

/**
 * Drift analysis tool (drift-over-time).
 *
 * Here "baseline" is a **prior-scan reference** — a previous ScanScore JSON
 * string, or the literal `"cached"` to reuse the last cached scan — answering
 * "how has this domain changed vs a prior scan?". It diffs score, findings, and
 * category scores against the current posture, then classifies drift direction.
 *
 * This is NOT a policy/requirements object. For compliance enforcement against
 * required controls (grade/score floors, `require_*` flags), use the
 * `compare_baseline` tool, whose `baseline` parameter is an object, not a string.
 */

import type { OutputFormat } from '../handlers/tool-args';
import type { Finding, ScanScore } from '@blackveil/dns-checks/scoring';
import { sanitizeOutputText } from '../lib/output-sanitize';
import { isGraded } from '../lib/scoring';
// The leaf module, not the `scan/format-report` re-export: that re-export drags the
// scan orchestrator's import graph in for one string constant.
import { displayGradeFor, UNGRADED_DISPLAY } from '../lib/ungraded-display';

/** Overall drift direction classification. */
export type DriftClassification = 'improving' | 'stable' | 'regressing' | 'mixed' | 'inconclusive';

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
	/**
	 * `'inconclusive'` = at least one side of the comparison carries no grade,
	 * so no drift statement can be made. Distinct from `'stable'`, which asserts
	 * that a real measurement did not move.
	 */
	classification: DriftClassification;
	/** Current score minus baseline score, or `null` when either side was never graded. */
	scoreDelta: number | null;
	/**
	 * The CUSTOMER-FACING NIST 6-band letters, from `displayGradeFor` — the same
	 * chokepoint `scan_domain`, `batch_scan`, `compare_domains` and `/badge` use, so
	 * one domain reads as one letter everywhere (#727: wiz.io at 92 was `"A"` from
	 * `scan_domain` and `"A+" -> "A+"` here, same score, same session).
	 *
	 * Deliberately NOT accompanied by a second field carrying the engine's canonical
	 * 9-band letters. Nothing here consumes them — `classifyDrift` reads `scoreDelta`,
	 * not the letter — and `scoreDelta` already carries the exact movement at finer
	 * resolution than any band. Shipping both letters in one payload would recreate
	 * the very failure the fix removes: two grades for one domain, disagreeing.
	 *
	 * Either side is `null` when that scan carried no grade. Never a fabricated letter.
	 */
	gradeChange: { from: string | null; to: string | null };
	/** Empty when `classification` is `'inconclusive'` — nothing real to diff. */
	categoryDeltas: Record<string, { from: number; to: number; delta: number }>;
	/** Empty when `classification` is `'inconclusive'` — nothing real to diff. */
	improvements: DriftFinding[];
	/** Empty when `classification` is `'inconclusive'` — nothing real to diff. */
	regressions: DriftFinding[];
	/** Empty when `classification` is `'inconclusive'` — nothing real to diff. */
	changed: Array<DriftFinding & { previousSeverity: string }>;
	timestamp: string;
}

/**
 * The letters either grade scale can emit. The canonical 9-band `scoreToGrade`
 * (A+ A B+ B C+ C D+ D F) is the superset; the NIST 6-band display scale is a
 * strict subset of it. Anything outside this set — a placeholder, an empty
 * string, an invented letter — was never a measured grade.
 *
 * This is INPUT validation and must keep admitting the 9-band letters: a baseline
 * is stored/pasted data carrying `ScanScore.grade`, the internal letter. That is a
 * separate concern from OUTPUT rendering, where `gradeChange` reports only the
 * 6-band display letter recomputed from `overall` (#727). Narrowing this set to
 * the 6 display letters would reject every real baseline written by the engine.
 */
const REAL_GRADE_LETTERS: ReadonlySet<string> = new Set(['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'F']);

/**
 * Whether a drift baseline carries a real measurement to diff against.
 *
 * Two sources reach {@link computeDrift} and BOTH could smuggle in an ungraded
 * scan: the `"cached"` path (a stored ScanScore) and the caller-supplied JSON
 * path (any object a caller pastes in). A structural `typeof grade === 'string'`
 * check admits the degraded `{ overall: 0, grade: <placeholder> }` pair the scan
 * producers emitted before 3.35.0 — and diffing against it renders a confident
 * fabricated delta ("Score: +73 pts (… → B), IMPROVING") against a baseline that
 * was never measured. Checking the grade is a REAL letter closes both sources
 * with one rule, and needs no reference to the retired sentinel value.
 *
 * `Number.isFinite` is part of the same gate: `JSON.parse('{"overall":1e999}')`
 * yields `Infinity`, whose `typeof` is `'number'`, and every delta computed
 * from it is `NaN`.
 *
 * Layered on {@link isGraded} rather than duplicating it, so "carries a grade"
 * has ONE definition fleet-wide: `isGraded` is the SSOT nullness rule, and the
 * checks below are the extra shape/domain narrowing the untrusted JSON path
 * needs on top of it (`isGraded` alone would accept `overall: "80"`).
 */
export function isUsableDriftBaseline(value: unknown): value is ScanScore & { overall: number; grade: string } {
	if (typeof value !== 'object' || value === null) return false;
	const candidate = value as ScanScore;
	if (!isGraded(candidate)) return false;
	if (typeof candidate.overall !== 'number' || !Number.isFinite(candidate.overall)) return false;
	if (typeof candidate.grade !== 'string' || !REAL_GRADE_LETTERS.has(candidate.grade)) return false;
	return Array.isArray(candidate.findings);
}

/** Build a unique key for matching findings across snapshots. */
function findingKey(f: { category: string; title: string }): string {
	return `${f.category}::${f.title}`;
}

/**
 * Classify the overall drift direction.
 *
 * @param scoreDelta - Current score minus baseline score, or `null` when either
 *   side was never graded (no score signal — the finding-based rules still apply).
 * @param newCriticalHighCount - Number of new critical/high findings (regressions)
 * @param resolvedCount - Number of resolved findings (improvements)
 */
export function classifyDrift(scoreDelta: number | null, newCriticalHighCount: number, resolvedCount: number): DriftClassification {
	// `null` = no score signal, NOT a delta of zero-meaning-stable. Treating it as 0 here
	// neutralises the score thresholds so only the finding-based rules classify. The
	// ungraded case never reaches those rules anyway: `computeDrift` short-circuits to
	// `'inconclusive'` before calling this function whenever either side carries no grade.
	//
	// NOTE: this `?? 0` is DOCUMENTARY, not load-bearing — `delta` is only ever used in
	// relational comparisons below, and JS already evaluates `null > 2` / `null < -2`
	// identically to `0 > 2` / `0 < -2` (verified exhaustively: no reachable input
	// distinguishes the two forms, so no test can guard it). It is kept so the intent is
	// explicit and so a future refactor that does ARITHMETIC on `delta` gets 0 rather
	// than NaN. Do not read its presence as evidence that a test covers it.
	const delta = scoreDelta ?? 0;
	const hasRegressions = newCriticalHighCount > 0;
	const hasImprovements = resolvedCount > 0 || delta > 2;

	// Mixed: both regressions and improvements present
	if (hasRegressions && hasImprovements) return 'mixed';

	// Regressing: score dropped significantly or has critical/high regressions with no improvements
	if (delta < -2 || (hasRegressions && !hasImprovements)) return 'regressing';

	// Improving: score increased significantly and no critical/high regressions
	if (delta > 2 && !hasRegressions) return 'improving';

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
	// Two separate `const`s, not one combined expression: TypeScript's aliased-
	// condition narrowing (4.4+) then lets the ternary below see both sides as
	// non-null, so no `!` assertion is needed (eslint bans them here).
	const baselineGraded = isGraded(baseline);
	const currentGraded = isGraded(current);
	const bothGraded = baselineGraded && currentGraded;
	const scoreDelta = baselineGraded && currentGraded ? current.overall - baseline.overall : null;
	// The engine's `.grade` is the INTERNAL 9-band letter; every customer-visible
	// letter routes through `displayGradeFor` (see `DriftReport.gradeChange`). It
	// returns `null` for an ungraded scan, which `driftGradeText` renders as
	// UNGRADED_DISPLAY — never a substituted letter.
	const gradeChange = { from: displayGradeFor(baseline), to: displayGradeFor(current) };

	// Every derived comparison below (category deltas, resolved/new/changed findings) is
	// gated on `bothGraded`. An ungraded side has no real categoryScores/findings to diff
	// against — computing "deltas" from an ungraded scan's empty categoryScores/findings
	// would render e.g. `spf: 100 -> 0 (-100)` and a baseline's findings as "RESOLVED" for
	// a domain that simply stopped existing, underneath a classification that already says
	// 'inconclusive'. The label must suppress that content, not just sit above it. Empty
	// arrays/object (not omitted fields) so `DriftReport`'s shape and every existing
	// consumer that iterates these fields unconditionally are unaffected; `classification`
	// is the authoritative signal for "nothing was computed" vs. "computed and empty".
	const categoryDeltas: DriftReport['categoryDeltas'] = {};
	const improvements: DriftFinding[] = [];
	const regressions: DriftFinding[] = [];
	const changed: DriftReport['changed'] = [];

	if (bothGraded) {
		// --- Category deltas (only changed categories) ---
		const allCategories = new Set([...Object.keys(baseline.categoryScores ?? {}), ...Object.keys(current.categoryScores ?? {})]);
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
	}

	// Count critical/high regressions for classification
	const newCriticalHighCount = regressions.filter((f) => f.severity === 'critical' || f.severity === 'high').length;

	const classification = bothGraded ? classifyDrift(scoreDelta ?? 0, newCriticalHighCount, improvements.length) : 'inconclusive';

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

/**
 * Render the score-delta token. `null` (either side ungraded) renders as
 * {@link UNGRADED_DISPLAY} — never as `0 pts`, which would read as "stable".
 */
function driftDeltaText(scoreDelta: number | null): string {
	if (scoreDelta === null) return UNGRADED_DISPLAY;
	return `${scoreDelta > 0 ? '+' : ''}${scoreDelta} pts`;
}

/** Render one side of the grade change; an ungraded scan has no letter to show. */
function driftGradeText(grade: string | null): string {
	return grade ?? UNGRADED_DISPLAY;
}

function formatDriftCompact(report: DriftReport): string {
	const lines: string[] = [];
	lines.push(
		`Drift: ${report.domain} — ${report.classification.toUpperCase()} (${driftDeltaText(report.scoreDelta)}, ${driftGradeText(report.gradeChange.from)} -> ${driftGradeText(report.gradeChange.to)})`,
	);

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
		lines.push(
			`New issues (${report.regressions.length}): ${report.regressions.map((f) => `[${f.severity.toUpperCase()}] ${sanitizeOutputText(f.title, 60)}`).join(', ')}`,
		);
	}
	if (report.changed.length > 0) {
		lines.push(
			`Changed (${report.changed.length}): ${report.changed.map((f) => `${sanitizeOutputText(f.title, 60)} (${f.previousSeverity}->${f.severity})`).join(', ')}`,
		);
	}

	return lines.join('\n');
}

function formatDriftFull(report: DriftReport): string {
	const lines: string[] = [];

	lines.push(`## Drift Analysis: ${report.domain}`);
	lines.push('');
	lines.push(`**Classification:** ${report.classification.toUpperCase()}`);
	lines.push(
		`**Score:** ${driftDeltaText(report.scoreDelta)} (${driftGradeText(report.gradeChange.from)} → ${driftGradeText(report.gradeChange.to)})`,
	);
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
