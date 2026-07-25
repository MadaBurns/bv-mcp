// SPDX-License-Identifier: BUSL-1.1

/**
 * Abstain-on-ungraded behaviour across every consumer widened by the nullable
 * `ScanScore.overall` / `ScanScore.grade` migration.
 *
 * These branches are NOT reachable through the live tool surface yet — the scan
 * producers still emit the legacy `overall: 0, grade: 'N/A'` shape and only start
 * emitting `null` in a later task. That is exactly why they are pinned here: without
 * these tests, every branch would execute for the FIRST time in production the day
 * the producers flip, and a mistake in any of them would ship silently green.
 *
 * Each case builds a `ScanScore` literal with nulls directly, so no producer change
 * is required to exercise the real code path.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import type { ScanScore } from '@blackveil/dns-checks/scoring';
import type { ScanDomainResult } from '../src/tools/scan-domain';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

/** A fully-populated ScanScore with NO measurement behind it. */
function ungradedScore(overrides: Partial<ScanScore> = {}): ScanScore {
	return {
		overall: null,
		grade: null,
		categoryScores: {} as ScanScore['categoryScores'],
		findings: [],
		summary: 'Scan could not be scored.',
		...overrides,
	};
}

/** A normal, measured ScanScore — the control for every "still works" assertion. */
function gradedScore(overrides: Partial<ScanScore> = {}): ScanScore {
	return {
		overall: 78,
		grade: 'B',
		categoryScores: { spf: 100, dmarc: 80 } as unknown as ScanScore['categoryScores'],
		findings: [],
		summary: 'Reasonable configuration. Grade: B',
		...overrides,
	};
}

function scanResult(score: ScanScore, overrides: Partial<ScanDomainResult> = {}): ScanDomainResult {
	return {
		domain: 'example.com',
		score,
		checks: [],
		maturity: { stage: 0, label: 'Unprotected', description: 'No controls detected.', nextStep: 'Publish SPF.' },
		context: { profile: 'mail_enabled', signals: [], detectedProvider: null } as unknown as ScanDomainResult['context'],
		cached: false,
		timestamp: new Date().toISOString(),
		scoringNote: null,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
		...overrides,
	};
}

describe('formatScanReport — ungraded scan', () => {
	it('renders the UNGRADED_DISPLAY token instead of a fabricated score line', async () => {
		const { formatScanReport, UNGRADED_DISPLAY } = await import('../src/tools/scan/format-report');
		const text = formatScanReport(scanResult(ungradedScore()), 'full');

		const scoreLine = text.split('\n').find((l) => l.startsWith('Overall Score:'));
		expect(scoreLine).toBeDefined();
		expect(scoreLine).toContain(UNGRADED_DISPLAY);
		// The fabrication this replaces: `0/100 (F)` / `null/100 (null)`.
		expect(scoreLine).not.toContain('/100');
		expect(scoreLine).not.toContain('null');
	});

	it('leaves the engine summary untouched rather than rewriting a grade token into it', async () => {
		const { formatScanReport } = await import('../src/tools/scan/format-report');
		// A summary that DOES carry a rewritable 'Grade: X' token — so the assertion
		// fails if the rewriter runs, rather than passing because there was nothing to rewrite.
		const text = formatScanReport(scanResult(ungradedScore({ summary: 'Unscored. Grade: D+' })), 'full');
		expect(text).toContain('Unscored. Grade: D+');
	});

	it('still renders a real score line for a measured scan (control)', async () => {
		const { formatScanReport, UNGRADED_DISPLAY } = await import('../src/tools/scan/format-report');
		const text = formatScanReport(scanResult(gradedScore()), 'full');

		const scoreLine = text.split('\n').find((l) => l.startsWith('Overall Score:'));
		expect(scoreLine).toBeDefined();
		expect(scoreLine).toContain('78/100');
		expect(scoreLine).not.toContain(UNGRADED_DISPLAY);
	});
});

describe('buildStructuredScanResult — ungraded scan', () => {
	it('emits null score/grade/passed rather than a coerced pass/fail verdict', async () => {
		const { buildStructuredScanResult } = await import('../src/tools/scan/format-report');
		const structured = buildStructuredScanResult(scanResult(ungradedScore()));

		expect(structured.score).toBeNull();
		expect(structured.grade).toBeNull();
		// The defect: `null >= 50` is `false`, so an unmeasured domain reported a
		// confident `passed: false` — a security failure it was never assessed for.
		expect(structured.passed).toBeNull();
		// NOT a guard on the null-score handling — `measured` is derived from
		// `checks.length > 0` and holds under the un-fixed code too. It is here to pin
		// the documented invariant that `measured === false` accompanies a null score.
		expect(structured.measured).toBe(false);
	});

	it('still emits a real boolean passed for a measured scan (control)', async () => {
		const { buildStructuredScanResult } = await import('../src/tools/scan/format-report');
		const structured = buildStructuredScanResult(
			scanResult(gradedScore(), { checks: [{ category: 'spf', passed: true, score: 100, findings: [] }] }),
		);

		expect(structured.score).toBe(78);
		expect(structured.passed).toBe(true);
		expect(structured.measured).toBe(true);
	});
});

describe('gradeBadge — null grade', () => {
	it('renders the error badge rather than an SVG carrying a fabricated letter', async () => {
		const { gradeBadge, errorBadge } = await import('../src/lib/badge');
		const svg = gradeBadge(null);

		expect(svg).toBe(errorBadge());
		for (const letter of ['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'F']) {
			expect(svg).not.toContain(`>${letter}<`);
		}
	});

	it('still renders the letter for a real grade (control)', async () => {
		const { gradeBadge, errorBadge } = await import('../src/lib/badge');
		const svg = gradeBadge('A+');

		expect(svg).toContain('A+');
		expect(svg).not.toBe(errorBadge());
	});
});

describe('compareBaseline — ungraded scan skips its grade/score rules', () => {
	it('records neither a grade nor a score violation, and counts neither rule as checked', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(scanResult(ungradedScore()), { grade: 'B', score: 50 });

		// Pre-fix this returned exactly ONE violation: the grade rule silently PASSED
		// (GRADE_ORDER.indexOf(null) === -1 → gradeWorseThan returns false) while the
		// score rule FAILED (`null < 50` coerces to `0 < 50`) — opposite directions on
		// the same scan, in a CI/CD policy gate.
		expect(result.violations).toHaveLength(0);
		expect(result.checkedRules).toBe(0);
	});

	it('still evaluates both rules for a measured scan (control)', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(scanResult(gradedScore({ overall: 40, grade: 'F' })), { grade: 'B', score: 50 });

		expect(result.checkedRules).toBe(2);
		expect(result.violations.map((v) => v.rule).sort()).toEqual(['grade', 'score']);
	});
});

describe('computeDrift / classifyDrift — ungraded side', () => {
	it('reports a null scoreDelta instead of a NaN or a fabricated points delta', async () => {
		const { computeDrift } = await import('../src/tools/analyze-drift');
		const report = computeDrift('example.com', gradedScore(), ungradedScore());

		// `null - 78` is NaN; `0 - 78` is a fabricated 78-point collapse.
		expect(report.scoreDelta).toBeNull();
		expect(report.gradeChange).toEqual({ from: 'B', to: null });
	});

	it('renders "not measured" in the SCORE-DELTA segment specifically, in both compact and full', async () => {
		const { computeDrift, formatDriftReport } = await import('../src/tools/analyze-drift');
		const report = computeDrift('example.com', gradedScore(), ungradedScore());

		// Deliberately NOT a bare `toContain(UNGRADED_DISPLAY)`: in this fixture the
		// current GRADE is also null, so the grade segment alone satisfies a bare check
		// and the delta segment goes unpinned. These assert the delta position itself —
		// they fail if the delta renders as a number (e.g. `null - 78` coercing to -78).
		const compact = formatDriftReport(report, 'compact');
		expect(compact).toContain('(not measured,');

		const full = formatDriftReport(report, 'full');
		expect(full).toContain('**Score:** not measured');

		for (const [format, text] of [
			['compact', compact],
			['full', full],
		] as const) {
			expect(text, format).not.toContain('NaN');
			expect(text, format).not.toContain('null');
			expect(text, format).not.toContain('0 pts');
		}
	});

	it('still renders a real delta for two measured scans (control)', async () => {
		const { computeDrift, formatDriftReport } = await import('../src/tools/analyze-drift');
		const { UNGRADED_DISPLAY } = await import('../src/tools/scan/format-report');
		const report = computeDrift('example.com', gradedScore({ overall: 60, grade: 'C' }), gradedScore());

		expect(report.scoreDelta).toBe(18);
		const text = formatDriftReport(report, 'full');
		expect(text).toContain('+18 pts');
		expect(text).not.toContain(UNGRADED_DISPLAY);
	});

	/**
	 * CHARACTERIZATION ONLY — this does NOT guard `classifyDrift`'s `?? 0`.
	 *
	 * `classifyDrift` uses `delta` in exactly three relational comparisons
	 * (`> 2`, `< -2`, `> 2`), and JS evaluates `null > 2` and `null < -2` identically
	 * to `0 > 2` and `0 < -2`. So the abstaining form (`scoreDelta ?? 0`) and a raw
	 * coercing cast produce the SAME classification for every reachable input —
	 * verified exhaustively over newCriticalHighCount/resolvedCount 0..5: zero
	 * divergent pairs. No fixture can distinguish them through the public surface.
	 *
	 * These cases therefore pin the CONTRACT (a missing score signal must not suppress
	 * a finding-based verdict) rather than the null-handling itself. Kept because they
	 * would catch a future refactor that changed the finding-based rules, and labelled
	 * so nobody mistakes them for a guard on the `?? 0`.
	 */
	it('[characterization] classifies on the finding-based rules alone when there is no score signal', async () => {
		const { classifyDrift } = await import('../src/tools/analyze-drift');

		// No score signal and no finding movement → nothing to call a regression.
		expect(classifyDrift(null, 0, 0)).toBe('stable');
		// A null delta must not suppress a genuine finding-based regression...
		expect(classifyDrift(null, 1, 0)).toBe('regressing');
		// ...nor a genuine finding-based improvement, nor both at once.
		expect(classifyDrift(null, 0, 3)).toBe('stable');
		expect(classifyDrift(null, 2, 3)).toBe('mixed');
	});
});

describe('applyInteractionPenalties — ungraded score', () => {
	// spf 0 + dmarc 0 fires `no_spf_no_dmarc` (-10) and dkim 0 + dmarc 0 fires
	// `weak_dkim_permissive_dmarc` (-5). A fixture that triggers NOTHING would make
	// the `effects: []` assertion below pass under any implementation.
	const triggeringCategoryScores = { spf: 0, dmarc: 0, dkim: 0 } as unknown as ScanScore['categoryScores'];

	it('returns the score untouched instead of computing null - penalty (NaN)', async () => {
		const { applyInteractionPenalties } = await import('../src/lib/category-interactions');
		const score = ungradedScore({ categoryScores: triggeringCategoryScores });
		const { adjustedScore, effects } = applyInteractionPenalties(score);

		expect(adjustedScore.overall).toBeNull();
		expect(adjustedScore.grade).toBeNull();
		expect(Number.isNaN(adjustedScore.overall as unknown as number)).toBe(false);
		expect(effects).toEqual([]);
	});

	it('proves that same fixture DOES trigger penalties once the score is measured (control)', async () => {
		const { applyInteractionPenalties } = await import('../src/lib/category-interactions');
		const score = gradedScore({ overall: 60, grade: 'C', categoryScores: triggeringCategoryScores });
		const { adjustedScore, effects } = applyInteractionPenalties(score);

		// Without this the ungraded assertion above would be vacuous.
		expect(effects.length).toBeGreaterThan(0);
		expect(adjustedScore.overall).toBeLessThan(60);
	});
});

describe('analyze_drift cached baseline — ungraded cached scan is rejected', () => {
	function makeKv(seed: Record<string, unknown> = {}): KVNamespace {
		const store = new Map<string, string>(Object.entries(seed).map(([k, v]) => [k, JSON.stringify(v)]));
		return {
			async get(key: string, type?: string): Promise<unknown> {
				const raw = store.get(key);
				if (raw === undefined) return null;
				return type === 'json' ? JSON.parse(raw) : raw;
			},
			async put(key: string, value: string): Promise<void> {
				store.set(key, value);
			},
			async delete(key: string): Promise<void> {
				store.delete(key);
			},
			async list(): Promise<unknown> {
				return { keys: [], list_complete: true, cacheStatus: null };
			},
			async getWithMetadata(): Promise<unknown> {
				return { value: null, metadata: null };
			},
		} as unknown as KVNamespace;
	}

	it("rejects a cached scan carrying the legacy 'N/A' sentinel instead of diffing against it", async () => {
		const { buildScanCacheKey } = await import('../src/lib/cache');
		const { handleToolsCall } = await import('../src/handlers/tools');

		// The exact shape buildNonResolvingResult writes for an NXDOMAIN apex: zero
		// checks, but score/grade populated with degraded placeholders — so isGraded()
		// alone returns TRUE and waves it through.
		const cachedUngraded = scanResult(ungradedScore({ overall: 0, grade: 'N/A' }), { resolves: false });
		const kv = makeKv({ [buildScanCacheKey('example.com')]: cachedUngraded });

		const result = await handleToolsCall({ name: 'analyze_drift', arguments: { domain: 'example.com', baseline: 'cached' } }, kv);

		expect(result.isError).toBe(true);
		const text = result.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');
		// Without this guard the report reads e.g. "Score: +73 pts (N/A -> B), improving" —
		// a fabricated improvement against a baseline that was never measured.
		expect(text).toContain('never graded');
		// The message must start with an allowlisted prefix or sanitizeErrorMessage()
		// replaces it with the generic fallback over the wire.
		expect(text).toContain('Invalid baseline:');
	});

	it('rejects a cached scan carrying a null grade (post-producer-migration shape)', async () => {
		const { buildScanCacheKey } = await import('../src/lib/cache');
		const { handleToolsCall } = await import('../src/handlers/tools');

		const cachedUngraded = scanResult(ungradedScore(), { resolves: false });
		const kv = makeKv({ [buildScanCacheKey('example.com')]: cachedUngraded });

		const result = await handleToolsCall({ name: 'analyze_drift', arguments: { domain: 'example.com', baseline: 'cached' } }, kv);

		expect(result.isError).toBe(true);
		const text = result.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');
		expect(text).toContain('never graded');
	});

	it('still reports "no cached scan" when the cache is genuinely empty (control — distinct error)', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall({ name: 'analyze_drift', arguments: { domain: 'example.com', baseline: 'cached' } }, makeKv());

		expect(result.isError).toBe(true);
		const text = result.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');
		expect(text).toContain('no cached scan');
		expect(text).not.toContain('never graded');
	});
});
