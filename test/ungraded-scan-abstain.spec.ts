// SPDX-License-Identifier: BUSL-1.1

/**
 * Abstain-on-ungraded behaviour across every consumer widened by the nullable
 * `ScanScore.overall` / `ScanScore.grade` migration.
 *
 * Most cases build a `ScanScore` literal with nulls directly, so the consumer's own
 * abstain branch is exercised without routing through a producer. They were written
 * while the producers still emitted the pre-3.35.0 `overall: 0, grade: <placeholder>`
 * shape, so that no branch would execute for the FIRST time in production the day
 * the producers flipped. The producers HAVE now flipped, and the last two describes
 * exercise the reachable end-to-end paths (`analyze_drift`'s two baseline sources and
 * the `scan_domain` tool_call analytics verdict) through the real tool surface.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import type { ScanScore } from '@blackveil/dns-checks/scoring';
import type { ScanDomainResult } from '../src/tools/scan-domain';
import { setupFetchMock, createDohResponse, nxdomainResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();
afterEach(() => {
	restore();
	IN_MEMORY_CACHE.clear();
	vi.restoreAllMocks();
});

/**
 * NS and A queries resolve (the domain is registered and delegated); every other
 * record type answers NOERROR-with-no-records. The controls need this since the
 * package grew its own derived non-resolving floor (keyed on check-ns concluding
 * no-NS-AND-no-A): an all-empty DoH mock now reads as an unresolvable domain and
 * the scan abstains, so "measured domain" fixtures must actually resolve.
 */
function installResolvingDnsFetch() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = String(input instanceof Request ? input.url : input);
		if (/dns-query|\/resolve|dns-json|dns\.google|cloudflare-dns/.test(url)) {
			const parsed = new URL(url);
			const name = (parsed.searchParams.get('name') ?? 'resolving-probe.test').replace(/\.$/, '');
			const type = (parsed.searchParams.get('type') ?? 'A').toUpperCase();
			if (type === 'NS' || type === '2') {
				return Promise.resolve(createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.example-dns.com.' }]));
			}
			if (type === 'A' || type === '1') {
				return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.10' }]));
			}
			return Promise.resolve(createDohResponse([], []));
		}
		return Promise.resolve(new Response('', { status: 200 }));
	}) as unknown as typeof globalThis.fetch;
}

/** Every DoH query answers NXDOMAIN, so scanDomain short-circuits to the ungraded result. */
function installNxdomainDnsFetch(domain: string) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = String(input instanceof Request ? input.url : input);
		if (/dns-query|\/resolve|dns-json|dns\.google|cloudflare-dns/.test(url)) {
			return Promise.resolve(nxdomainResponse(domain));
		}
		return Promise.resolve(new Response('', { status: 200 }));
	}) as unknown as typeof globalThis.fetch;
}

/** A fully-populated ScanScore with NO measurement behind it. */
function ungradedScore(overrides: Partial<ScanScore> = {}): ScanScore {
	return {
		overall: null,
		grade: null,
		categoryScores: {} as ScanScore['categoryScores'],
		findings: [],
		summary: 'Scan could not be scored.',
		// "NO measurement behind it" per the docstring above — evidence is honestly
		// zero, not a fabricated ratio for a scan that never ran.
		evidence: { attempted: 0, completed: 0, ratio: 0 },
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
		// Control fixture: a normal fully measured scan, so evidence is honestly full.
		evidence: { attempted: 19, completed: 19, ratio: 1 },
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

	/**
	 * The prose printed a maturity STAGE NUMBER while the payload built from the same
	 * result abstained.
	 *
	 * The three degraded builders all emit a maturity object carrying a placeholder
	 * `stage: 0`, whose canonical label is "Unprotected" — a posture verdict. So an
	 * NXDOMAIN scan rendered "Overall Score: not measured" and then "Email Security
	 * Maturity: Stage 0 — Does not resolve", while its own
	 * `structuredContent.maturityStage` was `null` (`buildStructuredScanResult` gates
	 * on `isGraded`) and `generate_fix_plan` said "Maturity Stage: not measured" for
	 * the same domain. Same fact, three answers.
	 */
	it.each(['compact', 'full'] as const)('withholds the maturity stage NUMBER but keeps its label [%s]', async (format) => {
		const { formatScanReport, UNGRADED_DISPLAY } = await import('../src/tools/scan/format-report');
		const result = scanResult(ungradedScore(), {
			maturity: { stage: 0, label: 'Does not resolve', description: 'The domain does not exist in DNS.', nextStep: null },
		});
		const text = formatScanReport(result, format);

		const line = text.split('\n').find((l) => l.includes('Maturity'));
		expect(line, format).toBeDefined();
		// The banked defect verbatim.
		expect(line, format).not.toContain('Stage 0');
		expect(line, format).toContain(UNGRADED_DISPLAY);
		// The LABEL is information and must survive — this is not a suppression.
		expect(line, format).toContain('Does not resolve');
		// …and the payload built from the same result agrees.
		const { buildStructuredScanResult } = await import('../src/tools/scan/format-report');
		const structured = buildStructuredScanResult(result);
		expect(structured.maturityStage, format).toBeNull();
		expect(structured.maturityLabel, format).toBe('Does not resolve');
	});

	it.each(['compact', 'full'] as const)(
		'still prints Stage 0 for a MEASURED domain that genuinely sits there [%s] (mirror)',
		async (format) => {
			const { formatScanReport, UNGRADED_DISPLAY } = await import('../src/tools/scan/format-report');
			// `scanResult`'s default maturity IS stage 0 / "Unprotected". A graded scan that
			// scores there has measured that posture, and zero is the measurement — gating
			// the stage on the mere value `0` rather than on `isGraded` would delete it.
			const result = scanResult(gradedScore({ overall: 12, grade: 'F' }), {
				checks: [{ category: 'spf', passed: false, score: 0, findings: [] }],
			});
			const text = formatScanReport(result, format);

			const line = text.split('\n').find((l) => l.includes('Maturity'));
			expect(line, format).toBeDefined();
			expect(line, format).toContain('Stage 0');
			expect(line, format).toContain('Unprotected');
			expect(line, format).not.toContain(UNGRADED_DISPLAY);
			const { buildStructuredScanResult } = await import('../src/tools/scan/format-report');
			expect(buildStructuredScanResult(result).maturityStage, format).toBe(0);
		},
	);
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
	it('renders an explicit "unknown" badge rather than an SVG carrying a fabricated letter', async () => {
		// Task 2 shipped an interim stopgap that routed a null grade through
		// errorBadge() — better than fabricating a letter, but still conflated
		// "not measured" with "server error". Task 5 finalizes the distinction:
		// gradeBadge(null) now renders its own "unknown" value text, and is no
		// longer identical to errorBadge()'s "error" value text.
		const { gradeBadge, errorBadge } = await import('../src/lib/badge');
		const svg = gradeBadge(null);

		expect(svg).toContain('unknown');
		expect(svg).not.toBe(errorBadge());
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

describe('compareBaseline — ungraded scan records its grade/score rules as inconclusive', () => {
	it('records neither a grade nor a score violation, and counts neither rule as checked', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(scanResult(ungradedScore()), { grade: 'B', score: 50 });

		// Pre-fix this returned exactly ONE violation: the grade rule silently PASSED
		// (GRADE_ORDER.indexOf(null) === -1 → gradeWorseThan returns false) while the
		// score rule FAILED (`null < 50` coerces to `0 < 50`) — opposite directions on
		// the same scan, in a CI/CD policy gate.
		expect(result.violations).toHaveLength(0);
		expect(result.checkedRules).toBe(0);
		// Skipping the rules was only half the fix: a skipped rule still yielded
		// `passed: true`, which a pipeline gating on `passed === true` reads as
		// "policy met" for a domain that was never measured.
		expect(result.passed).toBeNull();
		expect(result.inconclusiveRules).toEqual(['grade', 'score']);
	});

	it('still evaluates both rules for a measured scan (control)', async () => {
		const { compareBaseline } = await import('../src/tools/compare-baseline');
		const result = compareBaseline(scanResult(gradedScore({ overall: 40, grade: 'F' })), { grade: 'B', score: 50 });

		expect(result.checkedRules).toBe(2);
		expect(result.violations.map((v) => v.rule).sort()).toEqual(['grade', 'score']);
		expect(result.passed).toBe(false);
		expect(result.inconclusiveRules).toEqual([]);
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

	it('rejects a cached scan whose grade is a placeholder, not a real grade letter', async () => {
		const { buildScanCacheKey } = await import('../src/lib/cache');
		const { handleToolsCall } = await import('../src/handlers/tools');

		// The shape buildNonResolvingResult wrote for an NXDOMAIN apex BEFORE 3.35.0:
		// zero checks, but score/grade populated with degraded placeholders — so
		// isGraded() alone returns TRUE and waves it through. The producer no longer
		// emits it, but a version-matched cache entry or any other ScanScore source
		// still could, and the fabricated-delta consequence is unchanged.
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

	// The CALLER-SUPPLIED baseline is the same fabricated-delta hazard from the other
	// direction: `analyze_drift` accepts an arbitrary ScanScore JSON string, and a
	// `typeof grade === 'string'` check waves through any placeholder a caller pastes
	// in — including the exact `{overall: 0, grade: <placeholder>}` shape the scan
	// producers used to emit and that a caller may still have stored from an older run.
	it('rejects a caller-supplied JSON baseline whose grade is a placeholder, not a real grade letter', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		const baseline = JSON.stringify({ overall: 0, grade: 'N/A', categoryScores: {}, findings: [], summary: 'does not resolve' });

		const result = await handleToolsCall({ name: 'analyze_drift', arguments: { domain: 'example.com', baseline } }, makeKv());

		expect(result.isError).toBe(true);
		const text = result.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');
		// Without the letter check this returns a drift REPORT reading e.g.
		// "Score: +73 pts (N/A → B), IMPROVING" — a fabricated 73-point improvement
		// against a baseline that was never measured.
		expect(text).toContain('Invalid baseline:');
		expect(text).not.toContain('IMPROVING');
	});

	it('rejects a caller-supplied JSON baseline whose overall is a non-finite number', async () => {
		const { handleToolsCall } = await import('../src/handlers/tools');
		// `JSON.parse('{"overall":1e999}')` yields Infinity, and `typeof Infinity` is
		// 'number' — so the type check alone admits it and every delta becomes NaN.
		const baseline = '{"overall":1e999,"grade":"B","categoryScores":{},"findings":[],"summary":"x"}';

		const result = await handleToolsCall({ name: 'analyze_drift', arguments: { domain: 'example.com', baseline } }, makeKv());

		expect(result.isError).toBe(true);
		const text = result.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');
		expect(text).toContain('Invalid baseline:');
	});

	it('still accepts a caller-supplied JSON baseline carrying a real grade letter (control)', async () => {
		installResolvingDnsFetch();
		const { handleToolsCall } = await import('../src/handlers/tools');
		const baseline = JSON.stringify({ overall: 78, grade: 'B', categoryScores: {}, findings: [], summary: 'Grade: B' });

		const result = await handleToolsCall({ name: 'analyze_drift', arguments: { domain: 'example.com', baseline } }, makeKv());

		// Without this control every assertion above would also pass under a guard
		// that rejected EVERY caller-supplied baseline.
		expect(result.isError).toBeFalsy();
		const text = result.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');
		expect(text).toContain('Drift Analysis');
	});
});

describe('analyze_drift CURRENT side — an unmeasured current scan cannot fabricate a diff', () => {
	function makeKv(): KVNamespace {
		return {
			async get(): Promise<unknown> {
				return null;
			},
			async put(): Promise<void> {},
			async delete(): Promise<void> {},
			async list(): Promise<unknown> {
				return { keys: [], list_complete: true, cacheStatus: null };
			},
			async getWithMetadata(): Promise<unknown> {
				return { value: null, metadata: null };
			},
		} as unknown as KVNamespace;
	}

	/** A graded baseline carrying two findings that a diff could "resolve". */
	const GRADED_BASELINE = JSON.stringify({
		overall: 78,
		grade: 'B',
		categoryScores: { spf: 80, dmarc: 60 },
		summary: 'Grade: B',
		findings: [
			{ category: 'spf', title: 'SPF too permissive', severity: 'high', detail: 'x' },
			{ category: 'dmarc', title: 'DMARC p=none', severity: 'medium', detail: 'y' },
		],
	});

	it('abstains instead of reporting the baseline findings as RESOLVED when the domain has lapsed', async () => {
		installNxdomainDnsFetch('lapsed-drift-probe.com');
		const { handleToolsCall } = await import('../src/handlers/tools');

		const result = await handleToolsCall(
			{ name: 'analyze_drift', arguments: { domain: 'lapsed-drift-probe.com', baseline: GRADED_BASELINE, force_refresh: true } },
			makeKv(),
		);
		const text = result.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');

		expect(result.isError).toBe(true);
		// The defect: a monitored client domain stops existing, and the report says
		// posture is STABLE and a HIGH plus a MEDIUM finding were RESOLVED. Nothing
		// was resolved — there is no current scan to hold the findings.
		expect(text).not.toContain('Resolved');
		expect(text).not.toContain('SPF too permissive');
		expect(text).not.toContain('STABLE');
		// …and no fabricated category delta from an empty categoryScores map
		// (`current ?? 0` renders a confident `spf: 80 -> 0 (-80)`).
		expect(text).not.toContain('-80');
		// Allowlisted prefix, or sanitizeErrorMessage() replaces it over the wire.
		expect(text).toContain('Domain ');
	});

	it('still produces a real drift report when the current scan IS measured (control)', async () => {
		installResolvingDnsFetch();
		const { handleToolsCall } = await import('../src/handlers/tools');

		const result = await handleToolsCall(
			{ name: 'analyze_drift', arguments: { domain: 'measured-drift-probe.com', baseline: GRADED_BASELINE, force_refresh: true } },
			makeKv(),
		);
		const text = result.content.map((c) => (c.type === 'text' ? c.text : '')).join('\n');

		// Without this the assertions above would hold under a guard that rejected
		// EVERY drift request.
		expect(result.isError).toBeFalsy();
		expect(text).toContain('Drift Analysis');
	});
});

describe('scan_domain tool_call analytics — ungraded scan', () => {
	it("emits status 'inconclusive' rather than a confident 'fail' for a domain that does not resolve", async () => {
		const emitted: Array<{ toolName: string; status: string }> = [];
		const analytics = {
			enabled: true,
			emitRequestEvent: () => {},
			emitToolEvent: (event: { toolName: string; status: string }) => emitted.push(event),
			emitRateLimitEvent: () => {},
			emitSessionEvent: () => {},
			emitDegradationEvent: () => {},
			emitQueueBatchEvent: () => {},
			emitQuotaShardEvent: () => {},
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} as any;

		installNxdomainDnsFetch('nxdomain-analytics-probe.com');
		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall({ name: 'scan_domain', arguments: { domain: 'nxdomain-analytics-probe.com', force_refresh: true } }, undefined, {
			analytics,
		});

		const scanEvents = emitted.filter((e) => e.toolName === 'scan_domain');
		expect(scanEvents.length).toBeGreaterThan(0);
		// `null >= 50` is `false`, so the un-fixed ternary reported a confident 'fail'
		// — a security verdict for a domain that was never assessed.
		expect(scanEvents[0].status).toBe('inconclusive');
	});

	it("still emits 'pass'/'fail' for a domain that WAS measured (control)", async () => {
		const emitted: Array<{ toolName: string; status: string }> = [];
		const analytics = {
			enabled: true,
			emitRequestEvent: () => {},
			emitToolEvent: (event: { toolName: string; status: string }) => emitted.push(event),
			emitRateLimitEvent: () => {},
			emitSessionEvent: () => {},
			emitDegradationEvent: () => {},
			emitQueueBatchEvent: () => {},
			emitQuotaShardEvent: () => {},
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} as any;

		installResolvingDnsFetch();
		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall({ name: 'scan_domain', arguments: { domain: 'measured-analytics-probe.com', force_refresh: true } }, undefined, {
			analytics,
		});

		const scanEvents = emitted.filter((e) => e.toolName === 'scan_domain');
		expect(scanEvents.length).toBeGreaterThan(0);
		// Proves the assertion above discriminates: the same emit path yields a real
		// verdict once there is a measurement behind it.
		expect(['pass', 'fail']).toContain(scanEvents[0].status);
	});
});
