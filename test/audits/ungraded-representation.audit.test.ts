// SPDX-License-Identifier: BUSL-1.1

/**
 * `null` is the SINGLE representation of "this scan produced no grade".
 *
 * Before 3.35.0 there were two: a `null` at the batch_scan boundary and the
 * string sentinel `'N/A'` emitted by scan-domain's three degraded paths. Two
 * representations meant every consumer had to handle both, and consumers that
 * handled only one silently mis-rendered or mis-ranked the other. This audit
 * fails if the sentinel reappears.
 */

import { describe, it, expect } from 'vitest';

// Vitest's Workers pool has no `fs`; the source corpus is inlined at build time
// by import.meta.glob (eager, raw) so this audit runs inside workerd. Only the two
// SOURCE trees are globbed — never `test/**` — so the quoted sentinel in THIS
// file's own prose and assertions is never scanned.
//
// `packages/dns-checks/src` is in the corpus deliberately: `ScanScore`,
// `scoreToGrade` and `isGraded` all live there, so a sentinel reintroduced in the
// vendored core would otherwise be invisible to this audit. Its `__tests__/`
// subtree is excluded below — those are test fixtures, not shipped code.
const SOURCES = import.meta.glob(['../../src/**/*.ts', '../../packages/dns-checks/src/**/*.ts'], {
	eager: true,
	query: '?raw',
	import: 'default',
}) as Record<string, string>;

/** Shipped source only: drop the vendored core's colocated test suites. */
function shippedSources(): Array<[string, string]> {
	return Object.entries(SOURCES).filter(([path]) => !path.includes('/__tests__/'));
}

// Files where the literal 'N/A' is legitimate and unrelated to grading.
const ALLOWED = new Set([
	// check-fast-flux renders 'N/A' for an unbounded minimum TTL, not a grade.
	'../../src/tools/check-fast-flux.ts',
]);

/**
 * The ONE module allowed to build a `score/grade` display string. Every other
 * formatter must call its helper rather than interpolate the pair itself.
 */
const SCORE_GRADE_RENDERER = '../../src/lib/ungraded-display.ts';

describe('ungraded representation', () => {
	it('scanned a non-trivial source corpus spanning BOTH source trees', () => {
		// Non-vacuity guard: if either glob resolves to nothing, every assertion
		// below passes trivially and this audit protects nothing.
		expect(shippedSources().length).toBeGreaterThan(250);
		expect(shippedSources().some(([p]) => p.startsWith('../../src/'))).toBe(true);
		expect(shippedSources().some(([p]) => p.startsWith('../../packages/dns-checks/src/'))).toBe(true);
	});

	it("never uses the string 'N/A' as a grade value anywhere in the shipped source", () => {
		const offenders: string[] = [];
		for (const [path, source] of shippedSources()) {
			if (ALLOWED.has(path)) continue;
			// All three quoting forms — a backtick `N/A` in a template literal or a
			// doc comment escapes a check that only looks for the two quote styles.
			if (source.includes("'N/A'") || source.includes('"N/A"') || source.includes('`N/A`')) {
				offenders.push(path);
			}
		}
		expect(offenders).toEqual([]);
	});

	/**
	 * The mechanical rule behind the `null/100 (null)` regression.
	 *
	 * `${score}/100 (${grade})` over a `number | null` / `string | null` pair is
	 * invisible to TypeScript (`${null}` is legal under strict), to eslint and to
	 * every existing spec — four shipped tools began printing `null/100 (null)`
	 * into client reports with all gates green. One rule catches every instance,
	 * present and future; the per-formatter fixtures in
	 * `ungraded-formatter-rendering.spec.ts` only catch the ones someone thought of.
	 *
	 * Matches a `/100 (…)` interpolation whose PARENTHESISED expression mentions a
	 * grade — that is what distinguishes a nullable score/grade pair from the
	 * non-nullable `${spoofabilityScore}/100 (${riskLevel})` and
	 * `${populationMeanScore}/100 (… points above average)` renderings, which are
	 * legitimately not this shape.
	 */
	it('never interpolates a score/grade pair directly; every formatter routes through the shared renderer', () => {
		const SCORE_GRADE_INTERPOLATION = /\$\{[^{}]*\}\/100\s*\(\$\{[^{}]*grade[^{}]*\}\)/i;
		const offenders: string[] = [];
		for (const [path, source] of shippedSources()) {
			if (path === SCORE_GRADE_RENDERER) continue;
			if (SCORE_GRADE_INTERPOLATION.test(source)) offenders.push(path);
		}
		expect(offenders).toEqual([]);
	});

	it('the shared renderer abstains on either half being null', async () => {
		const { formatScoreGrade, UNGRADED_DISPLAY } = await import('../../src/lib/ungraded-display');

		expect(formatScoreGrade(null, null)).toBe(UNGRADED_DISPLAY);
		// Each half independently: a score with no grade, and a grade with no score,
		// are both "not measured" — neither may render its surviving half.
		expect(formatScoreGrade(73, null)).toBe(UNGRADED_DISPLAY);
		expect(formatScoreGrade(null, 'C+')).toBe(UNGRADED_DISPLAY);
		// Control — without it every assertion above holds for a function that
		// returned the token unconditionally.
		expect(formatScoreGrade(73, 'C+')).toBe('73/100 (C+)');
		// A real zero is a MEASUREMENT and must still render as one.
		expect(formatScoreGrade(0, 'F')).toBe('0/100 (F)');
	});

	it('exports exactly one ungraded display token', async () => {
		const { UNGRADED_DISPLAY } = await import('../../src/tools/scan/format-report');
		expect(UNGRADED_DISPLAY).toBe('not measured');
	});

	/**
	 * The split-surface trap, as an invariant rather than a per-tool fixture.
	 *
	 * Every reporting tool renders TWO surfaces from one result: the prose a
	 * customer reads, and the serialized payload a machine consumes
	 * (`structuredContent` plus the legacy `STRUCTURED_RESULT` comment — both built
	 * from the SAME object by `buildToolResult`). The regression this closes fixed
	 * only the prose: `map_compliance` still shipped
	 * `{"passing":0,"failing":5,"percentage":0,"status":"fail"}` with no caveat
	 * field, so every dashboard still charted a 0% compliance verdict for a domain
	 * that was never assessed. The same trap has now appeared twice on this branch.
	 *
	 * So the rule is stated over the WIRE payload, for every reporting tool at once:
	 * given an input with nothing measured, the serialized result may not contain a
	 * fabricated verdict number or letter.
	 */
	it('no reporting tool emits a fabricated verdict on the wire for an unmeasured domain', async () => {
		const { buildToolResult } = await import('../../src/handlers/tool-formatters');
		const { evaluateCompliance, formatCompliance } = await import('../../src/tools/map-compliance');
		const { evaluateCscProducts, formatCscProducts } = await import('../../src/tools/map-csc-products');
		const { formatFixPlan, UNASSESSED_FIX_PLAN_CAVEAT } = await import('../../src/tools/generate-fix-plan');
		const { rankCscLeads, formatCscLeads } = await import('../../src/tools/prioritize-csc-leads');

		const unmeasuredCsc = evaluateCscProducts([], null, 'never-measured.example', null, null);
		const surfaces: Array<{ tool: string; text: string; data: unknown }> = [
			(() => {
				const r = evaluateCompliance([], 'never-measured.example', null, null);
				return { tool: 'map_compliance', text: formatCompliance(r, 'full'), data: r };
			})(),
			{ tool: 'map_csc_products', text: formatCscProducts(unmeasuredCsc, 'full'), data: unmeasuredCsc },
			(() => {
				const p = {
					domain: 'never-measured.example',
					score: null,
					grade: null,
					maturityStage: null,
					totalActions: 0,
					actions: [],
					assessed: false,
					caveat: UNASSESSED_FIX_PLAN_CAVEAT,
				};
				return { tool: 'generate:fix_plan', text: formatFixPlan(p, 'full'), data: p };
			})(),
			(() => {
				const r = rankCscLeads([{ report: unmeasuredCsc, ownershipBucket: 'consolidated' as const }]);
				return { tool: 'prioritize_csc_leads', text: formatCscLeads(r, 'full'), data: r };
			})(),
		];

		// Non-vacuity: an empty or short list would make every assertion below trivial.
		expect(surfaces).toHaveLength(4);

		for (const { tool, text, data } of surfaces) {
			const result = buildToolResult(text, data, 'full');
			const structured = JSON.stringify(result.structuredContent);
			const comment = result.content.map((c) => c.text).find((t) => t.includes('STRUCTURED_RESULT'));
			expect(comment, `${tool}: STRUCTURED_RESULT comment`).toBeDefined();

			for (const [channel, payload] of [
				['structuredContent', structured],
				['STRUCTURED_RESULT', comment!],
			] as const) {
				const label = `${tool}/${channel}`;
				// A score or grade that was never measured is `null` on the wire —
				// never a coerced 0 and never a fabricated letter.
				expect(payload, label).toContain('"score":null');
				expect(payload, label).not.toContain('"score":0');
				expect(payload, label).toContain('"grade":null');
				// And no compliance verdict may be manufactured from that absence.
				expect(payload, label).not.toContain('"percentage":0');
				expect(payload, label).not.toContain('"status":"fail"');
			}
		}
	});

	// Spec §D1's scoring-boundary guard, expressed as an invariant over the three
	// zero-check paths (NXDOMAIN, unresolvable zone, scoring-bundle failure) plus
	// the batch placeholder: no path may return a grade with nothing measured.
	it('never returns a non-null grade alongside empty categoryScores', async () => {
		const { buildStructuredScanResult } = await import('../../src/tools/scan/format-report');
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const zeroCheckResult: any = {
			domain: 'zero-checks.example',
			score: { overall: null, grade: null, categoryScores: {}, findings: [], summary: 'nothing measured' },
			checks: [],
			maturity: { stage: 0, label: 'Unscored', description: 'x', nextStep: null },
			context: { profile: 'mail_enabled', signals: [] },
			cached: false,
			timestamp: '2026-07-26T00:00:00.000Z',
			scoringNote: null,
			adaptiveWeightDeltas: null,
			interactionEffects: [],
		};
		const structured = buildStructuredScanResult(zeroCheckResult);

		expect(Object.keys(structured.categoryScores)).toHaveLength(0);
		expect(structured.grade).toBeNull();
		expect(structured.score).toBeNull();
		expect(structured.passed).toBeNull();
		// DD4's invariant: nothing ran, so `measured` must say so.
		expect(structured.measured).toBe(false);
	});
});
