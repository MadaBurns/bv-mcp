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
import type { CheckResult } from '../../src/lib/scoring';

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
	 * So the rule is stated over the WIRE payload: given an input with nothing
	 * measured, the serialized result may not contain a fabricated verdict.
	 *
	 * Every surface here is built by its REAL producer from an empty check list —
	 * no hand-written literals, because a literal with `score: null` already baked
	 * in cannot fail a `"score":null` assertion, and an invariant that cannot fail
	 * is decoration. `generate_fix_plan` is deliberately ABSENT: its producer needs
	 * a mocked `scanDomain`, which does not belong in a corpus audit, so its wire
	 * payload is pinned producer-side in
	 * `test/reporting-surfaces-unmeasured.integration.test.ts` instead.
	 *
	 * `forbidden` is per surface rather than shared, so no surface carries a rule
	 * about a field it does not have — a globally-shared forbidden list would be
	 * vacuously satisfied by three of the four and read as broader than it is.
	 */
	it('no reporting tool emits a fabricated verdict on the wire for an unmeasured domain', async () => {
		const { buildToolResult } = await import('../../src/handlers/tool-formatters');
		const { evaluateCompliance, formatCompliance } = await import('../../src/tools/map-compliance');
		const { evaluateCscProducts, formatCscProducts } = await import('../../src/tools/map-csc-products');
		const { rankCscLeads, formatCscLeads } = await import('../../src/tools/prioritize-csc-leads');

		const unmeasuredCsc = evaluateCscProducts([], null, 'never-measured.example', null, null);
		const unmeasuredCompliance = evaluateCompliance([], 'never-measured.example', null, null);
		const unmeasuredLeads = rankCscLeads([{ report: unmeasuredCsc, ownershipBucket: 'consolidated' as const }]);

		const surfaces = [
			{
				tool: 'map_compliance',
				text: formatCompliance(unmeasuredCompliance, 'full'),
				data: unmeasuredCompliance as unknown,
				// The banked defect verbatim: a 0% compliance verdict and eight failed
				// controls for a domain that does not exist.
				forbidden: ['"percentage":0', '"status":"fail"', '"score":0'],
				required: ['"score":null', '"grade":null', '"assessed":false'],
				proseForbidden: [] as string[],
				proseRequired: ['not measured'],
			},
			{
				tool: 'map_csc_products',
				text: formatCscProducts(unmeasuredCsc, 'full'),
				data: unmeasuredCsc as unknown,
				// `assessed` was on the wire from the start and the formatter simply
				// never read it, so a payload rule alone did not catch the defect: the
				// prose sold three priority-tagged products under a "not measured"
				// score. Both channels are now stated, and the payload no longer carries
				// a recommendation derived from non-observation for a consumer to find.
				forbidden: ['"score":0', '"grade":"', '"recommended":true', '"recommendedCount":3'],
				required: ['"score":null', '"grade":null', '"assessed":false', '"recommendedCount":0'],
				proseForbidden: ['recommended', 'not observed', 'Managed DMARC', 'DNSSEC management'],
				proseRequired: ['not measured', 'No checks ran for this domain, so no product gap could be assessed.'],
			},
			{
				tool: 'prioritize_csc_leads',
				text: formatCscLeads(unmeasuredLeads, 'full'),
				data: unmeasuredLeads as unknown,
				// A severity manufactured from non-observation, and a hot-lead count
				// that includes a domain nobody measured.
				forbidden: ['"gapSeverity":7', '"assessed":true', '"hotLeads":1', '"score":0'],
				required: ['"score":null', '"grade":null', '"assessed":false', '"graded":false', '"gapSeverity":null'],
				proseForbidden: ['Recommended CSC products', 'Top priority'],
				proseRequired: ['not measured', 'No checks ran for this domain, so no product gap could be assessed.'],
			},
		];

		// Non-vacuity: every surface must carry at least one rule, and the producers
		// must have actually produced something to inspect.
		expect(surfaces).toHaveLength(3);
		expect(unmeasuredCompliance.frameworks.soc2.mappings.length).toBeGreaterThan(0);
		expect(unmeasuredCsc.recommendations.length).toBeGreaterThan(0);
		expect(unmeasuredLeads.rankedLeads.length).toBeGreaterThan(0);

		for (const { tool, text, data, forbidden, required, proseForbidden, proseRequired } of surfaces) {
			// The prose is the other half of the same result. `map_csc_products` shipped
			// a clean payload and a fabricated report for four commits because only the
			// payload was under a rule here.
			for (const token of proseForbidden) expect(text, `${tool}/prose: must not contain ${token}`).not.toContain(token);
			for (const token of proseRequired) expect(text, `${tool}/prose: must contain ${token}`).toContain(token);

			const result = buildToolResult(text, data, 'full');
			const structured = JSON.stringify(result.structuredContent);
			const comment = result.content.map((c) => c.text).find((t) => t.includes('STRUCTURED_RESULT'));
			expect(comment, `${tool}: STRUCTURED_RESULT comment`).toBeDefined();

			for (const [channel, payload] of [
				['structuredContent', structured],
				['STRUCTURED_RESULT', comment!],
			] as const) {
				const label = `${tool}/${channel}`;
				for (const token of forbidden) expect(payload, `${label}: must not contain ${token}`).not.toContain(token);
				for (const token of required) expect(payload, `${label}: must contain ${token}`).toContain(token);
			}
		}
	});

	/**
	 * Task 8's banked defect, as a corpus invariant rather than a producer-level fixture:
	 * a check that never COMPLETED (`checkStatus: 'timeout'`/`'error'` — the
	 * `buildDnsErrorResult`/`safeCheck` shape) is not evidence of a failed control. Before
	 * the fix, `map_compliance` filtered matched results only on category membership, so a
	 * transient DNS failure (one slow resolver) rendered as `"status":"fail"` on the wire —
	 * on a HEALTHY domain, unlike the empty-`checks[]` case covered above.
	 *
	 * Built via the REAL `evaluateCompliance` producer from a hand-built `CheckResult[]`
	 * (not `mapCompliance`/`scanDomain` — a corpus audit does not belong mocking DNS; that
	 * full-pipeline shape is covered by `test/map-compliance.spec.ts` instead), matching
	 * this file's existing pattern for the `map_compliance` surface above.
	 */
	it('a transient (never-completed) check renders not_assessed, not fail, on the wire', async () => {
		const { evaluateCompliance, formatCompliance: format } = await import('../../src/tools/map-compliance');
		const { buildToolResult } = await import('../../src/handlers/tool-formatters');

		// Only DMARC ran, and it never completed — a slow resolver, not a measured failure.
		const transientDmarc: CheckResult = {
			category: 'dmarc',
			passed: false,
			score: 0,
			findings: [{ category: 'dmarc', title: 'DMARC check timed out', severity: 'low', detail: 'Check did not complete in time.' }],
			checkStatus: 'timeout',
		};
		const report = evaluateCompliance([transientDmarc], 'slow-resolver.example', null, null);

		// NIST §4.3.3 is the only control mapping solely to `dmarc`.
		const dmarcControl = report.frameworks.nist_800_177.mappings.find((m) => m.controlId === '§4.3.3');
		// Non-vacuity guard: prove the control actually exists in the output before
		// asserting its status — an empty/missing mapping would make the assertion below
		// pass for a producer that emitted nothing at all.
		expect(dmarcControl).toBeDefined();
		expect(dmarcControl!.status).toBe('not_assessed');

		const result = buildToolResult(format(report, 'full'), report, 'full');
		const structured = JSON.stringify(result.structuredContent);
		const comment = result.content.map((c) => c.text).find((t) => t.includes('STRUCTURED_RESULT'));
		expect(comment, 'STRUCTURED_RESULT comment').toBeDefined();

		for (const [channel, payload] of [
			['structuredContent', structured],
			['STRUCTURED_RESULT', comment!],
		] as const) {
			expect(payload, `${channel}: must not fabricate a fail verdict`).not.toContain(
				'"controlId":"§4.3.3","controlName":"DMARC Policy","status":"fail"',
			);
			expect(payload, `${channel}: must carry not_assessed`).toContain(
				'"controlId":"§4.3.3","controlName":"DMARC Policy","status":"not_assessed"',
			);
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
