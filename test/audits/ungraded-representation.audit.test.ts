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
// by import.meta.glob (eager, raw) so this audit runs inside workerd. Only
// `src/**` is globbed, so the quoted sentinel in THIS file's own prose and
// assertions is never scanned.
const SOURCES = import.meta.glob('../../src/**/*.ts', { eager: true, query: '?raw', import: 'default' }) as Record<string, string>;

// Files where the literal 'N/A' is legitimate and unrelated to grading.
const ALLOWED = new Set([
	// check-fast-flux renders 'N/A' for an unbounded minimum TTL, not a grade.
	'../../src/tools/check-fast-flux.ts',
]);

describe('ungraded representation', () => {
	it('scanned a non-trivial source corpus', () => {
		// Non-vacuity guard: if the glob resolves to nothing, every assertion
		// below passes trivially and this audit protects nothing.
		expect(Object.keys(SOURCES).length).toBeGreaterThan(50);
	});

	it("never uses the string 'N/A' as a grade value anywhere in src/", () => {
		const offenders: string[] = [];
		for (const [path, source] of Object.entries(SOURCES)) {
			if (ALLOWED.has(path)) continue;
			if (source.includes("'N/A'") || source.includes('"N/A"')) {
				offenders.push(path);
			}
		}
		expect(offenders).toEqual([]);
	});

	it('exports exactly one ungraded display token', async () => {
		const { UNGRADED_DISPLAY } = await import('../../src/tools/scan/format-report');
		expect(UNGRADED_DISPLAY).toBe('not measured');
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
