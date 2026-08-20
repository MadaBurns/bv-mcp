// SPDX-License-Identifier: BUSL-1.1
/**
 * Every CUSTOMER-VISIBLE grade letter comes from one chokepoint:
 * `displayGradeFor` in `src/lib/ungraded-display.ts`.
 *
 * Why an audit and not just a unit test: the parity spec
 * (`test/badge-grade-parity.spec.ts`) proves `displayGradeFor` + `gradeBadge`
 * agree with the report, but it calls them directly. Reverting the `/badge`
 * ROUTE to `gradeBadge(result.score.grade)` — the exact bug being fixed — would
 * leave that spec fully green, because nothing in it exercises the wiring. This
 * audit covers the link the unit test structurally cannot.
 *
 * The defect it locks out has occurred three times. #640: the maturity cap read the
 * internal 9-band while the report displayed the 6-band, so github.com at 67
 * printed grade D beside "Stage 4 — Hardened". And `/badge/:domain` rendered
 * `score.grade` — the 9-band letter — so the same domain showed C on its badge
 * and D in its report. And #727: `analyze_drift` reported `gradeChange` straight
 * from `ScanScore.grade`, so wiz.io at 92 was "A" in `scan_domain` and "A+" here.
 *
 * SCOPE: a TEXT scan of specific `src/` files. It deliberately does NOT ban
 * `nistScoreToGrade` corpus-wide: `src/tools/prioritize-csc-leads.ts` computes a
 * display letter from its own weighted lead score (not a scan score), which is a
 * legitimate second caller. The invariant here is narrower and precise — the
 * SCAN-score display surfaces must not re-derive a letter.
 */
import { describe, expect, it } from 'vitest';

/**
 * Vite injects `import.meta.glob`, but the test tree's `tsconfig` does not pull in
 * `vite/client`, so `ImportMeta` has no `glob` member. Narrowing through this local
 * interface keeps the file at zero type errors under the `typecheck:tests` ratchet
 * (#645) instead of adding one to the baseline.
 */
interface GlobbingImportMeta {
	glob(patterns: string[], options: { eager: true; query: '?raw'; import: 'default' }): Record<string, string>;
}

const SOURCES = (import.meta as unknown as GlobbingImportMeta).glob(
	['../../src/index.ts', '../../src/lib/ungraded-display.ts', '../../src/tools/scan/format-report.ts', '../../src/tools/analyze-drift.ts'],
	{ eager: true, query: '?raw', import: 'default' },
);

function source(suffix: string): string {
	const key = Object.keys(SOURCES).find((k) => k.endsWith(suffix));
	// Anti-vacuity: a renamed/moved file must fail loudly, not silently pass.
	expect(key, `expected a source file ending in ${suffix}`).toBeDefined();
	return SOURCES[key!];
}

describe('display-grade SSOT', () => {
	it('defines displayGradeFor exactly once, in the leaf module', () => {
		expect(source('lib/ungraded-display.ts')).toMatch(/export function displayGradeFor\(/);

		// format-report.ts used to own a private copy. It must now IMPORT the shared one —
		// two copies is how the scales drift apart again.
		const report = source('tools/scan/format-report.ts');
		expect(report).not.toMatch(/function displayGradeFor\(/);
		expect(report).toMatch(/import \{[^}]*displayGradeFor[^}]*\} from '\.\.\/\.\.\/lib\/ungraded-display'/);
	});

	it('the /badge route renders the display grade, not the internal one', () => {
		const index = source('src/index.ts');

		expect(index).toMatch(/gradeBadge\(displayGradeFor\(result\.score\)/);
		// The precise regression: handing the engine's canonical 9-band letter straight to
		// the badge. Kept as a literal so the failure message names the exact bad call.
		expect(index).not.toMatch(/gradeBadge\(result\.score\.grade/);
	});

	it('analyze_drift reports the display grade, not the engine letter it was handed', () => {
		// The third occurrence of the same defect (#727): `gradeChange` was
		// `{ from: baseline.grade, to: current.grade }` — the raw 9-band letters — so
		// wiz.io at 92 read "A" from scan_domain and "A+ -> A+" from analyze_drift in the
		// same session. Belongs in the AUDIT and not only in the spec for the same reason
		// the /badge case does: a spec that calls displayGradeFor directly stays green
		// through a route-wiring revert.
		const drift = source('tools/analyze-drift.ts');

		expect(drift).toMatch(/import \{[^}]*displayGradeFor[^}]*\} from '\.\.\/lib\/ungraded-display'/);
		expect(drift).toMatch(/from: displayGradeFor\(baseline\), to: displayGradeFor\(current\)/);
		// The precise regression, kept literal so the failure names the exact bad call.
		expect(drift).not.toMatch(/from: baseline\.grade/);
		expect(drift).not.toMatch(/to: current\.grade/);
	});

	it('only the leaf module derives a NIST letter for a scan score', () => {
		// `nistScoreToGrade` must not be called in index.ts or format-report.ts — both must
		// route through displayGradeFor, which owns the null-abstention guard too. A direct
		// call would bypass that guard and can fabricate an F for an unmeasured domain.
		expect(source('src/index.ts')).not.toMatch(/nistScoreToGrade\(/);
		expect(source('tools/scan/format-report.ts')).not.toMatch(/nistScoreToGrade\(/);
		expect(source('tools/analyze-drift.ts')).not.toMatch(/nistScoreToGrade\(/);
		expect(source('lib/ungraded-display.ts')).toMatch(/nistScoreToGrade\(score\.overall\)/);
	});
});
