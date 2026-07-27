// SPDX-License-Identifier: BUSL-1.1

/**
 * "Does this check/scan carry completed evidence" must be spelled in exactly
 * ONE place on the `src/` side: `isCompletedCheck`/`hasCompletedEvidence` in
 * `src/lib/ungraded-display.ts`.
 *
 * Before this audit the same question was answered FOUR different ways: the
 * SSOT export itself; a local `const hasCompletedEvidence` re-declared inside
 * `map_compliance`'s `evaluateCompliance` instead of importing the primitive;
 * an inline arrow-function copy of the same per-check test inside that same
 * function's per-control partition; and (found while collapsing the above,
 * so folded into this same guard) two more inline copies inside
 * `generate_fix_plan` and `map_csc_products`. A future change to what
 * "completed" means — e.g. a new `CheckStatus` member — would then only
 * reach the ONE spelling a maintainer remembered to update, silently
 * reintroducing this campaign's own defect class on whichever surfaces were
 * missed: a scan with incomplete evidence rendering a confident verdict.
 * This audit fails if any of those spellings reappears anywhere in `src/`.
 *
 * SCOPE: `src/` only. `packages/dns-checks/src/scoring/evidence.ts` carries
 * its own DELIBERATE twin (`computeScanEvidence`'s per-result
 * completed/attempted accounting) — that package is a published SSOT
 * vendored by another repo and is frozen for this campaign (see
 * `src/lib/ungraded-display.ts`'s file-level doc for the cross-package
 * pointer). This audit does not, and must not, reach into
 * `packages/dns-checks`; it exists solely to stop the `src/`-side surfaces
 * from drifting from EACH OTHER and from their own SSOT.
 */

import { describe, it, expect } from 'vitest';

// Vitest's Workers pool has no `fs`; the source corpus is inlined at build
// time by import.meta.glob (eager, raw) so this audit runs inside workerd.
// `src/` ONLY — packages/dns-checks is out of scope by design, see file doc.
const SOURCES = import.meta.glob(['../../src/**/*.ts'], {
	eager: true,
	query: '?raw',
	import: 'default',
}) as Record<string, string>;

/** Shipped source only — never this audit's own siblings. */
function shippedSources(): Array<[string, string]> {
	return Object.entries(SOURCES).filter(([path]) => !path.endsWith('.spec.ts') && !path.endsWith('.test.ts'));
}

const SSOT_PATH = '../../src/lib/ungraded-display.ts';

/**
 * Files that legitimately branch on the CONCRETE `'error' | 'timeout'` value
 * rather than asking the completed/not-completed BOOLEAN question, so the
 * three-way-OR shape below is expected and already reviewed there — it is
 * not a re-spelling of the SSOT predicate:
 *
 * - `scan-domain.ts` records the concrete status into a
 *   `Map<CheckCategory, 'error' | 'timeout'>` for re-application after
 *   post-processing strips `checkStatus`. It needs the VALUE, not a
 *   boolean — routing it through `isCompletedCheck` would just move the
 *   same type-narrowing problem to an unsafe cast at the call site, with
 *   no SSOT benefit.
 * - `check-http-security.ts` gates a CDN-annotation enrichment on a
 *   THREE-way OR (`checkStatus` transient OR a `missingControl` finding) —
 *   a narrower, single-check, single-purpose gate, not the "does this scan
 *   have usable evidence" question the SSOT answers.
 */
const KNOWN_DIFFERENT_PURPOSE = new Set(['../../src/tools/scan-domain.ts', '../../src/tools/check-http-security.ts']);

/**
 * Every shape (both comparison orders) this collapse found duplicated:
 *   - DENYLIST-AND: `!== 'timeout' && ... !== 'error'` — the local shadow
 *     and the inline copy inside `map_compliance`, and the fix-plan
 *     `actionableFindings` filter.
 *   - ALLOWLIST-OR (manually spelled): `=== undefined || ... === 'completed'`
 *     — a hand-written restatement of `isCompletedCheck`'s own body.
 *   - NOT-COMPLETED-OR: `=== 'error' || ... === 'timeout'` — the complement
 *     form used by the fix-plan `transientCategories` filter and
 *     `map_csc_products`' single-result gate.
 * A `[\s\S]{0,80}` gap tolerates the arrow-function/whitespace between the
 * two comparisons without reaching across unrelated code far apart in the
 * same file.
 */
const FORBIDDEN_SHAPES: RegExp[] = [
	/checkStatus\s*!==\s*'timeout'[\s\S]{0,80}?checkStatus\s*!==\s*'error'/,
	/checkStatus\s*!==\s*'error'[\s\S]{0,80}?checkStatus\s*!==\s*'timeout'/,
	/checkStatus\s*===\s*undefined[\s\S]{0,80}?checkStatus\s*===\s*'completed'/,
	/checkStatus\s*===\s*'completed'[\s\S]{0,80}?checkStatus\s*===\s*undefined/,
	/checkStatus\s*===\s*'error'[\s\S]{0,80}?checkStatus\s*===\s*'timeout'/,
	/checkStatus\s*===\s*'timeout'[\s\S]{0,80}?checkStatus\s*===\s*'error'/,
];

/** A local re-declaration of the SSOT's own exported names, anywhere outside the SSOT file. */
const REDECLARATION_SHAPES: RegExp[] = [
	/\b(?:export\s+)?(?:const|let|var|function)\s+hasCompletedEvidence\b/,
	/\b(?:export\s+)?(?:const|let|var|function)\s+isCompletedCheck\b/,
];

describe('completed-evidence predicate SSOT (src/ only)', () => {
	it('scanned a non-trivial src/ corpus, including the SSOT file and a known consumer', () => {
		// Anti-vacuous guard: an empty/near-empty glob would make every assertion
		// below pass trivially and protect nothing — this campaign caught exactly
		// that failure mode (a vacuous-green sweep) in an earlier slice.
		const files = shippedSources();
		expect(files.length).toBeGreaterThan(200);
		expect(Object.keys(SOURCES)).toContain(SSOT_PATH);
		expect(Object.keys(SOURCES)).toContain('../../src/tools/map-compliance.ts');
		expect(Object.keys(SOURCES)).toContain('../../src/tools/generate-fix-plan.ts');
		expect(Object.keys(SOURCES)).toContain('../../src/tools/map-csc-products.ts');
	});

	it('declares hasCompletedEvidence / isCompletedCheck exactly once each, both in the SSOT file', () => {
		for (const name of ['hasCompletedEvidence', 'isCompletedCheck']) {
			const declPattern = new RegExp(`\\bexport function ${name}\\b`, 'g');
			const declaredIn: string[] = [];
			for (const [path, source] of shippedSources()) {
				const matches = source.match(declPattern);
				if (matches) {
					for (const _m of matches) declaredIn.push(path);
				}
			}
			expect(declaredIn, `${name} must be declared exactly once, in ${SSOT_PATH}`).toEqual([SSOT_PATH]);
		}
	});

	it('hasCompletedEvidence delegates to isCompletedCheck rather than re-deriving it inline', () => {
		const source = SOURCES[SSOT_PATH];
		expect(source).toBeDefined();
		expect(source).toMatch(/checks\.some\(isCompletedCheck\)/);
	});

	it('has no OTHER src/ module re-deriving the completed/not-completed check inline', () => {
		const offenders: Array<{ path: string; shape: string }> = [];
		for (const [path, source] of shippedSources()) {
			if (path === SSOT_PATH) continue;
			if (KNOWN_DIFFERENT_PURPOSE.has(path)) continue;
			for (const shape of FORBIDDEN_SHAPES) {
				if (shape.test(source)) offenders.push({ path, shape: shape.source });
			}
		}
		expect(offenders, 'import isCompletedCheck/hasCompletedEvidence from src/lib/ungraded-display.ts instead').toEqual([]);
	});

	it('has no OTHER src/ module re-declaring hasCompletedEvidence/isCompletedCheck as a local binding', () => {
		const offenders: Array<{ path: string; shape: string }> = [];
		for (const [path, source] of shippedSources()) {
			if (path === SSOT_PATH) continue;
			for (const shape of REDECLARATION_SHAPES) {
				if (shape.test(source)) offenders.push({ path, shape: shape.source });
			}
		}
		expect(offenders).toEqual([]);
	});

	it('the KNOWN_DIFFERENT_PURPOSE exclusions still exist and still only contain the reviewed shape', () => {
		// If either file were renamed/removed this exclusion set would silently
		// stop meaning anything; if either one grows a SECOND, unreviewed
		// instance of the forbidden shape elsewhere in the same file, the
		// non-emptiness check for offenders in the previous test only skips a
		// whole PATH — so this test independently pins that the ONE reviewed
		// occurrence is still exactly what was reviewed, not a superset.
		for (const path of KNOWN_DIFFERENT_PURPOSE) {
			expect(Object.keys(SOURCES), `${path} must exist for this exclusion to mean anything`).toContain(path);
		}
		expect(SOURCES['../../src/tools/scan-domain.ts']).toMatch(/r\.checkStatus === 'error' \|\| r\.checkStatus === 'timeout'/);
		expect(SOURCES['../../src/tools/check-http-security.ts']).toMatch(
			/result\.checkStatus === 'error' \|\| result\.checkStatus === 'timeout'/,
		);
	});
});
