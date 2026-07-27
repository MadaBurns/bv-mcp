// SPDX-License-Identifier: BUSL-1.1

/**
 * "Does this check/scan carry completed evidence" must be spelled in exactly
 * ONE place on the `src/` side: `isCompletedCheck`/`hasCompletedEvidence`/
 * `normalizeCheckStatus` in `src/lib/ungraded-display.ts`.
 *
 * Before this audit the same question was answered independently, by hand, at
 * least SEVEN times: the SSOT export itself; a local `const hasCompletedEvidence`
 * re-declared inside `map_compliance`'s `evaluateCompliance` instead of
 * importing the primitive; an inline arrow-function copy of the same per-check
 * test inside that same function's per-control partition; two more inline
 * copies inside `generate_fix_plan` and `map_csc_products` (both explicitly
 * commented as "mirrors map_compliance's completed filter" — a comment that
 * correctly diagnosed the duplication without fixing it); and, in
 * `format-report.ts`'s customer-facing `buildStructuredScanResult`, a
 * `checkStatus ?? 'completed'` value-normalization (used twice) plus a THIRD
 * inline copy (`status === 'timeout' || status === 'error'`, hidden from a
 * naive `checkStatus`-only text search by a locally renamed variable). A
 * future change to what "completed" means — e.g. a new `CheckStatus` member —
 * would then only reach the ONE spelling a maintainer remembered to update,
 * silently reintroducing this campaign's own defect class on whichever
 * surfaces were missed: a scan with incomplete evidence rendering a confident
 * verdict. This audit fails if any of those spellings reappears anywhere in
 * `src/`, INCLUDING syntactic rewrites of the same logic (array-membership,
 * switch/case, loose (`!=`/`==`) comparison, or a comment wedged between the
 * two halves of a split comparison) — see FORBIDDEN_SHAPES below.
 *
 * SCOPE: `src/` only. `packages/dns-checks/src/scoring/evidence.ts` carries
 * its own DELIBERATE twin (`computeScanEvidence`'s per-result
 * completed/attempted accounting) — that package is a published SSOT
 * vendored by another repo and is frozen for this campaign (see
 * `src/lib/ungraded-display.ts`'s file-level doc for the cross-package
 * pointer). This audit does not, and must not, reach into
 * `packages/dns-checks`; it exists solely to stop the `src/`-side surfaces
 * from drifting from EACH OTHER and from their own SSOT.
 *
 * This is a TEXT scanner, not a parser — it cannot catch every conceivable
 * rewrite (a fully abstracted local helper with a made-up name, a computed
 * property lookup, a re-implementation via a completely different algorithm
 * that happens to be extensionally equal). It targets the syntactic shapes a
 * human actually reaches for when re-deriving "is this checkStatus
 * completed" by hand, discovered by adversarial review of an earlier version
 * of this same audit (see FORBIDDEN_SHAPES doc for the specific evasions this
 * closes, and for the one judged infeasible to add without an unacceptable
 * false-positive rate).
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
function shippedSourcePaths(): string[] {
	return Object.keys(SOURCES).filter((path) => !path.endsWith('.spec.ts') && !path.endsWith('.test.ts'));
}

/**
 * Strip comments before shape-matching, so a re-spelling can't hide by
 * wedging an arbitrarily long explanatory comment between the two halves of
 * a split comparison (the M5c evasion an earlier version of this audit
 * missed — see FORBIDDEN_SHAPES doc). Matches, in priority order: a
 * string/template literal (kept VERBATIM, so a `//` or `/*` inside a URL or
 * prose string is never mistaken for a comment start) OR a block comment OR
 * a line comment (both replaced with a single space, so tokens on either
 * side of a removed comment don't get accidentally glued together). This is
 * a text heuristic, not a real lexer — nested template-literal
 * interpolations containing comment-like sequences are the known edge case
 * it does not handle, judged acceptable because none of the `checkStatus`
 * shapes this audit polices occur inside a template-literal expression
 * anywhere in the current corpus (verified by the non-vacuity test below
 * still finding real files, and the corpus-wide "no offenders" test staying
 * green).
 */
function stripComments(source: string): string {
	return source.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, (match) =>
		match.startsWith('/*') || match.startsWith('//') ? ' ' : match,
	);
}

/** `path -> comment-stripped source`, computed once. Shape-matching ALWAYS runs against this, never raw SOURCES. */
const STRIPPED: Record<string, string> = Object.fromEntries(shippedSourcePaths().map((path) => [path, stripComments(SOURCES[path])]));

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
 * Every shape (both comparison orders, where applicable) known to re-derive
 * the completed/not-completed question outside the SSOT. Matched against
 * COMMENT-STRIPPED source (see `stripComments`) with a modest gap that only
 * needs to bridge whitespace/arrow-function syntax now that comments can no
 * longer pad it out:
 *
 *   - DENYLIST-AND: `!== 'timeout' && ... !== 'error'` (found in the local
 *     shadow, the inline copy inside `map_compliance`, and the fix-plan
 *     `actionableFindings` filter).
 *   - ALLOWLIST-OR (manually spelled): `=== undefined || ... === 'completed'`
 *     — a hand-written restatement of `isCompletedCheck`'s own body.
 *   - NOT-COMPLETED-OR: `=== 'error' || ... === 'timeout'` (the complement
 *     form used by the fix-plan `transientCategories` filter,
 *     `map_csc_products`' single-result gate, and — before this collapse —
 *     `format-report.ts`'s `inconclusiveCategories` partition).
 *   - ARRAY-MEMBERSHIP (M5a): `['timeout','error'].includes(checkStatus)`,
 *     either literal order, optionally parenthesised/`as const`-cast and
 *     negated — the same NOT-COMPLETED question spelled via `Array#includes`
 *     instead of `||`.
 *   - SWITCH/CASE (M5b): a `switch (…checkStatus…)` whose `case 'timeout':`
 *     and `case 'error':` fall through together (either order) — the same
 *     grouping of the two transient members into one bucket, spelled as
 *     control flow instead of a boolean expression.
 *
 * Comparison operators are `!==?`/`===?` (an optional second `=`) rather
 * than a hard-coded `!==`/`===`, so a re-spelling that loosens to `!=`/`==`
 * (M5d — behaviourally identical for these string-literal comparisons, so a
 * developer "simplifying" the operator would still slip the exact same
 * defect past a strict-only regex) is caught too.
 *
 * NOT attempted: a fully abstracted local re-implementation under a novel
 * name with no textual relationship to `checkStatus`/`timeout`/`error`/
 * `completed` at all (e.g. a bitmask, a lookup table keyed on something
 * else, or a helper imported from a brand-new, unreviewed module). No text
 * scanner can catch an arbitrary rename with an arbitrary algorithm without
 * either becoming a full type-aware linter or producing unworkable false
 * positives on unrelated code — that class of evasion needs code review to
 * catch, not an audit. This is a judgement call, not a silent gap: it is why
 * this audit is a SUPPLEMENT to review, not a replacement for it.
 */
const FORBIDDEN_SHAPES: RegExp[] = [
	/checkStatus\s*!==?\s*'timeout'[\s\S]{0,100}?checkStatus\s*!==?\s*'error'/,
	/checkStatus\s*!==?\s*'error'[\s\S]{0,100}?checkStatus\s*!==?\s*'timeout'/,
	/checkStatus\s*===?\s*undefined[\s\S]{0,100}?checkStatus\s*===?\s*'completed'/,
	/checkStatus\s*===?\s*'completed'[\s\S]{0,100}?checkStatus\s*===?\s*undefined/,
	/checkStatus\s*===?\s*'error'[\s\S]{0,100}?checkStatus\s*===?\s*'timeout'/,
	/checkStatus\s*===?\s*'timeout'[\s\S]{0,100}?checkStatus\s*===?\s*'error'/,
	// M5a — array-membership form, either literal order.
	/\[\s*'timeout'\s*,\s*'error'\s*\][\s\S]{0,60}?\.includes\([^)]*checkStatus[^)]*\)/,
	/\[\s*'error'\s*,\s*'timeout'\s*\][\s\S]{0,60}?\.includes\([^)]*checkStatus[^)]*\)/,
	// M5b — switch/case fall-through form, either case order.
	/switch\s*\([^)]*checkStatus[^)]*\)[\s\S]{0,200}?case\s*'timeout'\s*:[\s\S]{0,80}?case\s*'error'\s*:/,
	/switch\s*\([^)]*checkStatus[^)]*\)[\s\S]{0,200}?case\s*'error'\s*:[\s\S]{0,80}?case\s*'timeout'\s*:/,
];

/** A local re-declaration of the SSOT's own exported names, anywhere outside the SSOT file. */
const REDECLARATION_SHAPES: RegExp[] = [
	/\b(?:export\s+)?(?:const|let|var|function)\s+hasCompletedEvidence\b/,
	/\b(?:export\s+)?(?:const|let|var|function)\s+isCompletedCheck\b/,
	/\b(?:export\s+)?(?:const|let|var|function)\s+normalizeCheckStatus\b/,
];

/** Total forbidden-shape matches (all shapes, each counted with a global flag) in one file's stripped source. */
function countForbiddenShapeMatches(source: string): number {
	let total = 0;
	for (const shape of FORBIDDEN_SHAPES) {
		const global = new RegExp(shape.source, 'g');
		total += source.match(global)?.length ?? 0;
	}
	return total;
}

describe('completed-evidence predicate SSOT (src/ only)', () => {
	it('scanned a non-trivial src/ corpus, including the SSOT file and known consumers', () => {
		// Anti-vacuous guard: an empty/near-empty glob would make every assertion
		// below pass trivially and protect nothing — this campaign caught exactly
		// that failure mode (a vacuous-green sweep) in an earlier slice.
		const paths = shippedSourcePaths();
		expect(paths.length).toBeGreaterThan(200);
		expect(paths).toContain(SSOT_PATH);
		expect(paths).toContain('../../src/tools/map-compliance.ts');
		expect(paths).toContain('../../src/tools/generate-fix-plan.ts');
		expect(paths).toContain('../../src/tools/map-csc-products.ts');
		expect(paths).toContain('../../src/tools/scan/format-report.ts');
		// The comment-stripping preprocessor must actually remove something on a
		// real file, not silently no-op (which would make the M5c defense vacuous).
		expect(STRIPPED[SSOT_PATH].length).toBeLessThan(SOURCES[SSOT_PATH].length);
	});

	it('declares hasCompletedEvidence / isCompletedCheck / normalizeCheckStatus exactly once each, all in the SSOT file', () => {
		for (const name of ['hasCompletedEvidence', 'isCompletedCheck', 'normalizeCheckStatus']) {
			const declPattern = new RegExp(`\\bexport function ${name}\\b`, 'g');
			const declaredIn: string[] = [];
			for (const path of shippedSourcePaths()) {
				const matches = STRIPPED[path].match(declPattern);
				if (matches) {
					for (const _m of matches) declaredIn.push(path);
				}
			}
			expect(declaredIn, `${name} must be declared exactly once, in ${SSOT_PATH}`).toEqual([SSOT_PATH]);
		}
	});

	it('hasCompletedEvidence delegates to isCompletedCheck rather than re-deriving it inline', () => {
		const source = STRIPPED[SSOT_PATH];
		expect(source).toBeDefined();
		expect(source).toMatch(/checks\.some\(isCompletedCheck\)/);
	});

	it('has no OTHER src/ module re-deriving the completed/not-completed check inline (copy-paste OR rewritten)', () => {
		const offenders: Array<{ path: string; shape: string }> = [];
		for (const path of shippedSourcePaths()) {
			if (path === SSOT_PATH) continue;
			if (KNOWN_DIFFERENT_PURPOSE.has(path)) continue;
			const source = STRIPPED[path];
			for (const shape of FORBIDDEN_SHAPES) {
				if (shape.test(source)) offenders.push({ path, shape: shape.source });
			}
		}
		expect(offenders, 'import isCompletedCheck/hasCompletedEvidence/normalizeCheckStatus from src/lib/ungraded-display.ts instead').toEqual(
			[],
		);
	});

	it('has no OTHER src/ module re-declaring hasCompletedEvidence/isCompletedCheck/normalizeCheckStatus as a local binding', () => {
		const offenders: Array<{ path: string; shape: string }> = [];
		for (const path of shippedSourcePaths()) {
			if (path === SSOT_PATH) continue;
			const source = STRIPPED[path];
			for (const shape of REDECLARATION_SHAPES) {
				if (shape.test(source)) offenders.push({ path, shape: shape.source });
			}
		}
		expect(offenders).toEqual([]);
	});

	it('the KNOWN_DIFFERENT_PURPOSE exclusions carry EXACTLY ONE reviewed occurrence each, not a superset', () => {
		// F3: `toMatch`/presence-only would let a SECOND, unreviewed re-spelling
		// hide in an excluded file forever (both excluded files are among the
		// largest, most-churned in src/tools/). Count every forbidden-shape match
		// in each excluded file's stripped source and require exactly 1 — the one
		// shape reviewed and named in KNOWN_DIFFERENT_PURPOSE's doc above. Zero
		// would mean the exclusion no longer protects anything real (dead
		// exclusion); two or more means an unreviewed second instance was added.
		for (const path of KNOWN_DIFFERENT_PURPOSE) {
			expect(Object.keys(SOURCES), `${path} must exist for this exclusion to mean anything`).toContain(path);
			const count = countForbiddenShapeMatches(STRIPPED[path]);
			expect(count, `${path} must contain exactly the one reviewed forbidden-shape occurrence, found ${count}`).toBe(1);
		}
	});
});
