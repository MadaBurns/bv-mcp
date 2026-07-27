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
 *
 * ROUND 2: an independent review found the shapes above were still anchored
 * to the literal token `checkStatus`, so two more evasions slipped past: (E1)
 * `new Set(['timeout','error']).has(checkStatus)` / a hoisted
 * `const X = ['timeout','error']; ... X.includes(checkStatus)` — the same
 * NOT-COMPLETED question spelled via Set/collection membership instead of
 * `.includes`/`||`; and (E2) a locally renamed identifier, e.g.
 * `const { checkStatus: cs } = check; cs !== 'timeout' && cs !== 'error'`,
 * which no `checkStatus`-anchored regex can see. E1 is closed the same way
 * as M5a/M5b (new shapes below). E2 is closed by PROVENANCE tracking, not
 * blind identifier-agnostic matching: `findCheckStatusAliases()` traces a
 * local name back to `checkStatus` via a destructuring rename
 * (`const { checkStatus: X } = ...`) or a direct initializer
 * (`const X = obj.checkStatus;`), and only THOSE traced names — never an
 * arbitrary identifier — are folded into the shape regexes alongside the
 * literal `checkStatus` token. A blind "any identifier compared against both
 * literals" version was tried first and rejected: it flagged genuine
 * unrelated code (e.g. `src/lib/brand-audit-depth.ts` and
 * `src/tools/discover-brand-domains.ts`, both branching on an unrelated
 * `status` variable that was never derived from `checkStatus`) — see
 * `findCheckStatusAliases`'s doc for the exact boundary this leaves.
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
 * Traces a local identifier back to `checkStatus` via one of the two shapes
 * a developer actually reaches for when renaming/aliasing it (round 2, E2):
 *
 *   - a destructuring rename: `const { checkStatus: cs } = check;` — matched
 *     ONLY when the `{ ... } =` braces open directly after `const`/`let`/`var`
 *     (i.e. it's really the LHS of a destructuring assignment), not when
 *     `checkStatus: someVar` appears as a plain object-literal property on
 *     the RHS of an assignment (e.g. `return { ...base, checkStatus: status }`
 *     in `scan-domain.ts` — the OPPOSITE direction, writing INTO a
 *     `checkStatus` field, not reading a local alias OUT of one; conflating
 *     the two was tried and produced a false alias there).
 *   - a direct initializer: `const cs = checkStatus;` or
 *     `const cs = result.checkStatus;` — matched only when the initializer is
 *     JUST that reference (immediately followed by `;`/`,`/`)`/newline), not
 *     an arbitrary expression that merely mentions `checkStatus` (e.g.
 *     `const isUnanalyzable = result.checkStatus === 'error' || ...` in
 *     `check-http-security.ts` is deliberately NOT treated as an alias of
 *     `checkStatus` — `isUnanalyzable` is a derived boolean, not the status
 *     value itself, so tracing it would be both wrong and, worse, a source
 *     of false positives on unrelated later comparisons of that name).
 *
 * This is PROVENANCE tracking, not blind identifier-agnostic matching — the
 * distinction matters. An earlier version of this function returned any
 * identifier ever compared against BOTH `'timeout'` and `'error'`, with no
 * requirement that it be traceable to `checkStatus` at all; run against the
 * full `src/` corpus that flagged two genuine false positives —
 * `src/lib/brand-audit-depth.ts` and `src/tools/discover-brand-domains.ts`,
 * both branching on an unrelated `status` value with its own `'timeout'`/
 * `'error'`/`'failed'` members that were never derived from `checkStatus`.
 * Anchoring to provable provenance instead of the name closes the E2 evasion
 * (`cs` is caught because it demonstrably came FROM `checkStatus`) without
 * that false-positive rate — verified empirically: zero offenders across the
 * corpus below with this version, vs. two with the blind version.
 *
 * Known remaining gap (undetectable by a text scanner, same class as the
 * "NOT attempted" note further down): an alias assigned outside its
 * declaration (`let cs; cs = checkStatus;`) or threaded through an
 * intermediate function call (`const cs = pick(checkStatus);`) is NOT traced
 * — review-time concern, not this audit's job.
 */
function findCheckStatusAliases(source: string): string[] {
	const aliases = new Set<string>();
	for (const m of source.matchAll(/\b(?:const|let|var)\s*\{[^{}]{0,200}?checkStatus\s*:\s*(\w+)[^{}]{0,200}?\}\s*=/g)) {
		if (m[1] !== 'checkStatus') aliases.add(m[1]);
	}
	for (const m of source.matchAll(/\b(?:const|let)\s+(\w+)\s*=\s*(?:\w+\.)?checkStatus\s*[;,)\n]/g)) {
		if (m[1] !== 'checkStatus') aliases.add(m[1]);
	}
	return [...aliases];
}

/** `checkStatus`, or an alternation of it plus every traced alias in this file — see `findCheckStatusAliases`. */
function identifierPattern(aliases: string[]): string {
	return `\\b(?:${['checkStatus', ...aliases].join('|')})\\b`;
}

/**
 * Every shape (both comparison orders, where applicable) known to re-derive
 * the completed/not-completed question outside the SSOT, parameterized on
 * `idPat` — `identifierPattern(findCheckStatusAliases(source))` for the file
 * under test, so each shape matches `checkStatus` OR any alias PROVABLY
 * traced back to it in that same file (round 2, E2 — see
 * `findCheckStatusAliases` doc). Matched against COMMENT-STRIPPED source
 * (see `stripComments`) with a modest gap that only needs to bridge
 * whitespace/arrow-function syntax now that comments can no longer pad it
 * out:
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
 *   - SET-MEMBERSHIP (round 2, E1): `new Set(['timeout','error']).has(checkStatus)`,
 *     either literal order — the same NOT-COMPLETED question spelled via
 *     `Set#has` instead of `Array#includes`/`||`.
 *   - HOISTED-COLLECTION (round 2, E1): the denylist array/Set held in a
 *     NAMED const declared earlier (`const TRANSIENT = ['timeout','error'] as
 *     const;` … `TRANSIENT.includes(checkStatus)`), rather than inlined right
 *     before `.includes`/`.has` — a backreference (`\1`) ties the later call
 *     back to the SAME hoisted name, either literal order.
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
 * else, or a helper imported from a brand-new, unreviewed module), NOR an
 * alias whose provenance can't be traced back to `checkStatus` by
 * `findCheckStatusAliases` (see that function's "known remaining gap" note).
 * No text scanner can catch an arbitrary rename with an arbitrary algorithm
 * without either becoming a full type-aware linter or producing unworkable
 * false positives on unrelated code — that class of evasion needs code
 * review to catch, not an audit. This is a judgement call, not a silent gap:
 * it is why this audit is a SUPPLEMENT to review, not a replacement for it.
 */
function buildForbiddenShapes(idPat: string): RegExp[] {
	return [
		new RegExp(`${idPat}\\s*!==?\\s*'timeout'[\\s\\S]{0,100}?${idPat}\\s*!==?\\s*'error'`),
		new RegExp(`${idPat}\\s*!==?\\s*'error'[\\s\\S]{0,100}?${idPat}\\s*!==?\\s*'timeout'`),
		new RegExp(`${idPat}\\s*===?\\s*undefined[\\s\\S]{0,100}?${idPat}\\s*===?\\s*'completed'`),
		new RegExp(`${idPat}\\s*===?\\s*'completed'[\\s\\S]{0,100}?${idPat}\\s*===?\\s*undefined`),
		new RegExp(`${idPat}\\s*===?\\s*'error'[\\s\\S]{0,100}?${idPat}\\s*===?\\s*'timeout'`),
		new RegExp(`${idPat}\\s*===?\\s*'timeout'[\\s\\S]{0,100}?${idPat}\\s*===?\\s*'error'`),
		// M5a — array-membership form, either literal order.
		new RegExp(`\\[\\s*'timeout'\\s*,\\s*'error'\\s*\\][\\s\\S]{0,60}?\\.includes\\([^)]*${idPat}[^)]*\\)`),
		new RegExp(`\\[\\s*'error'\\s*,\\s*'timeout'\\s*\\][\\s\\S]{0,60}?\\.includes\\([^)]*${idPat}[^)]*\\)`),
		// M5b — switch/case fall-through form, either case order.
		new RegExp(`switch\\s*\\([^)]*${idPat}[^)]*\\)[\\s\\S]{0,200}?case\\s*'timeout'\\s*:[\\s\\S]{0,80}?case\\s*'error'\\s*:`),
		new RegExp(`switch\\s*\\([^)]*${idPat}[^)]*\\)[\\s\\S]{0,200}?case\\s*'error'\\s*:[\\s\\S]{0,80}?case\\s*'timeout'\\s*:`),
		// Round 2, E1 — Set-membership form, either literal order.
		new RegExp(`new\\s+Set\\(\\s*\\[\\s*'timeout'\\s*,\\s*'error'\\s*\\]\\s*\\)[\\s\\S]{0,60}?\\.has\\([^)]*${idPat}[^)]*\\)`),
		new RegExp(`new\\s+Set\\(\\s*\\[\\s*'error'\\s*,\\s*'timeout'\\s*\\]\\s*\\)[\\s\\S]{0,60}?\\.has\\([^)]*${idPat}[^)]*\\)`),
		// Round 2, E1 — hoisted array/Set held in a named const, either literal order.
		new RegExp(
			`\\bconst\\s+(\\w+)\\s*(?::\\s*[^=]+)?=\\s*(?:new\\s+Set\\()?\\[\\s*'timeout'\\s*,\\s*'error'\\s*\\](?:\\s*as\\s*const)?\\)?[\\s\\S]{0,400}?\\1\\.(?:includes|has)\\([^)]*${idPat}[^)]*\\)`,
		),
		new RegExp(
			`\\bconst\\s+(\\w+)\\s*(?::\\s*[^=]+)?=\\s*(?:new\\s+Set\\()?\\[\\s*'error'\\s*,\\s*'timeout'\\s*\\](?:\\s*as\\s*const)?\\)?[\\s\\S]{0,400}?\\1\\.(?:includes|has)\\([^)]*${idPat}[^)]*\\)`,
		),
	];
}

/** A local re-declaration of the SSOT's own exported names, anywhere outside the SSOT file. */
const REDECLARATION_SHAPES: RegExp[] = [
	/\b(?:export\s+)?(?:const|let|var|function)\s+hasCompletedEvidence\b/,
	/\b(?:export\s+)?(?:const|let|var|function)\s+isCompletedCheck\b/,
	/\b(?:export\s+)?(?:const|let|var|function)\s+normalizeCheckStatus\b/,
];

/** Total forbidden-shape matches (all shapes for THIS file's traced identifier set, each counted with a global flag) in one file's stripped source. */
function countForbiddenShapeMatches(source: string): number {
	let total = 0;
	for (const shape of buildForbiddenShapes(identifierPattern(findCheckStatusAliases(source)))) {
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

	it('has no OTHER src/ module re-deriving the completed/not-completed check inline (copy-paste OR rewritten, incl. renamed/aliased identifiers)', () => {
		const offenders: Array<{ path: string; shape: string }> = [];
		for (const path of shippedSourcePaths()) {
			if (path === SSOT_PATH) continue;
			if (KNOWN_DIFFERENT_PURPOSE.has(path)) continue;
			const source = STRIPPED[path];
			// Per-file: checkStatus plus any alias PROVABLY traced back to it in
			// THIS file — see findCheckStatusAliases doc for why this is not a
			// blind "any identifier" match.
			for (const shape of buildForbiddenShapes(identifierPattern(findCheckStatusAliases(source)))) {
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
