// SPDX-License-Identifier: BUSL-1.1

/// <reference types="vite/client" />

/**
 * Structural audit — the root worker tree's half of the missing-control hazard.
 *
 * ## The gap this file closes (SQ-100)
 *
 * `packages/dns-checks/src/__tests__/scoring/missing-control-intent.audit.test.ts` enumerates
 * every `createFinding` call site via `import.meta.glob`, scoped (by its own docstring) to
 * `packages/dns-checks/src/`. That scoping is real and correct for what it covers — but it means
 * the audit has never looked at the ROOT worker tree at all. Measured at the time this file was
 * written: 296 real `createFinding(` call sites live under this repo's root `src/` (57 files) —
 * two-thirds of the repo's total surface for this hazard, and until now none of it was checked.
 *
 * The hazard itself, the real exported predicates, the parsing engine, and the doctrine are all
 * identical to the sibling file above — read it for the full account (the `github.com` /
 * `missingkids.org` production incident this class of bug caused, the six assertions, why an
 * enumerative test beats a fixture corpus). This file is a second instance of that same audit
 * pointed at a different `import.meta.glob` root, not a different design. Sections below that
 * exist only because THIS tree's findings differ from the package tree's are called out; sections
 * that just repeat the sibling file's engine verbatim are kept terse.
 *
 * Discovery is via `import.meta.glob(..., '?raw')` for the same reason as the sibling file: it is
 * vite-resolved and scoped to `../../src/` relative to this file, so it can never descend into a
 * nested `.worktrees/` or `.claude/worktrees/` checkout (50+ of them exist on this machine
 * alongside this repo) the way a `readdirSync` recursion rooted anywhere above `src/` would. The
 * same glob shape is already used this way elsewhere in this directory (`safe-fetch-required` and
 * `completed-evidence-predicate-ssot`), so this is the established convention, not a new one.
 *
 * ## What was found (the item-3 census)
 *
 * Of 296 discovered sites, 238 are statically classifiable (literal title + detail + severity).
 * Exactly 7 zero their category on static text alone — every one of them read in source and
 * listed below as a genuine, designed absence-of-control finding (glue missing, no NS, no SOA, no
 * DANE TLSA ×2, "no SPF or DMARC" on a shadow domain, no nameservers at all). None is a violation:
 * this tree's `INTENDED_MISSING_CONTROLS` register accounts for all 7. Of the sites emitting at
 * qualifying severity with a target-controlled interpolation hole, ZERO are armed by a
 * target-controlled value that merely *contains* a trigger word (the live-defect class the
 * sibling file's assertion C exists to catch) — this tree does not currently have the
 * `missingkids.org`-shaped bug.
 *
 * ## The exact-match population is closed, and gated (SQ-102)
 *
 * SQ-100 also measured 17 sites (19 when SQ-102 re-measured) that a value supplying a trigger word
 * *exactly* could arm — a single-label NS target literally called `missing`, an npm package named
 * `required` — and left them as a non-failing warning, on the sibling file's stated grounds that
 * closing them needs a `scoring/model.ts` change. That premise predates SQ-97: a hole declared via
 * `[SUBJECT_TERMS_METADATA_KEY]` is substring-redacted before MISSING_CONTROL_REGEX runs, which
 * defeats an exact-match value as completely as a containing one, with no model change (the
 * sibling's own planted DISCRIMINATES control proves it). SQ-102 closed the population with
 * metadata only: 17 sites declare their string holes, `check-nsec-walkability.ts` declares
 * `missingControl: false` because redaction is unsafe in its prose (section C), and the remaining
 * holes are numbers in the reviewed per-file `INERT_HOLES` register. Section C's exact-match test
 * is now a hard assertion. No scoring rule changed: a declaration redacts only the declared
 * runtime value, so a verdict can move only where that value itself supplied the trigger text.
 */

import { describe, expect, it } from 'vitest';
import {
	findingsIndicateMissingControl,
	scoreIndicatesMissingControl,
	type CheckCategory,
	type Finding,
	type Severity,
} from '@blackveil/dns-checks/scoring';

// ---------------------------------------------------------------------------
// 1. THE INTENT REGISTER — every root-tree site read in source before being listed here.
// ---------------------------------------------------------------------------

interface IntendedZeroer {
	/** Path relative to this repo's root `src/`. */
	readonly file: string;
	readonly title: string;
	readonly category: CheckCategory;
	readonly mechanism: 'declared' | 'prose';
	readonly reason: string;
}

const INTENDED_MISSING_CONTROLS: readonly IntendedZeroer[] = [
	{
		file: 'lib/authoritative-dns-infra/delegation-analysis.ts',
		title: 'In-bailiwick nameserver glue is missing',
		category: 'ns',
		mechanism: 'declared',
		reason:
			'An in-bailiwick nameserver (one whose own name lives inside the zone it serves) with no A/AAAA glue at ' +
			'the parent creates a circular resolution dependency: resolvers cannot look up the nameserver without ' +
			'already knowing its address. That is a genuinely broken delegation, not a graded deficiency, so zeroing ' +
			'`ns` is correct. SQ-74: carries an explicit `{ missingControl: true }` — a reword can no longer ' +
			'silently un-zero this.',
	},
	{
		file: 'tools/check-shadow-domains.ts',
		title: 'Shadow domain fully spoofable',
		category: 'shadow_domains',
		mechanism: 'declared',
		reason:
			'Emitted only on the top rung of the ladder: the seed domain has MX records but neither SPF nor DMARC. ' +
			'A domain that publishes mail infrastructure with zero sender-authentication controls is the same ' +
			'"genuinely absent control" shape as `check-mx.ts`\'s "No MX and no SPF" entry in the sibling file\'s ' +
			'register. SQ-74: carries an explicit `{ missingControl: true }` (spread onto the shared `meta` object ' +
			'for only this rung), independent of the interpolated `${variant}` domain-name hole (see the ' +
			'interpolation section below).',
	},
	{
		file: 'tools/check-zone-hygiene.ts',
		title: 'No NS records found',
		category: 'zone_hygiene',
		mechanism: 'declared',
		reason:
			'Zero NS records means zone-consistency analysis cannot run at all — there is nothing to check hygiene ' +
			'of. Declares `{ missingControl: true }`, so severity (`medium`) is irrelevant to whether this zeroes; ' +
			'the structural leg has no severity gate.',
	},
	{
		file: 'tools/check-zone-hygiene.ts',
		title: 'No SOA record found',
		category: 'zone_hygiene',
		mechanism: 'declared',
		reason:
			'Every zone must have exactly one SOA record (RFC 1035 §3.3.13); its absence is a genuine zone defect, ' +
			'not a style deficiency. Declares `{ missingControl: true }`.',
	},
	{
		file: 'tools/dane-analysis.ts',
		title: 'No DANE TLSA for MX servers',
		category: 'dane',
		mechanism: 'declared',
		reason:
			'DANE is opt-in infrastructure (most domains legitimately never deploy it), but when this classifier ' +
			'reports the absence it is a measured "we looked and found nothing" result, so the declared ' +
			'`missingControl: true` (at `medium`, irrelevant to the structural leg) correctly represents absence ' +
			'rather than a graded score in between.',
	},
	{
		file: 'tools/dane-analysis.ts',
		title: 'No DANE TLSA for HTTPS',
		category: 'dane',
		mechanism: 'declared',
		reason: 'Same absence-of-control shape as the MX-TLSA sibling above, for the HTTPS (port 443) endpoint instead. Declares `{ missingControl: true }`.',
	},
	{
		file: 'tools/ns-analysis.ts',
		title: 'No NS records found',
		category: 'ns',
		mechanism: 'declared',
		reason:
			'Root-tree counterpart to the sibling file\'s `checks/ns-analysis.ts` "No NS records found" entry — a ' +
			'distinct file in this tree, same genuinely-absent-control shape: zero NS records means the domain ' +
			'cannot resolve at all. Emitted at `critical` on the `!domainResolves` branch. SQ-74: carries an ' +
			'explicit `{ missingControl: true }` — a reword can no longer silently un-zero this.',
	},
];

/** Deliberately empty, same as the sibling file — no interpolation has been reviewed and accepted here. */
const INTERPOLATION_REVIEWED: readonly { file: string; title: string; reason: string }[] = [];

/**
 * Holes reviewed as STRUCTURALLY unable to carry a trigger word: every entry renders a `number`
 * (type cited in `reason`), so its text is digits, `Infinity` or `NaN`, never prose. Unlike the
 * sibling file's global expression set, each entry is pinned to its FILE: `algorithm` is a number
 * in `check-dnskey-strength.ts` but would be free text in, say, a DKIM `a=` parser, and a global
 * entry would silently exempt that future hole too. Fail-closed by construction, same as the
 * sibling file: a `${...}` not listed here defaults to hazardous, and an entry that no longer
 * names a real qualifying-severity hole fails the staleness check in section C.
 */
const INERT_HOLES: readonly { file: string; expression: string; reason: string }[] = [
	{ file: 'tools/brand-audit-single.ts', expression: 'verdict.limit ?? 0', reason: '`limit?: number`, defaulted to 0' },
	{ file: 'tools/check-dnskey-strength.ts', expression: 'algorithm', reason: '`parseDnskeyAlgorithm(): number | null`, null-guarded' },
	{ file: 'tools/check-fast-flux.ts', expression: 'allUniqueIps.size', reason: '`Set#size`' },
	{ file: 'tools/check-fast-flux.ts', expression: 'effectiveRounds', reason: '`Math.max(3, Math.min(5, rounds ?? 3))`' },
	{ file: 'tools/check-fast-flux.ts', expression: 'ipSetChanges', reason: '`let ipSetChanges = 0`, incremented' },
	{ file: 'tools/check-fast-flux.ts', expression: 'overallMinTtl', reason: '`Math.min(...rounds.map((r) => r.minTtl))`' },
];

const LITERAL_TERNARY = /^[^?]*\?\s*'[^']*'\s*:\s*'[^']*'$/;

function isInertHole(site: Pick<Site, 'file'>, expression: string): boolean {
	return INERT_HOLES.some((e) => e.file === site.file && e.expression === expression) || LITERAL_TERNARY.test(expression);
}

// ---------------------------------------------------------------------------
// 2. DISCOVERY — every createFinding call site under this repo's root src/.
// ---------------------------------------------------------------------------

const ROOT_SOURCES = import.meta.glob(['../../src/**/*.ts', '!../../src/**/*.d.ts'], {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

interface Prose {
	readonly parts: readonly string[];
	readonly holes: readonly string[];
	readonly literal: boolean;
}

interface Site {
	readonly file: string;
	readonly line: number;
	readonly category: Prose;
	readonly title: Prose;
	readonly severity: Prose;
	readonly detail: Prose;
	readonly metadataSource: string | null;
}

const NON_LITERAL: Prose = { parts: [], holes: [], literal: false };

function readQuoted(src: string, start: number, quote: string): number {
	let i = start + 1;
	while (i < src.length) {
		if (src[i] === '\\') {
			i += 2;
			continue;
		}
		if (src[i] === quote) return i + 1;
		i++;
	}
	return i;
}

function readTemplate(src: string, start: number): number {
	let i = start + 1;
	while (i < src.length) {
		if (src[i] === '\\') {
			i += 2;
			continue;
		}
		if (src[i] === '`') return i + 1;
		if (src[i] === '$' && src[i + 1] === '{') {
			i = skipBraces(src, i + 2);
			continue;
		}
		i++;
	}
	return i;
}

function skipBraces(src: string, start: number): number {
	let depth = 1;
	let i = start;
	while (i < src.length && depth > 0) {
		const c = src[i];
		if (c === "'" || c === '"') {
			i = readQuoted(src, i, c);
			continue;
		}
		if (c === '`') {
			i = readTemplate(src, i);
			continue;
		}
		if (c === '{') depth++;
		if (c === '}') depth--;
		i++;
	}
	return i;
}

/** Same comment-stripping argument splitter as the sibling file — load-bearing there, kept identical here. */
function splitArguments(src: string, openIdx: number): string[] | null {
	let i = openIdx + 1;
	let depth = 1;
	const args: string[] = [];
	let current = '';
	while (i < src.length) {
		const c = src[i];
		if (c === '/' && src[i + 1] === '/') {
			const nl = src.indexOf('\n', i);
			i = nl === -1 ? src.length : nl;
			continue;
		}
		if (c === '/' && src[i + 1] === '*') {
			const end = src.indexOf('*/', i + 2);
			i = end === -1 ? src.length : end + 2;
			continue;
		}
		if (c === "'" || c === '"') {
			const next = readQuoted(src, i, c);
			current += src.slice(i, next);
			i = next;
			continue;
		}
		if (c === '`') {
			const next = readTemplate(src, i);
			current += src.slice(i, next);
			i = next;
			continue;
		}
		if (c === '(' || c === '[' || c === '{') depth++;
		if (c === ')' || c === ']' || c === '}') {
			depth--;
			if (depth === 0) {
				args.push(current);
				return args;
			}
		}
		if (c === ',' && depth === 1) {
			args.push(current);
			current = '';
			i++;
			continue;
		}
		current += c;
		i++;
	}
	return null;
}

function unescape(text: string): string {
	return text
		.replace(/\\(['"`\\])/g, '$1')
		.replace(/\\n/g, '\n')
		.replace(/\\t/g, '\t');
}

function parseProse(argSource: string): Prose {
	const t = argSource.trim();
	if ((t.startsWith("'") && t.endsWith("'") && t.length > 1) || (t.startsWith('"') && t.endsWith('"') && t.length > 1)) {
		return { parts: [unescape(t.slice(1, -1))], holes: [], literal: true };
	}
	if (t.startsWith('`') && t.endsWith('`') && t.length > 1) {
		const body = t.slice(1, -1);
		const parts: string[] = [];
		const holes: string[] = [];
		let i = 0;
		let segment = '';
		while (i < body.length) {
			if (body[i] === '\\') {
				segment += body.slice(i, i + 2);
				i += 2;
				continue;
			}
			if (body[i] === '$' && body[i + 1] === '{') {
				const end = skipBraces(body, i + 2);
				holes.push(body.slice(i + 2, end - 1).trim());
				parts.push(unescape(segment));
				segment = '';
				i = end;
				continue;
			}
			segment += body[i];
			i++;
		}
		parts.push(unescape(segment));
		return { parts, holes, literal: true };
	}
	return NON_LITERAL;
}

function isStatic(prose: Prose): boolean {
	return prose.literal && prose.holes.length === 0;
}

function render(prose: Prose, fill: (expression: string, index: number) => string): string {
	if (!prose.literal) return '';
	let out = prose.parts[0] ?? '';
	for (let i = 0; i < prose.holes.length; i++) {
		out += fill(prose.holes[i], i) + (prose.parts[i + 1] ?? '');
	}
	return out;
}

const INERT_FILL = '•';

function neutralText(prose: Prose): string {
	return render(prose, () => INERT_FILL);
}

function parseMetadata(source: string | null): Record<string, unknown> | undefined {
	if (!source) return undefined;
	const meta: Record<string, unknown> = {};
	for (const m of source.matchAll(/([A-Za-z_$][\w$]*)\s*:\s*(?:'([^']*)'|(true|false)|(-?\d+(?:\.\d+)?))/g)) {
		const key = m[1];
		if (m[2] !== undefined) meta[key] = m[2];
		else if (m[3] !== undefined) meta[key] = m[3] === 'true';
		else if (m[4] !== undefined) meta[key] = Number(m[4]);
	}
	return Object.keys(meta).length > 0 ? meta : undefined;
}

/**
 * Same computed-key recognizer as the sibling file (kept identical so both trees enforce the
 * SAME understood-shapes contract). The root tree's own discovery run turned up a shape the
 * sibling tree does not have: `{ [flag]: true }` / `{ [marker]: true }` — a dynamically-keyed
 * boolean status flag in several async/error-result builders (`async-start-result.ts`,
 * `brand-audit-*.ts`, `discover-brand-domains-start.ts`, `osint-investigate.ts`,
 * `scan-buckets.ts`). That shape cannot be SUBJECT_TERMS_METADATA_KEY (whose value is always an
 * array or an array-referencing identifier, never a boolean) and it cannot arm or disarm the
 * missing-control gate — it never touches title/detail interpolation at all. The sibling file was
 * updated in this same change to skip boolean-valued computed keys for exactly this reason,
 * before either file's fail-loud guard sees them.
 */
const COMPUTED_METADATA_KEY = /\[\s*([A-Za-z_$][\w$]*)\s*\]\s*:\s*(\[[^\]]*\]|[A-Za-z_$][\w$.]*)/g;

function parseSubjectTermDeclarations(source: string | null): readonly string[] {
	if (!source) return [];
	const declared: string[] = [];
	for (const m of source.matchAll(COMPUTED_METADATA_KEY)) {
		const rawValue = m[2].trim();
		if (rawValue === 'true' || rawValue === 'false') continue;
		if (m[1] !== 'SUBJECT_TERMS_METADATA_KEY') {
			throw new Error(
				`missing-control-intent-root audit: unrecognised computed metadata key "[${m[1]}]" in "${source.trim()}". ` +
					'parseMetadata only understands the [SUBJECT_TERMS_METADATA_KEY] shape; any other non-boolean computed ' +
					'key would otherwise be silently dropped from every assertion in this file. Teach ' +
					'parseSubjectTermDeclarations the new shape (or confirm it cannot arm the missing-control gate and ' +
					'list it as reviewed) before this passes.',
			);
		}
		const inner = rawValue.startsWith('[') ? rawValue.slice(1, -1) : rawValue;
		for (const part of inner.split(',')) {
			const trimmed = part.trim();
			if (trimmed) declared.push(trimmed);
		}
	}
	return declared;
}

function holeMatchesDeclaration(hole: string, declaration: string): boolean {
	return hole === declaration || hole.startsWith(`${declaration}.`);
}

const SITES: readonly Site[] = (() => {
	const found: Site[] = [];
	for (const [globKey, source] of Object.entries(ROOT_SOURCES)) {
		const file = globKey.replace(/^(\.\.\/)+src\//, '');
		if (file.endsWith('.d.ts')) continue;
		let cursor = 0;
		for (;;) {
			const at = source.indexOf('createFinding(', cursor);
			if (at === -1) break;
			cursor = at + 1;
			const preceding = source.slice(Math.max(0, at - 20), at);
			if (/[A-Za-z0-9_$.]$/.test(preceding)) continue;
			if (/\bfunction\s+$/.test(preceding)) continue;
			const args = splitArguments(source, at + 'createFinding'.length);
			if (!args || args.length < 4) continue;
			found.push({
				file,
				line: source.slice(0, at).split('\n').length,
				category: parseProse(args[0]),
				title: parseProse(args[1]),
				severity: parseProse(args[2]),
				detail: parseProse(args[3]),
				metadataSource: args[4] !== undefined && args[4].trim() !== '' ? args[4].trim() : null,
			});
		}
	}
	return found;
})();

/** Eager, same as the sibling file: an unmodeled computed key anywhere fails the whole file at module load. */
SITES.forEach((s) => parseSubjectTermDeclarations(s.metadataSource));

// ---------------------------------------------------------------------------
// 3. CLASSIFICATION — through the REAL exported gate.
// ---------------------------------------------------------------------------

const QUALIFYING_SEVERITIES = new Set(['high', 'critical']);

function atQualifyingSeverity(site: Site): boolean {
	return isStatic(site.severity) && QUALIFYING_SEVERITIES.has(site.severity.parts[0]);
}

function severityOf(site: Site): string | null {
	return isStatic(site.severity) ? site.severity.parts[0] : null;
}

function toFinding(site: Site, fill: (expression: string, index: number) => string = () => INERT_FILL): Finding {
	return {
		category: (isStatic(site.category) ? site.category.parts[0] : 'spf') as CheckCategory,
		title: render(site.title, fill),
		severity: (severityOf(site) ?? 'info') as Severity,
		detail: render(site.detail, fill),
		...(parseMetadata(site.metadataSource) ? { metadata: parseMetadata(site.metadataSource) } : {}),
	};
}

function zeroesCategory(site: Site, fill?: (expression: string, index: number) => string): boolean {
	return findingsIndicateMissingControl([toFinding(site, fill)]);
}

function zeroesCategoryWithoutProseConfidence(site: Site): boolean {
	const finding = toFinding(site);
	return findingsIndicateMissingControl([
		{ ...finding, metadata: { ...(finding.metadata ?? {}), confidence: finding.metadata?.confidence ?? 'deterministic' } },
	]);
}

function ref(site: Site): string {
	return `${site.file}:${site.line}`;
}

function label(site: Site): string {
	return `${ref(site)} [${severityOf(site) ?? 'runtime'}] "${neutralText(site.title)}"`;
}

const CLASSIFIABLE = SITES.filter((s) => s.title.literal && s.detail.literal && isStatic(s.severity));
const UNCLASSIFIABLE = SITES.filter((s) => !CLASSIFIABLE.includes(s));

const STATIC_ZEROERS = CLASSIFIABLE.filter((s) => zeroesCategory(s));

function isIntended(site: Site): boolean {
	const title = neutralText(site.title);
	return INTENDED_MISSING_CONTROLS.some((e) => e.file === site.file && e.title === title);
}

function isReviewedInterpolation(site: Site): boolean {
	const title = neutralText(site.title);
	return INTERPOLATION_REVIEWED.some((e) => e.file === site.file && e.title === title);
}

function fixed(text: string): Prose {
	return { parts: [text], holes: [], literal: true };
}

function interpolated(parts: string[], holes: string[]): Prose {
	return { parts, holes, literal: true };
}

// ---------------------------------------------------------------------------
// D. PLANTED POSITIVE CONTROLS — run FIRST. An audit never seen to fail is not evidence.
//    This file has its own discovery/parsing engine (a separate copy, not a shared import), so
//    its OWN plumbing needs its own proof it can fail, independent of the sibling file's controls.
// ---------------------------------------------------------------------------

describe('missing-control intent (root tree) — positive controls (the guard can fail)', () => {
	const PLANTED_BASE: Site = {
		file: 'tools/__planted__.ts',
		line: 1,
		category: fixed('spf'),
		title: fixed('Planted control finding'),
		severity: fixed('high'),
		detail: fixed('The SPF record is missing for this domain.'),
		metadataSource: null,
	};

	it('FIRES: a planted high-severity finding whose prose says "missing" is caught as a zeroer', () => {
		expect(zeroesCategory(PLANTED_BASE)).toBe(true);
		expect(isIntended(PLANTED_BASE)).toBe(false);
	});

	it('DISCRIMINATES on severity: the same prose at `medium` is NOT caught', () => {
		const medium: Site = { ...PLANTED_BASE, severity: fixed('medium') };
		expect(zeroesCategory(medium)).toBe(false);
	});

	it('DISCRIMINATES on declaration: `missingControl: false` beats matching prose', () => {
		const declaredFalse: Site = { ...PLANTED_BASE, metadataSource: '{ missingControl: false }' };
		expect(zeroesCategory(PLANTED_BASE), 'the base control must still fire, or this proves nothing').toBe(true);
		expect(zeroesCategory(declaredFalse)).toBe(false);
	});

	it('DISCRIMINATES on prose: a high-severity finding with no trigger word is NOT caught', () => {
		const clean: Site = { ...PLANTED_BASE, detail: fixed('The SPF policy ends in ?all, which asserts nothing.') };
		expect(zeroesCategory(clean)).toBe(false);
	});

	it('FIRES on interpolation: a planted site armed only by a hostile ${hole} is caught', () => {
		const interpolating: Site = {
			...PLANTED_BASE,
			detail: interpolated(['The policy directive ', ' was rejected by the parser.'], ['token']),
		};
		expect(zeroesCategory(interpolating), 'static text alone must not match').toBe(false);
		expect(zeroesCategory(interpolating, () => 'missing'), 'a hostile hole value must arm it').toBe(true);
	});

	it('DISCRIMINATES: a planted declared-subject-data hole is armed WITHOUT the declaration and clean WITH it', () => {
		const undeclared: Site = {
			file: 'tools/__planted__.ts',
			line: 1,
			category: fixed('dane'),
			title: interpolated(['Pin mismatch for '], ['token']),
			severity: fixed('high'),
			detail: fixed('placeholder'),
			metadataSource: null,
		};
		expect(zeroesCategory(undeclared, () => 'missing'), 'an undeclared hole must still be armable — otherwise this proves nothing').toBe(true);

		const declaredMeta = '{ [SUBJECT_TERMS_METADATA_KEY]: [token] }';
		const declared: Site = { ...undeclared, metadataSource: declaredMeta };
		const declarations = parseSubjectTermDeclarations(declared.metadataSource);
		expect(declarations, 'the computed-key parser must recognize this declaration').toEqual(['token']);
		expect(holeMatchesDeclaration('token', declarations[0])).toBe(true);
		expect(armedBy(undeclared, STANDALONE_HOSTILE_VALUES), 'armedBy must arm the undeclared hole').toEqual(['token <- "missing"']);
		expect(armedBy(declared, STANDALONE_HOSTILE_VALUES), 'the declaration must disarm it against every hostile value').toEqual([]);
		expect(armedBy(declared, STANDALONE_HOSTILE_VALUES, { declarations: false }), 'stripping it must re-arm it').not.toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// Non-vacuity — a guard that stops finding violations may just have stopped looking.
// ---------------------------------------------------------------------------

describe('missing-control intent (root tree) — discovery is not vacuous', () => {
	it('discovers a realistic census of createFinding sites across the root worker tree', () => {
		expect(Object.keys(ROOT_SOURCES).length, 'source glob resolved to nothing').toBeGreaterThan(100);
		expect(SITES.length, 'createFinding parser found implausibly few call sites').toBeGreaterThan(250);
		expect(new Set(SITES.map((s) => s.file)).size).toBeGreaterThan(40);
	});

	it('classifies the overwhelming majority of sites — the parser has not gone blind', () => {
		const coverage = CLASSIFIABLE.length / SITES.length;
		expect(
			coverage,
			`only ${CLASSIFIABLE.length}/${SITES.length} createFinding sites have literal title+detail+severity. ` +
				'A sharp drop means the parser stopped reading a syntax this tree uses, not that the tree changed.',
		).toBeGreaterThan(0.7);
	});

	it('recovers known anchor sites verbatim, proving the parser reads real root-tree arguments', () => {
		const ns = CLASSIFIABLE.find((s) => s.file === 'tools/ns-analysis.ts' && neutralText(s.title) === 'No NS records found');
		expect(ns, 'anchor site tools/ns-analysis.ts "No NS records found" not recovered').toBeDefined();
		expect(severityOf(ns!)).toBe('critical');
		expect(neutralText(ns!.detail)).toContain('the domain cannot resolve');

		const dane = CLASSIFIABLE.find((s) => s.file === 'tools/dane-analysis.ts' && neutralText(s.title) === 'No DANE TLSA for MX servers');
		expect(dane, 'anchor site tools/dane-analysis.ts "No DANE TLSA for MX servers" not recovered').toBeDefined();
		expect(severityOf(dane!)).toBe('medium');
		expect(parseMetadata(dane!.metadataSource)).toMatchObject({ missingControl: true });
	});

	it('finds sites that match the trigger prose BELOW qualifying severity (the detector still detects)', () => {
		const belowThreshold = CLASSIFIABLE.filter(
			(s) => !QUALIFYING_SEVERITIES.has(severityOf(s)!) && zeroesCategory({ ...s, severity: fixed('high') }),
		);
		expect(belowThreshold.length, 'no sub-threshold trigger prose found — the detector has stopped looking').toBeGreaterThan(5);
	});
});

// ---------------------------------------------------------------------------
// A. No UNLISTED root-tree site may zero a category.
// ---------------------------------------------------------------------------

describe('missing-control intent (root tree) — only listed findings may zero a category', () => {
	it('every site that zeroes on its own static prose is on INTENDED_MISSING_CONTROLS', () => {
		const unlisted = STATIC_ZEROERS.filter((s) => !isIntended(s));
		expect(
			unlisted.map(label),
			'These findings force `score: 0, passed: false` on their whole category — and trip the 64-point ' +
				'critical-gap ceiling for a critical category — purely because of the words they use. If that is ' +
				'intended, add a row to INTENDED_MISSING_CONTROLS with a reason. If it is not, reword the finding or ' +
				'lower its severity (a scoring-visible change — see the ticket note on landing that separately).',
		).toEqual([]);
	});

	it('is NOT vacuous: exactly the 7 measured static zeroers are found, no more, no fewer', () => {
		// Pinned to the exact count (not just >0) because this is the item-3 census the ticket asked
		// for: a silent rise means a new unreviewed zeroer landed; a silent fall means one was
		// reworded or removed without anyone noticing the register needs to shrink too.
		expect(
			STATIC_ZEROERS.length,
			`expected exactly 7 static zeroers in the root tree (the INTENDED_MISSING_CONTROLS census); found ` +
				`${STATIC_ZEROERS.length}: ${STATIC_ZEROERS.map(label).join(', ')}`,
		).toBe(7);
	});
});

// ---------------------------------------------------------------------------
// B. No LISTED root-tree site may STOP zeroing.
// ---------------------------------------------------------------------------

describe('missing-control intent (root tree) — listed findings must keep zeroing', () => {
	it.each(INTENDED_MISSING_CONTROLS)('$file — "$title" still zeroes its category ($mechanism)', (entry) => {
		const site = CLASSIFIABLE.find((s) => s.file === entry.file && neutralText(s.title) === entry.title);
		expect(
			site,
			`INTENDED_MISSING_CONTROLS names ${entry.file} "${entry.title}" but no such createFinding site exists. ` +
				'Either it was reworded (which silently un-zeroes the category and moves production scores UPWARD ' +
				'with nothing else to notice) or it was removed. Update this register in the same commit.',
		).toBeDefined();
		if (entry.mechanism === 'prose') {
			expect(severityOf(site!), `${entry.file} "${entry.title}" must stay at high/critical to keep zeroing`).toMatch(/^(high|critical)$/);
		} else {
			expect(
				parseMetadata(site!.metadataSource)?.missingControl,
				`${entry.file} "${entry.title}" is registered as a DECLARED zeroer but no longer carries ` +
					'`missingControl: true`. Either restore the declaration or change the row to mechanism: "prose" ' +
					'and accept that its wording is now load-bearing.',
			).toBe(true);
		}
		expect(isStatic(site!.category) ? site!.category.parts[0] : null).toBe(entry.category);
		expect(
			zeroesCategory(site!),
			`${entry.file} "${entry.title}" no longer satisfies scoreIndicatesMissingControl. Reason this entry was ` +
				'listed: ' +
				entry.reason,
		).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// C. No qualifying-severity root-tree site may be armed by an INTERPOLATED value that merely
//    CONTAINS a trigger word — the live-defect class (github.com / missingkids.org) — nor, since
//    SQ-102, by a value that IS one.
// ---------------------------------------------------------------------------

const INTERPOLATING_AT_RISK = CLASSIFIABLE.filter(
	(s) =>
		atQualifyingSeverity(s) &&
		!zeroesCategory(s) &&
		[...s.title.holes, ...s.detail.holes].some((h) => !isInertHole(s, h)) &&
		parseMetadata(s.metadataSource)?.missingControl !== true,
);

const EMBEDDED_HOSTILE_VALUES = ['missingkids.org', 'no-mx-record.example', 'requiredfields.co.nz'];
const STANDALONE_HOSTILE_VALUES = ['missing', 'required', 'not found'];

/** A "no … record" span with an UNBOUNDED gap, over prose whose every hole is one REDACTED-sized character. */
const UNBOUNDED_NO_RECORD = /no\s+[^\r\n]*\srecord/i;

function hasShortenableNoRecordSpan(site: Site): boolean {
	return [site.title, site.detail].some((prose) => UNBOUNDED_NO_RECORD.test(render(prose, () => '-')));
}

/**
 * `declarations: false` ignores the site's `[SUBJECT_TERMS_METADATA_KEY]` and `missingControl`
 * declarations; `inert: false` ignores INERT_HOLES. Both default to honoured — the switches exist
 * only so the non-vacuity tests can prove each defence is load-bearing, never to grade a site.
 */
function armedBy(site: Site, hostileValues: readonly string[], honour: { declarations?: boolean; inert?: boolean } = {}): string[] {
	const { declarations: honourDeclarations = true, inert: honourInert = true } = honour;
	const armed: string[] = [];
	const holes = [...site.title.holes, ...site.detail.holes];
	const declarations = honourDeclarations ? parseSubjectTermDeclarations(site.metadataSource) : [];
	const parsedMetadata = parseMetadata(site.metadataSource);
	const baseMetadata =
		honourDeclarations || !parsedMetadata
			? parsedMetadata
			: Object.fromEntries(Object.entries(parsedMetadata).filter(([key]) => key !== 'missingControl'));
	for (let index = 0; index < holes.length; index++) {
		if (honourInert && isInertHole(site, holes[index])) continue;
		const isDeclaredSubjectData = declarations.some((d) => holeMatchesDeclaration(holes[index], d));
		for (const value of hostileValues) {
			const fillTitle = (_e: string, i: number) => (i === index ? value : INERT_FILL);
			const fillDetail = (_e: string, i: number) => (i + site.title.holes.length === index ? value : INERT_FILL);
			const probe: Finding = {
				...toFinding(site),
				metadata: baseMetadata,
				title: render(site.title, fillTitle),
				detail: render(site.detail, fillDetail),
				...(isDeclaredSubjectData ? { metadata: { ...baseMetadata, subjectTerms: [value] } } : {}),
			};
			if (findingsIndicateMissingControl([probe])) {
				armed.push(`${holes[index]} <- "${value}"`);
				break;
			}
		}
	}
	return armed;
}

describe('missing-control intent (root tree) — interpolated values must not arm the gate', () => {
	it('the at-risk population is non-empty (the detector is watching real interpolating sites)', () => {
		expect(INTERPOLATING_AT_RISK.length, 'no qualifying-severity interpolating site found — the detector has stopped looking').toBeGreaterThan(5);
	});

	it('no high/critical finding is zeroed by a target-controlled value that merely CONTAINS a trigger word', () => {
		const offenders = INTERPOLATING_AT_RISK.filter((s) => !isReviewedInterpolation(s))
			.map((s) => ({ site: s, armed: armedBy(s, EMBEDDED_HOSTILE_VALUES) }))
			.filter((o) => o.armed.length > 0)
			.map((o) => `${label(o.site)} armed by ${o.armed.join(', ')}`);

		expect(
			offenders,
			'LIVE-DEFECT CLASS (the same class the sibling file measured in production on missingkids.org). Each of ' +
				'these findings zeroes its category when an interpolated value merely CONTAINS "missing" / "required" ' +
				'/ a "no … record" shape. Measured at the time this file was written: this root tree has ZERO such ' +
				'offenders — this assertion exists to keep it that way, not because one was found. The fix belongs ' +
				'in scoring/model.ts, NOT in per-site rewording.',
		).toEqual([]);
	});

	it('no high/critical finding can be armed by a target supplying the trigger word EXACTLY', () => {
		// A non-failing warning until SQ-102 (17 sites at SQ-100, 19 when re-measured). Closed with
		// metadata only, so a new interpolating site that reopens it fails here instead of joining a
		// warning nobody reads.
		const exposed = INTERPOLATING_AT_RISK.map((s) => ({ site: s, armed: armedBy(s, STANDALONE_HOSTILE_VALUES) }))
			.filter((o) => o.armed.length > 0)
			.map((o) => `${label(o.site)} via ${o.armed.join(', ')}`);
		expect(
			exposed,
			'Each of these findings zeroes its category when an interpolated value IS a trigger word ("missing", ' +
				'"required", "not found"): a single-label NS target, a package name, an upstream string. Declare the ' +
				'hole via `[SUBJECT_TERMS_METADATA_KEY]` (or `missingControl: false` when the finding never asserts an ' +
				'absent control), or list a provably numeric hole in INERT_HOLES. Never loosen armedBy to get here.',
		).toEqual([]);
	});

	it('is NOT vacuous: stripped of every declaration and inert entry, the measured population still arms', () => {
		// The gate above passes because each site is DEFENDED, not because the probe stopped probing:
		// with the defences ignored, all 19 sites SQ-102 measured are armed again.
		const undefended = INTERPOLATING_AT_RISK.filter(
			(s) => armedBy(s, STANDALONE_HOSTILE_VALUES, { declarations: false, inert: false }).length > 0,
		);
		expect(undefended.length, 'the exact-match probe went blind — it should still arm the undefended sites').toBeGreaterThanOrEqual(19);
	});

	it('every declaration and every INERT_HOLES entry is load-bearing (none decorative, none stale)', () => {
		const declaring = INTERPOLATING_AT_RISK.filter(
			(s) => parseSubjectTermDeclarations(s.metadataSource).length > 0 || parseMetadata(s.metadataSource)?.missingControl === false,
		);
		expect(declaring.length, 'no defended site found — the census below is vacuous').toBeGreaterThanOrEqual(18);
		expect(
			declaring.filter((s) => armedBy(s, STANDALONE_HOSTILE_VALUES, { declarations: false }).length === 0).map(label),
			'these declarations defend nothing: the site is not armed even without them — remove them or fix the probe',
		).toEqual([]);
		for (const entry of INERT_HOLES) {
			const sites = INTERPOLATING_AT_RISK.filter(
				(s) => s.file === entry.file && [...s.title.holes, ...s.detail.holes].includes(entry.expression),
			);
			expect(
				sites.length,
				`INERT_HOLES entry ${entry.file} \`${entry.expression}\` names no qualifying-severity hole — stale`,
			).toBeGreaterThan(0);
			for (const site of sites) {
				expect(armedBy(site, STANDALONE_HOSTILE_VALUES, { inert: false }), `${label(site)} without INERT_HOLES`).not.toEqual([]);
			}
		}
	});

	it('a subjectTerms declaration can only SUBTRACT: no declaring site has a "no … record" span redaction could shorten', () => {
		// redactSubjectData swaps each declared term for ONE character, wherever the term occurs. A term
		// inside a "no … record" span therefore shortens MISSING_CONTROL_REGEX's 64-character gap and can
		// MANUFACTURE a zeroing the unredacted prose never had. Rendering every hole as that one character
		// and matching with an UNBOUNDED gap finds every span a redaction could ever shorten.
		const declaring = SITES.filter((s) => s.title.literal && s.detail.literal && parseSubjectTermDeclarations(s.metadataSource).length > 0);
		expect(declaring.length, 'no declaring site found — the check below is vacuous').toBeGreaterThanOrEqual(17);
		expect(declaring.filter(hasShortenableNoRecordSpan).map(label), 'declare `missingControl: false` instead').toEqual([]);
	});

	it('is NOT vacuous: the span check fires on the real walkable-NSEC detail, which is why that site declares missingControl: false', () => {
		// Measured: "no NSEC3PARAM, … a plain NSEC record" has a 70-character gap, 6 past the bound;
		// redacting a dotless next-name such as "NSEC" shortens it to 64 and the regex fires.
		const nsec = CLASSIFIABLE.find(
			(s) => s.file === 'tools/check-nsec-walkability.ts' && neutralText(s.title) === 'Zone is walkable via plain NSEC',
		);
		expect(nsec, 'anchor site tools/check-nsec-walkability.ts "Zone is walkable via plain NSEC" not recovered').toBeDefined();
		expect(hasShortenableNoRecordSpan(nsec!)).toBe(true);
		expect(parseMetadata(nsec!.metadataSource)?.missingControl).toBe(false);
		expect(armedBy(nsec!, STANDALONE_HOSTILE_VALUES, { declarations: false }), 'undeclared, the site is armable').not.toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// Computed subjectTerms declarations, and the boolean-flag shape this tree newly surfaced.
// ---------------------------------------------------------------------------

describe('missing-control intent (root tree) — computed metadata keys are handled, not silently dropped', () => {
	it('recognizes the real root-tree sites that declare [SUBJECT_TERMS_METADATA_KEY] (the SQ-102 census)', () => {
		// Keyed on FILE, not line, for the sibling file's reason: lines shift on every unrelated edit.
		// A different list means a declaration was silently lost or a new one added — update it either
		// way, after checking the new site against section C.
		const declaring = SITES.filter((s) => parseSubjectTermDeclarations(s.metadataSource).length > 0);
		expect(declaring.map((s) => s.file).sort()).toEqual(
			[
				'lib/authoritative-dns-infra/delegation-analysis.ts',
				'lib/authoritative-dns-infra/delegation-analysis.ts',
				'lib/dns-error-result.ts',
				'lib/tls-probe-binding.ts',
				'tools/check-agent-discovery.ts',
				'tools/check-agent-discovery.ts',
				'tools/check-dnskey-strength.ts',
				'tools/check-dnssec-chain.ts',
				'tools/check-dnssec-chain.ts',
				'tools/check-fast-flux.ts',
				'tools/check-llms-txt.ts',
				'tools/check-llms-txt.ts',
				'tools/check-txt-hygiene.ts',
				'tools/dane-analysis.ts',
				'tools/mx-reputation-analysis.ts',
				'tools/ns-analysis.ts',
				'tools/zone-hygiene-analysis.ts',
			].sort(),
		);
	});

	it('the boolean-flag computed-key shape ([flag]/[marker]: true) is recognized as inert, not thrown on', () => {
		// Non-vacuity + regression pin for the shape this tree's own discovery surfaced (see the
		// COMPUTED_METADATA_KEY doc comment above). If SITES.forEach(parseSubjectTermDeclarations) at
		// module load had NOT skipped these, this whole file would already be a thrown error instead
		// of a running test — so passing this test at all is already partial proof, but pin the exact
		// known sites too, so a future regression (someone re-tightening the skip condition) is named.
		const flagSites = SITES.filter((s) => s.file === 'tools/async-start-result.ts' || s.file === 'tools/brand-audit-watch.ts');
		expect(flagSites.length, 'expected the known boolean-flag computed-key sites to still be discovered').toBeGreaterThan(0);
		for (const s of flagSites) {
			expect(parseSubjectTermDeclarations(s.metadataSource), `${ref(s)} must not be read as a subject-term declaration`).toEqual([]);
		}
	});

	it('FAILS LOUD on a computed metadata key this parser does not recognize (and is not a boolean flag)', () => {
		expect(() => parseSubjectTermDeclarations('{ [SOME_OTHER_COMPUTED_KEY]: [value] }')).toThrow(/unrecognised computed metadata key/);
	});

	it('does NOT fail loud on a boolean-valued computed key — it is structurally not a subject-term declaration', () => {
		expect(() => parseSubjectTermDeclarations('{ [flag]: true }')).not.toThrow();
		expect(parseSubjectTermDeclarations('{ [flag]: true }')).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// E. A DECLARED root-tree finding is prose-independent.
// ---------------------------------------------------------------------------

const DECLARED_SITES = CLASSIFIABLE.filter((s) => typeof parseMetadata(s.metadataSource)?.missingControl === 'boolean');

const HOSTILE_TITLE = 'Missing required control';
const HOSTILE_DETAIL = 'No SPF record found. The control is missing and a policy is required; it was not found.';

describe('missing-control intent (root tree) — a declared finding is prose-independent', () => {
	it('the declared population is non-empty', () => {
		// This tree's declared population was `true`-only until SQ-102 (7 sites as of SQ-74:
		// check-zone-hygiene.ts ×2, dane-analysis.ts ×2, delegation-analysis.ts,
		// check-shadow-domains.ts, ns-analysis.ts). SQ-102 added the first `false`, on
		// check-nsec-walkability.ts's walkable-NSEC finding, so the sweep below now proves both
		// directions here too, like the sibling file.
		expect(DECLARED_SITES.length, 'no site declares metadata.missingControl — the sweep below is vacuous').toBeGreaterThan(2);
		expect([...new Set(DECLARED_SITES.map((s) => parseMetadata(s.metadataSource)!.missingControl))].sort()).toEqual([false, true]);
	});

	it.each(DECLARED_SITES.map((s) => [ref(s), s] as const))('%s keeps its verdict through any reword', (_ref, site) => {
		const declared = parseMetadata(site.metadataSource)!.missingControl as boolean;
		const base = toFinding(site);
		const hostile: Finding = { ...base, title: HOSTILE_TITLE, detail: HOSTILE_DETAIL };
		const innocuous: Finding = { ...base, title: 'Observation', detail: 'The zone is configured as described.' };

		expect(findingsIndicateMissingControl([base]), 'the site does not honour its own declaration').toBe(declared);
		expect(
			findingsIndicateMissingControl([hostile]),
			`${ref(site)} changes its scoring verdict when its prose is reworded into the trigger words.`,
		).toBe(declared);
		expect(
			findingsIndicateMissingControl([innocuous]),
			`${ref(site)} changes its scoring verdict when its prose is reworded into neutral text.`,
		).toBe(declared);
	});
});

// ---------------------------------------------------------------------------
// F. No root-tree verdict may depend on the prose-inferred CONFIDENCE sniff.
// ---------------------------------------------------------------------------

describe('missing-control intent (root tree) — no verdict may depend on the prose-confidence sniff', () => {
	it('every site decides identically with and without the adjective sniff', () => {
		const dependent = CLASSIFIABLE.filter((s) => zeroesCategory(s) !== zeroesCategoryWithoutProseConfidence(s)).map(label);
		expect(
			dependent,
			'These findings are held out of (or pushed into) the missing-control gate by an ADJECTIVE. Declare the ' +
				'intent instead: `missingControl: false` for a graded deficiency, `missingControl: true` for a ' +
				'measured absence.',
		).toEqual([]);
	});

	it('is NOT vacuous: the sniff still disarms a planted finding', () => {
		const planted: Site = {
			file: 'tools/__planted__.ts',
			line: 1,
			category: fixed('spf'),
			title: fixed('Planted sniff-dependent finding'),
			severity: fixed('high'),
			detail: fixed('A potential problem: no SPF record found for this zone.'),
			metadataSource: null,
		};
		expect(zeroesCategory(planted), '"potential" should downgrade this to heuristic and disarm the gate').toBe(false);
		expect(zeroesCategoryWithoutProseConfidence(planted), 'without the sniff the same sentence zeroes the category').toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Sanity: scoreIndicatesMissingControl (the regex leg alone) is real and imported — used only to
// keep the import from going stale as an unused re-export; the file's actual gate throughout is
// the structural predicate `findingsIndicateMissingControl`, exactly like the sibling file.
// ---------------------------------------------------------------------------

describe('missing-control intent (root tree) — the regex leg alone still fires on trigger prose', () => {
	it('scoreIndicatesMissingControl matches a bare "no record" sentence with no declaration', () => {
		expect(scoreIndicatesMissingControl([{ category: 'ns', title: 'x', severity: 'high', detail: 'No NS record found.' }])).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Inventory — reported, not failed. Same doctrine as the sibling file: a parser that quietly
// shrinks its own scope makes every sweep above pass for the wrong reason.
// ---------------------------------------------------------------------------

describe('missing-control intent (root tree) — latent risk inventory', () => {
	it('reports the runtime-severity blind spot this audit cannot statically classify', () => {
		const why = (s: Site) =>
			!isStatic(s.severity) ? 'severity is an expression' : !s.title.literal ? 'title is an expression' : 'detail is an expression';
		console.warn(
			`[missing-control-intent-root] ${UNCLASSIFIABLE.length} site(s) cannot be classified from source:\n` +
				UNCLASSIFIABLE.map((s) => `  - ${ref(s)} (${why(s)})`).join('\n'),
		);
		expect(UNCLASSIFIABLE.length, 'every site suddenly statically classifiable — verify the parser still parses').toBeGreaterThan(0);
	});
});
