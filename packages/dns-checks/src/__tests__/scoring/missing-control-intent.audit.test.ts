// SPDX-License-Identifier: BUSL-1.1

/// <reference types="vite/client" />

/**
 * Structural audit — WHICH findings are allowed to zero a category, and by what mechanism.
 *
 * ## The hazard
 *
 * `scoreIndicatesMissingControl` (scoring/model.ts) runs a regex over a finding's `title`
 * and `detail`. A match at `high`/`critical` severity with `deterministic`/`verified`
 * confidence makes `buildCheckResult` force `score: 0, passed: false`, and — because
 * `scoring/engine.ts` builds its `missingControls` map from this predicate and NOTHING else,
 * not from `metadata.missingControl` — it ALSO trips the critical-gap ceiling of 64 for any
 * category in `PROFILE_CRITICAL_CATEGORIES`. Incidental PROSE is therefore strictly more
 * powerful than the deliberate `missingControl: true` flag.
 *
 * Three consequences follow, and all three are measured, not theoretical:
 *
 * 1. A finding can start zeroing a category because someone chose a different adjective.
 * 2. A finding can STOP zeroing a category because someone removed one, moving real scores
 *    upward with no test to notice.
 * 3. Worst: the trigger word need not be in the source at all. Most findings interpolate
 *    target-controlled values (`${target}`, `${domain}`, `${mxHost}`, `${policy}`) into the
 *    same sentence, so the SCANNED DOMAIN'S OWN NAME can supply it. Verified live in
 *    production 2026-08-20: `github.com` scores `dnssec` 60 and `missingkids.org` scores 0
 *    on byte-identical findings, dropping the whole domain from 79/B to 64/D and publishing
 *    that grade at `/security-report/missingkids.org`.
 *
 * ## Why this file exists
 *
 * The defence today is hand-written per-site source comments. There are three that re-derive
 * the rule from memory, a fourth (`mta-sts-analysis.ts`, the `MTA_STS_ABSENCE_IS_GRADED_NOT_ZEROING`
 * block) that states it WRONGLY, and the best-written one of the lot (`check-dnssec.ts`, which
 * claims its detail "deliberately avoids" the trigger words) sits directly above the live
 * defect — because the comment governs the static text while the hazard arrives through the
 * `${target}` next to it. A convention enforced by prose comments, against a mechanism
 * triggered by prose, is not a control. `parity-corpus.contract.test.ts` cannot close the gap
 * either: it is fixture-driven, so it only ever sees the scenarios someone thought to write down.
 *
 * This audit is enumerative instead. It discovers every `createFinding` call site from source,
 * reconstructs the real title/detail/severity/metadata, and runs the REAL exported
 * `scoreIndicatesMissingControl` over them — so the regex, the severity gate and the
 * prose-inferred confidence gate can never drift from what this test believes they are.
 *
 * It asserts four directions plus a planted positive control:
 *
 *   A. Every site that zeroes on its own static text is on `INTENDED_MISSING_CONTROLS`.
 *   B. Every entry on `INTENDED_MISSING_CONTROLS` still zeroes (the silent-loss direction).
 *   C. No qualifying-severity site can be armed by an INTERPOLATED target-controlled value.
 *   D. The classifier is proven to fire, and proven to discriminate, on planted findings.
 *
 * Discovery is via `import.meta.glob(..., '?raw')` — vite-resolved and scoped to this package's
 * `src/`, so it never walks the filesystem and can never descend into a nested `.worktrees/`
 * or `.claude/worktrees/` checkout the way a `readdirSync` recursion would.
 */

import { describe, expect, it } from 'vitest';
import { scoreIndicatesMissingControl } from '../../scoring/model';
import type { CheckCategory, Finding, Severity } from '../../types';

// ---------------------------------------------------------------------------
// 1. THE INTENT REGISTER
// ---------------------------------------------------------------------------

interface IntendedZeroer {
	/** Path relative to `packages/dns-checks/src`. */
	readonly file: string;
	/** Exact `createFinding` title argument. Identity is file+title, not line — lines churn. */
	readonly title: string;
	readonly category: CheckCategory;
	/** Why zeroing this category is the DESIGNED outcome, not an accident of wording. */
	readonly reason: string;
}

/**
 * The findings that are SUPPOSED to zero their category.
 *
 * Every entry below was read in source before being listed; the audit that produced the
 * candidate list is treated as a lead, not as evidence. Adding a row here is a deliberate
 * scoring decision and should be reviewed as one.
 */
const INTENDED_MISSING_CONTROLS: readonly IntendedZeroer[] = [
	{
		file: 'scoring/classifiers/dmarc.ts',
		title: 'Missing DMARC policy',
		category: 'dmarc',
		reason:
			'A DMARC record with no `p=` tag is a control no receiver can evaluate, so zeroing is the ' +
			'same correct outcome the no-record case (`:67`) and the multiple-record case (`:82`) already ' +
			'get. Added 2026-08-20: this site previously zeroed PURELY by prose accident — its detail ' +
			'contains both "missing" and "required" — while its two siblings declared the intent. It now ' +
			'carries an explicit `{ missingControl: true }` so a reword cannot silently un-zero it. The ' +
			'declaration is behaviourally inert today (engine.ts reads the regex, never the flag); that ' +
			'gap is tracked in bv-web docs/superpowers/specs/2026-08-20-missing-control-prose-hazard.md.',
	},
	{
		file: 'checks/check-spf.ts',
		title: 'No SPF record found',
		category: 'spf',
		reason:
			'Genuinely absent control: zero TXT records begin with the v=spf1 version token, so no receiver ' +
			'can evaluate SPF at all. Emitted at `critical` on the early-return path immediately before ' +
			"buildCheckResult('spf', findings). The parity corpus pins this outcome as 'no record (missingControl)'.",
	},
	{
		file: 'checks/ns-analysis.ts',
		title: 'No NS records found',
		category: 'ns',
		reason:
			'Genuinely absent control: NS returned nothing AND the A-record fallback returned nothing. ' +
			'Carries an explicit `{ missingControl: true, domainResolves: false }` — the author declared ' +
			'the zeroing, so the prose match is corroborating a stated intent rather than creating one.',
	},
	{
		file: 'checks/check-dnssec.ts',
		title: 'DNSSEC chain of trust incomplete',
		category: 'dnssec',
		reason:
			'DNSKEY published but no DS in the parent zone — BOGUS to any validating resolver, i.e. worse ' +
			'than unsigned. Carries an explicit `{ missingControl: true }` and the comment above it states ' +
			'"explicit missingControl -> score 0". Declared intent, verified in source.',
	},
	{
		file: 'scoring/classifiers/dmarc.ts',
		title: 'No DMARC record found',
		category: 'dmarc',
		reason:
			'Genuinely absent control: recordCount === 0 on the classifier early-return path. No DMARC ' +
			'record exists, so receivers apply no policy. Zeroing is the correct representation of absence.',
	},
	// The four RFC 8461 conformance findings below. Grouped because they share one reason:
	// a policy file missing any REQUIRED directive is one a conforming sender must refuse to
	// apply, so the control does not function even though a file was served. Measured
	// 2026-08-20: each scores its category 0/failed at `high`; with the zeroing suppressed
	// they score 85+/passed.
	//
	// Listing them is a deliberate ratification of the invariant `test/check-mta-sts.spec.ts`
	// already pins ("DEPLOYED-BUT-BROKEN policy still penalises confidently" — score < 60,
	// passed false), NOT a new decision. A change of heart here is a scoring-model change and
	// belongs in that review, not in a reword: the counter-argument (a partial deployment
	// should still beat publishing nothing, which scores 85) is real but unadjudicated.
	//
	// ⚠️ These zero on AUTHORED prose, so `redactSubjectData` cannot reach them — unlike the
	// interpolated-subject-data sites, no domain name is involved. Rewording any of these
	// titles or details to drop "missing"/"required" would SILENTLY un-zero the category;
	// assertion B below is what catches that.
	{
		file: 'checks/mta-sts-analysis.ts',
		title: 'MTA-STS policy missing or invalid version',
		category: 'mta_sts',
		reason: 'RFC 8461 requires `version: STSv1`; without it a conforming sender refuses the policy, so MTA-STS does not function.',
	},
	{
		file: 'checks/mta-sts-analysis.ts',
		title: 'MTA-STS policy missing mode',
		category: 'mta_sts',
		reason: 'No `mode:` directive means the policy is inert — nothing is enforced or even tested, despite a file being served.',
	},
	{
		file: 'checks/mta-sts-analysis.ts',
		title: 'MTA-STS policy missing MX entries',
		category: 'mta_sts',
		reason: 'A policy with no `mx:` pattern covers no host, so no inbound mail path is protected by it.',
	},
	{
		file: 'checks/mta-sts-analysis.ts',
		title: 'MTA-STS policy missing max_age',
		category: 'mta_sts',
		reason: 'RFC 8461 requires `max_age`; a policy without one cannot be cached or applied, so senders fall back to opportunistic TLS.',
	},
];

/**
 * Sites whose interpolation into a qualifying-severity finding has been REVIEWED and accepted.
 *
 * Deliberately empty. It exists so that an accepted interpolation becomes an explicit, reviewed
 * row rather than an invisible side effect — the same shape as the debt registers under
 * `config/` in the web repo. An entry here is a statement that the interpolated value provably
 * cannot carry attacker- or target-controlled prose; "it seems unlikely" is not that statement.
 */
const INTERPOLATION_REVIEWED: readonly { file: string; title: string; reason: string }[] = [];

/**
 * Interpolation expressions that provably cannot carry prose, and are therefore excluded from
 * the arming analysis in test C. Each is a number or a fixed literal at its emission site.
 *
 * Fail-closed by construction: an expression NOT listed here is treated as target-controlled.
 * A new `${...}` in a finding defaults to hazardous and has to be argued out, never in.
 */
const INERT_HOLE_EXPRESSIONS: ReadonlySet<string> = new Set([
	'spfRecords.length', // count of matched TXT records
	'recursiveLookupCount', // SPF DNS-lookup budget counter
	'response.status', // HTTP status number
	'contentLength', // byte count
	'facts.recordCount', // count of DMARC TXT records
	'iterations', // NSEC3 iteration count
]);

/** `cond ? 'literal' : 'literal'` — a hole whose every branch is a source-fixed string. */
const LITERAL_TERNARY = /^[^?]*\?\s*'[^']*'\s*:\s*'[^']*'$/;

function isInertHole(expression: string): boolean {
	return INERT_HOLE_EXPRESSIONS.has(expression) || LITERAL_TERNARY.test(expression);
}

// ---------------------------------------------------------------------------
// 2. DISCOVERY — every createFinding call site in this package's src/
// ---------------------------------------------------------------------------

const PACKAGE_SOURCES = import.meta.glob(['../../**/*.ts', '!../../__tests__/**'], {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;

/** A template literal split into its source-fixed segments and its `${...}` expressions. */
interface Prose {
	/** `parts.length === holes.length + 1`. */
	readonly parts: readonly string[];
	readonly holes: readonly string[];
	/** False when the argument was not a string/template literal (a variable, a call, …). */
	readonly literal: boolean;
}

interface Site {
	readonly file: string;
	readonly line: number;
	readonly category: Prose;
	readonly title: Prose;
	readonly severity: Prose;
	readonly detail: Prose;
	/** Raw source text of the 5th (metadata) argument, or null. */
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

/** Advance past a balanced `${ ... }` body, respecting nested strings/templates. Returns index after `}`. */
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

/**
 * Split the argument list of a call whose `(` is at `openIdx`, returning each argument's
 * source text with comments REMOVED.
 *
 * Comment stripping is load-bearing, not cosmetic. This package routinely explains a
 * severity choice in a `//` comment sitting between the title and severity arguments — e.g.
 * `check-dkim.ts` "Deprecated hash algorithm", `check-bimi.ts` "No BIMI record found". An
 * earlier draft of this parser sliced raw source per argument, so those arguments came back
 * as `"// RFC 8301 §3.1: …\n'high'"`, failed the string-literal test, and the sites fell
 * silently out of the audit's scope — the guard would have stopped watching exactly the
 * sites whose authors cared enough to justify them.
 */
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

/** Recover the authored prose from one argument's source text. */
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

/** Render prose with each `${...}` replaced by `fill(expression, index)`. */
function render(prose: Prose, fill: (expression: string, index: number) => string): string {
	if (!prose.literal) return '';
	let out = prose.parts[0] ?? '';
	for (let i = 0; i < prose.holes.length; i++) {
		out += fill(prose.holes[i], i) + (prose.parts[i + 1] ?? '');
	}
	return out;
}

/**
 * A regex-inert, non-whitespace placeholder. Non-whitespace matters: the regex's
 * `no\s+[^\r\n]{1,64}\srecord` branch must still be able to span a hole, so a frame like
 * "no ${x} record" is correctly reported as matching on its STATIC text alone.
 */
const INERT_FILL = '•';

function neutralText(prose: Prose): string {
	return render(prose, () => INERT_FILL);
}

/** Parse the flat `key: value` pairs of a metadata object literal into a real object. */
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

const SITES: readonly Site[] = (() => {
	const found: Site[] = [];
	for (const [globKey, source] of Object.entries(PACKAGE_SOURCES)) {
		const file = globKey.replace(/^\.\.\/\.\.\//, '');
		if (file.endsWith('.d.ts')) continue;
		let cursor = 0;
		for (;;) {
			const at = source.indexOf('createFinding(', cursor);
			if (at === -1) break;
			cursor = at + 1;
			// Skip qualified/suffixed identifiers (`x.createFinding(`, `myCreateFinding(`) and the
			// two DECLARATIONS of createFinding itself, whose parameter list would otherwise be
			// parsed as a call with `severity: Severity` in the severity position.
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

// ---------------------------------------------------------------------------
// 3. CLASSIFICATION — through the REAL exported gate, never a copied regex
// ---------------------------------------------------------------------------

const QUALIFYING_SEVERITIES = new Set(['high', 'critical']);

/** Emitted at a severity the missing-control gate acts on, as a source literal. */
function atQualifyingSeverity(site: Site): boolean {
	return isStatic(site.severity) && QUALIFYING_SEVERITIES.has(site.severity.parts[0]);
}

function severityOf(site: Site): string | null {
	return isStatic(site.severity) ? site.severity.parts[0] : null;
}

/** Reconstruct a real `Finding` for this site, filling `${...}` holes via `fill`. */
function toFinding(site: Site, fill: (expression: string, index: number) => string = () => INERT_FILL): Finding {
	return {
		category: (isStatic(site.category) ? site.category.parts[0] : 'spf') as CheckCategory,
		title: render(site.title, fill),
		severity: (severityOf(site) ?? 'info') as Severity,
		detail: render(site.detail, fill),
		...(parseMetadata(site.metadataSource) ? { metadata: parseMetadata(site.metadataSource) } : {}),
	};
}

/** Does this site zero its category, per the REAL scoring gate? */
function zeroesCategory(site: Site, fill?: (expression: string, index: number) => string): boolean {
	return scoreIndicatesMissingControl([toFinding(site, fill)]);
}

function ref(site: Site): string {
	return `${site.file}:${site.line}`;
}

function label(site: Site): string {
	return `${ref(site)} [${severityOf(site) ?? 'runtime'}] "${neutralText(site.title)}"`;
}

/** Sites classifiable statically: literal title, detail and severity. */
const CLASSIFIABLE = SITES.filter((s) => s.title.literal && s.detail.literal && isStatic(s.severity));
/** Blind spot: severity (or the prose itself) is resolved at runtime. */
const UNCLASSIFIABLE = SITES.filter((s) => !CLASSIFIABLE.includes(s));

/** Sites that zero on their SOURCE-FIXED text alone. */
const STATIC_ZEROERS = CLASSIFIABLE.filter((s) => zeroesCategory(s));

function isIntended(site: Site): boolean {
	const title = neutralText(site.title);
	return INTENDED_MISSING_CONTROLS.some((e) => e.file === site.file && e.title === title);
}

function isReviewedInterpolation(site: Site): boolean {
	const title = neutralText(site.title);
	return INTERPOLATION_REVIEWED.some((e) => e.file === site.file && e.title === title);
}

/** Authored text with no `${...}` — the shape most planted fixtures need. */
function fixed(text: string): Prose {
	return { parts: [text], holes: [], literal: true };
}

/** Authored segments interleaved with named `${...}` expressions. */
function interpolated(parts: string[], holes: string[]): Prose {
	return { parts, holes, literal: true };
}

// ---------------------------------------------------------------------------
// D. PLANTED POSITIVE CONTROLS — run FIRST. An audit never seen to fail is not evidence.
// ---------------------------------------------------------------------------

describe('missing-control intent — positive controls (the guard can fail)', () => {
	const PLANTED_BASE: Site = {
		file: 'checks/__planted__.ts',
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

	it('DISCRIMINATES on confidence: the same finding at `heuristic` is NOT caught (the third gate)', () => {
		// Confidence is the gate most easily forgotten, and it is itself prose-inferred by a
		// seven-phrase sniff in inferFindingConfidence — so a copy edit can arm or disarm from
		// either side. Both routes are exercised: the explicit key, and the inferred phrase.
		const explicit: Site = { ...PLANTED_BASE, metadataSource: "{ confidence: 'heuristic' }" };
		expect(zeroesCategory(explicit)).toBe(false);

		const inferred: Site = {
			...PLANTED_BASE,
			detail: fixed('The SPF record is missing among tested selectors.'),
		};
		expect(zeroesCategory(inferred)).toBe(false);
	});

	it('DISCRIMINATES on prose: a high-severity finding with no trigger word is NOT caught', () => {
		const clean: Site = {
			...PLANTED_BASE,
			detail: fixed('The SPF policy ends in ?all, which asserts nothing.'),
		};
		expect(zeroesCategory(clean)).toBe(false);
	});

	it('FIRES on interpolation: a planted site armed only by a hostile ${hole} is caught', () => {
		// The live-defect shape: static text that cannot match, plus a target-controlled value
		// beside it that can. The planted value is a BARE token — not host-shaped — so this
		// control exercises the detector's plumbing (render → real gate) without depending on
		// how any particular subject-data defence classifies it.
		const interpolating: Site = {
			...PLANTED_BASE,
			detail: interpolated(['The policy directive ', ' was rejected by the parser.'], ['token']),
		};
		expect(zeroesCategory(interpolating), 'static text alone must not match').toBe(false);
		expect(
			zeroesCategory(interpolating, () => 'missing'),
			'a hostile hole value must arm it',
		).toBe(true);
	});

	it('PINS the 2026-08-20 production defect: a host-shaped interpolated value must not arm the gate', () => {
		// The exact sentence from the `check-dnssec.ts` unsigned-zone branch. In production on
		// 2026-08-20, `github.com` scored dnssec 60/passed and `missingkids.org` 0/failed on
		// byte-identical findings, dropping that domain from 79/B to 64/D on a published page.
		const dnssec: Site = {
			...PLANTED_BASE,
			category: fixed('dnssec'),
			title: fixed('DNSSEC not enabled'),
			detail: interpolated(
				['DNSSEC is not configured for ', '. Without DNSSEC, DNS responses are not cryptographically verified.'],
				['target'],
			),
			metadataSource: '{ penaltyOverride: 40 }',
		};
		expect(zeroesCategory(dnssec, () => 'github.com')).toBe(false);
		expect(
			zeroesCategory(dnssec, () => 'missingkids.org'),
			"REGRESSION: the scanned domain's own NAME is again able to zero its category and cap the grade at 64.",
		).toBe(false);
		// Non-vacuity for the two assertions above: the sentence frame IS still live — a value
		// that is not recognisable as subject data still arms it. Without this, a defence that
		// simply stopped matching anything would look like a pass.
		expect(
			zeroesCategory(dnssec, () => 'missing'),
			'the sentence frame is inert — this pin proves nothing',
		).toBe(true);
	});

	it('DISCRIMINATES on interpolation: a hole-free site is unaffected by hostile substitution', () => {
		const clean: Site = {
			...PLANTED_BASE,
			detail: fixed('DNSSEC is not configured for this zone.'),
		};
		expect(zeroesCategory(clean, () => 'missingkids.org')).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Non-vacuity — a guard that stops finding violations may just have stopped looking.
// ---------------------------------------------------------------------------

describe('missing-control intent — discovery is not vacuous', () => {
	it('discovers a realistic census of createFinding sites across the package', () => {
		expect(Object.keys(PACKAGE_SOURCES).length, 'source glob resolved to nothing').toBeGreaterThan(40);
		expect(SITES.length, 'createFinding parser found implausibly few call sites').toBeGreaterThan(200);
		expect(new Set(SITES.map((s) => s.file)).size).toBeGreaterThan(25);
	});

	it('classifies the overwhelming majority of sites — the parser has not gone blind', () => {
		// A parser that quietly stops recognising arguments does not fail; it shrinks its own
		// scope and every sweep below passes for the wrong reason. This exact regression already
		// happened once in development (see splitArguments) — an inter-argument `//` comment
		// pushed 7 sites, including a `high`-severity interpolating one, out of scope unnoticed.
		const coverage = CLASSIFIABLE.length / SITES.length;
		expect(
			coverage,
			`only ${CLASSIFIABLE.length}/${SITES.length} createFinding sites have literal title+detail+severity. ` +
				'A sharp drop means the parser stopped reading a syntax the package uses, not that the package changed.',
		).toBeGreaterThan(0.9);
	});

	it('recovers known anchor sites verbatim, proving the parser reads real arguments', () => {
		const spf = CLASSIFIABLE.find((s) => s.file === 'checks/check-spf.ts' && neutralText(s.title) === 'No SPF record found');
		expect(spf, 'anchor site checks/check-spf.ts "No SPF record found" not recovered').toBeDefined();
		expect(severityOf(spf!)).toBe('critical');
		expect(neutralText(spf!.detail)).toContain('Without SPF, any server can send email');

		const dnssec = CLASSIFIABLE.find((s) => s.file === 'checks/check-dnssec.ts' && neutralText(s.title) === 'DNSSEC not enabled');
		expect(dnssec, 'anchor site checks/check-dnssec.ts "DNSSEC not enabled" not recovered').toBeDefined();
		expect(dnssec!.detail.holes, 'the live-defect site must be seen to interpolate ${target}').toContain('target');
		expect(parseMetadata(dnssec!.metadataSource)).toMatchObject({ penaltyOverride: 40 });
	});

	it('finds sites that match the trigger prose BELOW qualifying severity (the detector still detects)', () => {
		// If this ever hits zero, the regex or the parser has gone quiet and every sweep below
		// would pass for the wrong reason.
		const belowThreshold = CLASSIFIABLE.filter(
			(s) => !QUALIFYING_SEVERITIES.has(severityOf(s)!) && zeroesCategory({ ...s, severity: fixed('high') }),
		);
		expect(belowThreshold.length, 'no sub-threshold trigger prose found — the detector has stopped looking').toBeGreaterThan(10);
	});
});

// ---------------------------------------------------------------------------
// A. No UNLISTED site may zero a category.
// ---------------------------------------------------------------------------

describe('missing-control intent — only listed findings may zero a category', () => {
	it('every site that zeroes on its own static prose is on INTENDED_MISSING_CONTROLS', () => {
		const unlisted = STATIC_ZEROERS.filter((s) => !isIntended(s));
		expect(
			unlisted.map(label),
			'These findings force `score: 0, passed: false` on their whole category — and trip the 64-point ' +
				'critical-gap ceiling — purely because of the words they use. If that is intended, add a row to ' +
				'INTENDED_MISSING_CONTROLS with a reason. If it is not, reword the finding or lower its severity.',
		).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// B. No LISTED site may STOP zeroing. A one-directional guard is half a guard.
// ---------------------------------------------------------------------------

describe('missing-control intent — listed findings must keep zeroing', () => {
	it.each(INTENDED_MISSING_CONTROLS)('$file — "$title" still zeroes its category', (entry) => {
		const site = CLASSIFIABLE.find((s) => s.file === entry.file && neutralText(s.title) === entry.title);
		expect(
			site,
			`INTENDED_MISSING_CONTROLS names ${entry.file} "${entry.title}" but no such createFinding site exists. ` +
				'Either it was reworded (which silently un-zeroes the category and moves production scores UPWARD ' +
				'with nothing else to notice) or it was removed. Update this register in the same commit.',
		).toBeDefined();
		expect(severityOf(site!), `${entry.file} "${entry.title}" must stay at high/critical to keep zeroing`).toMatch(/^(high|critical)$/);
		expect(isStatic(site!.category) ? site!.category.parts[0] : null).toBe(entry.category);
		expect(
			zeroesCategory(site!),
			`${entry.file} "${entry.title}" no longer satisfies scoreIndicatesMissingControl. Its behaviour rests on ` +
				'incidental wording, and that wording has changed. Reason this entry was listed: ' +
				entry.reason,
		).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// C. No qualifying-severity site may be armed by an INTERPOLATED value.
//    This is the class the live production defect belongs to, and the only assertion here
//    that static source inspection cannot reach — the trigger arrives at runtime.
// ---------------------------------------------------------------------------

/** Sites at qualifying severity+confidence that do NOT match on static text but DO interpolate. */
const INTERPOLATING_AT_RISK = CLASSIFIABLE.filter(
	(s) =>
		atQualifyingSeverity(s) &&
		!zeroesCategory(s) &&
		[...s.title.holes, ...s.detail.holes].some((h) => !isInertHole(h)) &&
		// A site that already declares `missingControl: true` has zeroed its category by
		// declaration regardless, so an interpolated arming cannot change the category score.
		// (It CAN still change the whole-domain ceiling, per scoring/engine.ts — a separate,
		// model-level asymmetry that belongs in an adjudication, not in this guard.)
		parseMetadata(s.metadataSource)?.missingControl !== true,
);

/**
 * The measured live case: a target-controlled value that merely CONTAINS a trigger substring.
 * `missingkids.org` is the real domain that scores `dnssec` 0 in production where `github.com`
 * scores 60 on byte-identical findings.
 */
const EMBEDDED_HOSTILE_VALUES = ['missingkids.org', 'no-mx-record.example', 'requiredfields.co.nz'];

/** A target-controlled value that IS the trigger word — e.g. a domain publishing `p=missing`. */
const STANDALONE_HOSTILE_VALUES = ['missing', 'required', 'not found'];

function armedBy(site: Site, hostileValues: readonly string[]): string[] {
	const armed: string[] = [];
	const holes = [...site.title.holes, ...site.detail.holes];
	for (let index = 0; index < holes.length; index++) {
		if (isInertHole(holes[index])) continue;
		for (const value of hostileValues) {
			// Title and detail hole indices are numbered independently by `render`, so probe each.
			const fillTitle = (_e: string, i: number) => (i === index ? value : INERT_FILL);
			const fillDetail = (_e: string, i: number) => (i + site.title.holes.length === index ? value : INERT_FILL);
			const probe: Finding = {
				...toFinding(site),
				title: render(site.title, fillTitle),
				detail: render(site.detail, fillDetail),
			};
			if (scoreIndicatesMissingControl([probe])) {
				armed.push(`${holes[index]} <- "${value}"`);
				break;
			}
		}
	}
	return armed;
}

describe('missing-control intent — interpolated values must not arm the gate', () => {
	it('the at-risk population is non-empty and includes the known live-defect site', () => {
		// Non-vacuity for this section specifically: if the filter goes empty, the sweep below
		// passes trivially. The dnssec unsigned-zone branch must be in scope.
		expect(INTERPOLATING_AT_RISK.length).toBeGreaterThan(0);
		expect(INTERPOLATING_AT_RISK.map((s) => `${s.file} :: ${neutralText(s.title)}`)).toContain(
			'checks/check-dnssec.ts :: DNSSEC not enabled',
		);
	});

	it('no high/critical finding is zeroed by a target-controlled value that merely CONTAINS a trigger word', () => {
		const offenders = INTERPOLATING_AT_RISK.filter((s) => !isReviewedInterpolation(s))
			.map((s) => ({ site: s, armed: armedBy(s, EMBEDDED_HOSTILE_VALUES) }))
			.filter((o) => o.armed.length > 0)
			.map((o) => `${label(o.site)} armed by ${o.armed.join(', ')}`);

		expect(
			offenders,
			'LIVE-DEFECT CLASS. Each of these findings zeroes its category — and, for a critical category, ' +
				'caps the whole domain at 64 — when an interpolated value merely CONTAINS "missing" / "required" / ' +
				'a "no … record" shape. The value is supplied by the scan target: its own domain name, a nameserver ' +
				'hostname, an MX host, a policy URL, its own DMARC p= token. Confirmed in production: ' +
				'missingkids.org scores dnssec 0 where github.com scores 60 on byte-identical findings. ' +
				'The fix belongs in scoring/model.ts (match against a projection of the prose that excludes ' +
				'interpolated values), NOT in per-site rewording — rewording re-creates the same prose dependency ' +
				'it is fixing, one site at a time.',
		).toEqual([]);
	});

	it('reports (without failing) findings a target could arm by supplying the trigger word EXACTLY', () => {
		// Deliberately a warning, not a failure. Defending against a value that IS the trigger word
		// ("p=missing", a hostname literally called `missing`) cannot be done by excluding
		// interpolations from the match — it requires deleting prose inference altogether and
		// migrating the four intended zeroers to `metadata.missingControl`, which per
		// scoring/engine.ts also needs the engine to start reading that flag. That is a
		// scoring-model change with corpus-wide score movement and belongs behind an adjudication
		// gate, not behind a test that turns red on a Tuesday.
		const exposed = INTERPOLATING_AT_RISK.map((s) => ({ site: s, armed: armedBy(s, STANDALONE_HOSTILE_VALUES) })).filter(
			(o) => o.armed.length > 0,
		);
		if (exposed.length > 0) {
			console.warn(
				`[missing-control-intent] ${exposed.length} high/critical finding(s) can be zeroed by a target supplying a ` +
					`trigger word verbatim:\n${exposed.map((o) => `  - ${label(o.site)} via ${o.armed.join(', ')}`).join('\n')}`,
			);
		}
		expect(exposed.length, 'detector went silent — it should still see this population').toBeGreaterThan(0);
	});
});

// ---------------------------------------------------------------------------
// Inventories — reported, not failed. Justification is in each block.
// ---------------------------------------------------------------------------

describe('missing-control intent — latent risk inventory', () => {
	it('reports findings that would zero their category on a single severity bump', () => {
		// WARNING, NOT FAILURE — deliberate. These sites are CORRECT today: their severity is an
		// authored value and a bump is a reviewed change. More to the point, the moment a bump
		// actually happens the site becomes an unlisted static zeroer and the FIRST test in this
		// file hard-fails on it. Pre-failing ~35 correct sites would force a 35-row debt register
		// that protects nothing the existing assertion does not already protect at the exact
		// moment the risk becomes real. The perverse members are worth reading, though: several
		// are POSITIVE or NOT-APPLICABLE findings ("Correctly-configured non-mail domain",
		// "SMTP DANE not applicable", "CAA inherited from parent zone") — promoting any of them
		// would zero the category of a domain that is doing BETTER than average.
		const latent = CLASSIFIABLE.filter(
			(s) => !QUALIFYING_SEVERITIES.has(severityOf(s)!) && zeroesCategory({ ...s, severity: fixed('high') }),
		);
		console.warn(
			`[missing-control-intent] ${latent.length} finding(s) would zero their category on a severity bump alone:\n` +
				latent.map((s) => `  - ${ref(s)} [${severityOf(s)}] "${neutralText(s.title)}"`).join('\n'),
		);
		expect(latent.length, 'detector went silent').toBeGreaterThan(0);
	});

	it('reports the runtime-severity blind spot this audit cannot statically classify', () => {
		// Honest blind spot: where `severity` is a variable, static text plus a runtime severity
		// could combine into a zeroing this file will never see. None of these currently carries
		// statically-matching prose, so none is active — but that is a property of today's text.
		const why = (s: Site) =>
			!isStatic(s.severity) ? 'severity is an expression' : !s.title.literal ? 'title is an expression' : 'detail is an expression';
		console.warn(
			`[missing-control-intent] ${UNCLASSIFIABLE.length} site(s) cannot be classified from source:\n` +
				UNCLASSIFIABLE.map((s) => `  - ${ref(s)} (${why(s)})`).join('\n'),
		);
		expect(UNCLASSIFIABLE.length, 'every site suddenly statically classifiable — verify the parser still parses').toBeGreaterThan(0);
	});
});
