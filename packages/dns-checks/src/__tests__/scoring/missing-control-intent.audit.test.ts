// SPDX-License-Identifier: BUSL-1.1

/// <reference types="vite/client" />

/**
 * Structural audit — WHICH findings are allowed to zero a category, and by what mechanism.
 *
 * ## The hazard
 *
 * `scoreIndicatesMissingControl` (scoring/model.ts) runs a regex over a finding's `title`
 * and `detail`. A match at `high`/`critical` severity with `deterministic`/`verified`
 * confidence makes `buildCheckResult` force `score: 0, passed: false`, and it ALSO trips the
 * critical-gap ceiling of 64 for any category in `PROFILE_CRITICAL_CATEGORIES`.
 *
 * This file tests the CANONICAL predicate `findingsIndicateMissingControl`, which is what
 * `buildCheckResult` and `scoring/engine.ts` actually call — not the regex leg alone. Since
 * scoring model 1.35.0 that predicate resolves each finding independently: an explicit
 * `metadata.missingControl` boolean is the answer, in BOTH directions, and only an
 * UNDECLARED finding falls through to the prose regex. So a declaration now outranks
 * incidental wording instead of being outranked by it.
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
 * predicates over them — so the regex, the severity gate, the confidence gate and the
 * structural declaration can never drift from what this test believes they are.
 *
 * It asserts six directions plus a planted positive control:
 *
 *   A. Every site that zeroes its category is on `INTENDED_MISSING_CONTROLS`.
 *   B. Every entry on `INTENDED_MISSING_CONTROLS` still zeroes (the silent-loss direction).
 *   C. No qualifying-severity site can be armed by an INTERPOLATED target-controlled value.
 *   D. The classifier is proven to fire, and proven to discriminate, on planted findings.
 *   E. A site that DECLARES `metadata.missingControl` is prose-independent — rewording its
 *      title and detail to anything at all, hostile or innocuous, cannot move the decision.
 *   F. No site's decision depends on the prose-inferred confidence sniff in
 *      `inferFindingConfidence`. That sniff is a display heuristic; a check that needs to
 *      stay out of the gate declares `missingControl: false` instead of choosing adjectives.
 *
 * Discovery is via `import.meta.glob(..., '?raw')` — vite-resolved and scoped to this package's
 * `src/`, so it never walks the filesystem and can never descend into a nested `.worktrees/`
 * or `.claude/worktrees/` checkout the way a `readdirSync` recursion would.
 */

import { describe, expect, it } from 'vitest';
import { findingsIndicateMissingControl, scoreIndicatesMissingControl } from '../../scoring/model';
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
	/**
	 * How the site zeroes.
	 *
	 * `declared` — `metadata.missingControl: true`. The author said so; severity is irrelevant
	 * (the structural leg has no severity gate) and a reword cannot silently un-zero it.
	 * `prose` — the regex reads the title/detail. Fragile by construction: it needs
	 * `high`/`critical` severity AND particular words, so a reword or a severity change
	 * un-zeroes the category and moves production scores upward. Assertion B is what notices.
	 * Migrating a `prose` row to `declared` is the standing remediation.
	 */
	readonly mechanism: 'declared' | 'prose';
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
		mechanism: 'declared',
		reason:
			'A DMARC record with no `p=` tag is a control no receiver can evaluate, so zeroing is the ' +
			'same correct outcome the no-record case (`:67`) and the multiple-record case (`:82`) already ' +
			'get. Added 2026-08-20: this site previously zeroed PURELY by prose accident — its detail ' +
			'contains both "missing" and "required" — while its two siblings declared the intent. It now ' +
			'carries an explicit `{ missingControl: true }` so a reword cannot silently un-zero it. Since ' +
			'scoring model 1.35.0 that declaration is the OPERATIVE signal rather than a comment: ' +
			'`findingsIndicateMissingControl` resolves the flag first and consults prose only when a ' +
			'finding declares nothing.',
	},
	{
		file: 'checks/check-spf.ts',
		title: 'No SPF record found',
		category: 'spf',
		mechanism: 'declared',
		reason:
			'Genuinely absent control: zero TXT records begin with the v=spf1 version token, so no receiver ' +
			'can evaluate SPF at all. Emitted at `critical` on the early-return path immediately before ' +
			"buildCheckResult('spf', findings). The parity corpus pins this outcome as 'no record (missingControl)'. " +
			'SQ-74: carries an explicit `{ missingControl: true }` — a reword can no longer silently un-zero this.',
	},
	{
		file: 'checks/ns-analysis.ts',
		title: 'No NS records found',
		category: 'ns',
		mechanism: 'declared',
		reason:
			'Genuinely absent control: NS returned nothing AND the A-record fallback returned nothing. ' +
			'Carries an explicit `{ missingControl: true, domainResolves: false }` — the author declared ' +
			'the zeroing, so the prose match is corroborating a stated intent rather than creating one.',
	},
	{
		file: 'checks/check-dnssec.ts',
		title: 'DNSSEC chain of trust incomplete',
		category: 'dnssec',
		mechanism: 'declared',
		reason:
			'A parent DS is published while the child DNSKEY is unavailable, so validating resolvers cannot ' +
			'authenticate the zone. This genuinely bogus branch retains explicit `{ missingControl: true }`; ' +
			'the DNSKEY-without-parent-DS island now has a distinct graded title and declares ' +
			'`missingControl: false`.',
	},
	{
		file: 'checks/check-dnssec.ts',
		title: 'DNSSEC validation failing',
		category: 'dnssec',
		mechanism: 'declared',
		reason:
			'DNSKEY and DS are both published but the AD flag is unset: the zone is BOGUS, and a validating ' +
			'resolver rejects its data outright — worse than not deploying DNSSEC at all. Declared since the ' +
			'DNSSEC-1 decision. It appears in this register only from scoring model 1.35.0, because before ' +
			'that this audit measured the regex leg alone and a declared-but-prose-clean site was invisible ' +
			'to it — the register under-described what actually zeroes.',
	},
	{
		file: 'scoring/classifiers/dmarc.ts',
		title: 'No DMARC record found',
		category: 'dmarc',
		mechanism: 'declared',
		reason:
			'Genuinely absent control: recordCount === 0 on the classifier early-return path. No DMARC ' +
			'record exists, so receivers apply no policy. Zeroing is the correct representation of absence. ' +
			'Since scoring model 1.13.0 the finding also DECLARES `missingControl: true` (like its ' +
			'multiple-record and missing-p= siblings), so the zeroing survives a reword of the prose ' +
			'this assertion pins.',
	},
	{
		file: 'scoring/classifiers/dmarc.ts',
		title: 'Multiple DMARC records — no valid policy',
		category: 'dmarc',
		mechanism: 'declared',
		reason:
			'RFC 9989 §4.7: more than one DMARC record at `_dmarc` means receivers MUST apply no policy, so ' +
			'the published records protect nothing. Declared `missingControl: true`; newly visible to this ' +
			'register for the same reason as "DNSSEC validation failing".',
	},
	{
		file: 'checks/check-mx.ts',
		title: 'No MX and no SPF — domain spoofable',
		category: 'mx',
		mechanism: 'declared',
		reason:
			'A domain with neither MX nor SPF publishes nothing a receiver can use to reject forged mail in ' +
			'its name. Declared `missingControl: true` at `medium` severity — legitimate, because the ' +
			'structural leg has no severity gate, and deliberate: `mx` is protective, so zeroing the category ' +
			"costs weighted points without arming any ceiling (`mx` is in no profile's criticalCategories).",
	},
	{
		file: 'checks/check-bimi.ts',
		title: 'BIMI record ineffective (DMARC not enforcing)',
		category: 'bimi',
		mechanism: 'declared',
		reason:
			'A BIMI record under a non-enforcing DMARC policy is inert — no mail client will render the logo — ' +
			'so the control is published but absent in effect. Declared `missingControl: true` at `medium`. ' +
			'`bimi` is a hardening category, so the zero is a binary pass/fail within a 10-point tier.',
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
	// SQ-74: these now carry an explicit `{ missingControl: true }` — a reword of any of these
	// titles or details can no longer silently un-zero the category. (Previously they zeroed on
	// AUTHORED prose alone; `redactSubjectData` was never relevant here since no domain name is
	// involved.)
	{
		file: 'checks/mta-sts-analysis.ts',
		title: 'MTA-STS policy missing or invalid version',
		category: 'mta_sts',
		mechanism: 'declared',
		reason: 'RFC 8461 requires `version: STSv1`; without it a conforming sender refuses the policy, so MTA-STS does not function.',
	},
	{
		file: 'checks/mta-sts-analysis.ts',
		title: 'MTA-STS policy missing mode',
		category: 'mta_sts',
		mechanism: 'declared',
		reason: 'No `mode:` directive means the policy is inert — nothing is enforced or even tested, despite a file being served.',
	},
	{
		file: 'checks/mta-sts-analysis.ts',
		title: 'MTA-STS policy missing MX entries',
		category: 'mta_sts',
		mechanism: 'declared',
		reason: 'A policy with no `mx:` pattern covers no host, so no inbound mail path is protected by it.',
	},
	{
		file: 'checks/mta-sts-analysis.ts',
		title: 'MTA-STS policy missing max_age',
		category: 'mta_sts',
		mechanism: 'declared',
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
	'keyAnalysis.bits', // number|null from the internal DER-header/length classifier; never DNS prose
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

/**
 * `parseMetadata`'s leaf regex requires an IDENTIFIER key (`key: value`) — a computed key
 * (`[SUBJECT_TERMS_METADATA_KEY]: [result.selector]`) starts with `[`, never matches, and is
 * silently absent from the reconstructed object with no signal that anything was dropped
 * (SQ-97). `check-dkim.ts` declares exactly this shape on 4 high/critical findings to redact a
 * caller-controlled DKIM selector before the missing-control regex sees it; `dane-analysis.ts`
 * declares it on a 5th to redact a zone-owner-controlled TLSA token. A parser that cannot see a
 * declared defense cannot notice one being deleted — the defense and its test would both go
 * silently dark together.
 *
 * This recognizes exactly that one computed-key shape (an array literal or a bare array
 * identifier as the value) and returns the raw hole EXPRESSION TEXT(s) it declares as subject
 * data — not resolved values, which only the running check knows. A boolean-valued computed key
 * (`{ [flag]: true }`) is skipped rather than routed through the fail-loud path below: it cannot
 * be this shape (SUBJECT_TERMS_METADATA_KEY's value is always an array or an array-referencing
 * identifier) and cannot arm or disarm the missing-control gate either, so there is nothing for
 * this audit to silently lose by ignoring it. Any OTHER (non-boolean) computed key is a metadata
 * shape this audit does not understand, so it FAILS LOUD instead of silently dropping it, per the
 * ticket's explicit fallback: failing loud is acceptable, silently skipping is not.
 */
const COMPUTED_METADATA_KEY = /\[\s*([A-Za-z_$][\w$]*)\s*\]\s*:\s*(\[[^\]]*\]|[A-Za-z_$][\w$.]*)/g;

function parseSubjectTermDeclarations(source: string | null): readonly string[] {
	if (!source) return [];
	const declared: string[] = [];
	for (const m of source.matchAll(COMPUTED_METADATA_KEY)) {
		// A boolean-valued computed key (`{ [flag]: true }`, seen in the root worker tree's
		// error-result builders — SQ-100) can never be the SUBJECT_TERMS_METADATA_KEY shape: that
		// shape's value is always an array literal or an identifier referencing one. It also cannot
		// arm or disarm the missing-control gate itself — the key is a status marker, not prose or a
		// redaction declaration — so it is not "metadata this audit cannot parse" in the sense the
		// fail-loud guard exists for. Skipping it here (rather than routing it through the throw
		// below) keeps that guard aimed at the one shape it is actually protecting.
		const rawValue = m[2].trim();
		if (rawValue === 'true' || rawValue === 'false') continue;
		if (m[1] !== 'SUBJECT_TERMS_METADATA_KEY') {
			throw new Error(
				`missing-control-intent audit: unrecognised computed metadata key "[${m[1]}]" in "${source.trim()}". ` +
					'parseMetadata only understands the [SUBJECT_TERMS_METADATA_KEY] shape; any other computed key ' +
					'would otherwise be silently dropped from every assertion in this file — the exact SQ-97 defect. ' +
					'Teach parseSubjectTermDeclarations the new shape (or confirm it cannot arm the missing-control ' +
					'gate and list it as reviewed) before this passes.',
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

/**
 * True when interpolation hole `hole` carries the same runtime value the metadata declares as
 * subject data — either the exact same expression (`result.selector` metadata / `result.selector`
 * hole) or a value DERIVED from it (`pinned` metadata / `pinned.join('; ')` hole, dane-analysis's
 * shape). Both are real shapes in this package; a bare identity check would miss the second.
 */
function holeMatchesDeclaration(hole: string, declaration: string): boolean {
	return hole === declaration || hole.startsWith(`${declaration}.`);
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

/**
 * `[SUBJECT_TERMS_METADATA_KEY]`-style declarations recognized EAGERLY, over every discovered
 * site, at module load — so an unmodeled computed key anywhere in the package fails the whole
 * file immediately, not only when the particular site happens to be probed by `armedBy` below.
 * This is the fail-loud half of the fix: `parseSubjectTermDeclarations` throws on any computed
 * key it does not recognize, and mapping it over `SITES` up front forces that check for real,
 * rather than leaving it to fire lazily (or never) depending on which sites later get probed.
 */
SITES.forEach((s) => parseSubjectTermDeclarations(s.metadataSource));

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

/**
 * Does this site zero its category, per the REAL scoring gate?
 *
 * `findingsIndicateMissingControl`, not the regex leg alone — it is the predicate
 * `buildCheckResult` and `scoring/engine.ts` call, so it is the only one whose answer moves a
 * score. Using the regex leg here (as this file did until scoring model 1.35.0) made the audit
 * blind in both directions at once: a site that zeroes by DECLARATION went unregistered, and a
 * site that declares `missingControl: false` was still reported as armable by its own prose.
 */
function zeroesCategory(site: Site, fill?: (expression: string, index: number) => string): boolean {
	return findingsIndicateMissingControl([toFinding(site, fill)]);
}

/**
 * The same decision, with any prose-INFERRED confidence replaced by an explicit
 * `deterministic`. Used by assertion F: if this disagrees with {@link zeroesCategory}, the
 * site's score depends on `inferFindingConfidence`'s adjective sniff.
 */
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
		// Confidence is the gate most easily forgotten, and it is still partly prose-inferred by
		// an adjective sniff in inferFindingConfidence — so a copy edit can arm or disarm from
		// either side. Both routes are exercised: the explicit key, and the inferred phrase.
		// (Assertion F below proves no REAL site relies on the inferred route.)
		const explicit: Site = { ...PLANTED_BASE, metadataSource: "{ confidence: 'heuristic' }" };
		expect(zeroesCategory(explicit)).toBe(false);

		const inferred: Site = {
			...PLANTED_BASE,
			detail: fixed('The SPF record is missing — a possible misconfiguration.'),
		};
		expect(zeroesCategory(inferred)).toBe(false);
	});

	it('DISCRIMINATES on declaration: `missingControl: false` beats matching prose', () => {
		// The direction added in scoring model 1.35.0. Same sentence, same severity, same
		// deterministic confidence as the FIRES control above — only the declaration differs.
		const declaredFalse: Site = { ...PLANTED_BASE, metadataSource: '{ missingControl: false }' };
		expect(zeroesCategory(PLANTED_BASE), 'the base control must still fire, or this proves nothing').toBe(true);
		expect(zeroesCategory(declaredFalse)).toBe(false);
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
	it.each(INTENDED_MISSING_CONTROLS)('$file — "$title" still zeroes its category ($mechanism)', (entry) => {
		const site = CLASSIFIABLE.find((s) => s.file === entry.file && neutralText(s.title) === entry.title);
		expect(
			site,
			`INTENDED_MISSING_CONTROLS names ${entry.file} "${entry.title}" but no such createFinding site exists. ` +
				'Either it was reworded (which silently un-zeroes the category and moves production scores UPWARD ' +
				'with nothing else to notice) or it was removed. Update this register in the same commit.',
		).toBeDefined();
		if (entry.mechanism === 'prose') {
			// Only the regex leg has a severity gate. A `prose` row that drops below high/critical
			// stops zeroing, so pin the severity as part of the row's contract.
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
	const declarations = parseSubjectTermDeclarations(site.metadataSource);
	const baseMetadata = parseMetadata(site.metadataSource);
	for (let index = 0; index < holes.length; index++) {
		if (isInertHole(holes[index])) continue;
		// A hole this site declares via `[SUBJECT_TERMS_METADATA_KEY]` is the SAME runtime value
		// as the hostile fill below — in the real check the array literal interpolates that exact
		// hole expression. Modeling that here is what makes this detector see the check-dkim.ts /
		// dane-analysis.ts redaction at all; without it every declared site looked identical to an
		// undeclared one (SQ-97).
		const isDeclaredSubjectData = declarations.some((d) => holeMatchesDeclaration(holes[index], d));
		for (const value of hostileValues) {
			// Title and detail hole indices are numbered independently by `render`, so probe each.
			const fillTitle = (_e: string, i: number) => (i === index ? value : INERT_FILL);
			const fillDetail = (_e: string, i: number) => (i + site.title.holes.length === index ? value : INERT_FILL);
			const probe: Finding = {
				...toFinding(site),
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
// SQ-97. Computed-key `[SUBJECT_TERMS_METADATA_KEY]` declarations must be visible to this
// audit, not silently dropped by `parseMetadata`'s identifier-only regex.
// ---------------------------------------------------------------------------

describe('missing-control intent — computed subjectTerms declarations are not invisible', () => {
	it('recognizes the real repo sites that declare [SUBJECT_TERMS_METADATA_KEY]', () => {
		// Non-vacuity: if this list is empty, every assertion below passes for the wrong reason.
		// Keyed on the declaring FILE, deliberately not on `site.line`: the census this pins is
		// "which files declare the shape, and how many sites in each". Line numbers shift whenever
		// anything above a site is edited (SQ-95's rcode imports moved all four check-dkim.ts sites
		// down by 8), which would fail this audit for a reason it does not actually care about.
		const declaring = SITES.filter((s) => parseSubjectTermDeclarations(s.metadataSource).length > 0);
		expect(
			declaring.map((s) => s.file).sort(),
			'expected exactly the 4 check-dkim.ts sites ("Malformed DKIM key", the weak/legacy RSA key finding, ' +
				'"Deprecated hash algorithm (h=sha1)", "No DKIM records found") + 1 dane-analysis.ts site (the TLSA ' +
				'pin mismatch) known to declare this shape; a different count means either a declaration was ' +
				'silently lost again or a new one was added — either way this list (and the report in SQ-97) needs ' +
				'updating',
		).toEqual(
			[
				'checks/check-dkim.ts',
				'checks/check-dkim.ts',
				'checks/check-dkim.ts',
				'checks/check-dkim.ts',
				'checks/dane-analysis.ts',
			].sort(),
		);
	});

	it('the real "Malformed DKIM key" / SHA-1-only / DANE-pin-mismatch sites are not armed, on their DECLARED hole, by a standalone trigger word', () => {
		// Before this fix these sites were structurally invisible to armedBy — their declared
		// subjectTerms never reached the reconstructed finding, so a hostile selector/pinned-record
		// value would have shown up as "exposed" (or worse: removing the declaration entirely would
		// have changed nothing this file could see). This is now a hard assertion on the SPECIFIC
		// declared hole, not the whole-site sweep above: dane-analysis's OTHER interpolated holes
		// (`name`, `cert.host`, …) are undeclared and share the file's pre-existing, deliberately
		// non-failing exposure to a value that IS the trigger word verbatim — a different, wider gap
		// this ticket does not touch. (The weak/legacy-RSA-key finding at check-dkim.ts:261 also
		// declares this shape but its `severity` and `detail` are runtime variables, not source
		// literals, so it is UNCLASSIFIABLE and outside what this file can probe at all — captured
		// as a known blind spot, not silently ignored.)
		const targets: ReadonlyArray<{ site: Site | undefined; declaredHole: string }> = [
			{
				site: CLASSIFIABLE.find((s) => s.file === 'checks/check-dkim.ts' && neutralText(s.title) === 'Malformed DKIM key: •'),
				declaredHole: 'result.selector',
			},
			{
				site: CLASSIFIABLE.find(
					(s) => s.file === 'checks/check-dkim.ts' && neutralText(s.title) === 'Deprecated hash algorithm (h=sha1): •',
				),
				declaredHole: 'result.selector',
			},
			{
				site: CLASSIFIABLE.find(
					(s) => s.file === 'checks/dane-analysis.ts' && neutralText(s.title) === 'DANE TLSA pin does not match the served certificate for •',
				),
				declaredHole: "pinned.join('; ')",
			},
		];
		for (const { site, declaredHole } of targets) {
			expect(site, 'anchor site not recovered — the parser or the source moved').toBeDefined();
			const armedOnDeclaredHole = armedBy(site!, STANDALONE_HOSTILE_VALUES).filter((entry) => entry.startsWith(`${declaredHole} <- `));
			expect(
				armedOnDeclaredHole,
				`${label(site!)}'s declared [SUBJECT_TERMS_METADATA_KEY] hole "${declaredHole}" is armed by a standalone ` +
					'trigger word — its redaction is not being modeled (or was actually removed from source).',
			).toEqual([]);
		}
	});

	it('DISCRIMINATES: the same planted hole is armed WITHOUT the declaration and clean WITH it', () => {
		// Positive control (this file's own doctrine: an audit never seen to fail is not evidence).
		const undeclared: Site = {
			file: 'checks/__planted__.ts',
			line: 1,
			category: fixed('dkim'),
			title: interpolated(['Weak RSA key: '], ['selector']),
			severity: fixed('high'),
			detail: fixed('placeholder'),
			metadataSource: null,
		};
		// `armedBy` tries STANDALONE_HOSTILE_VALUES in order and stops at the first that arms —
		// 'missing' is first, so an undeclared hole is caught by it before 'required' is even tried.
		expect(armedBy(undeclared, STANDALONE_HOSTILE_VALUES), 'an undeclared hole must still be armable — otherwise this proves nothing').toEqual([
			'selector <- "missing"',
		]);

		const declared: Site = { ...undeclared, metadataSource: '{ [SUBJECT_TERMS_METADATA_KEY]: [selector] }' };
		expect(armedBy(declared, STANDALONE_HOSTILE_VALUES), 'the declaration must disarm the identical hole against every hostile value').toEqual(
			[],
		);
	});

	it('FAILS LOUD on a computed metadata key this parser does not recognize', () => {
		expect(() => parseSubjectTermDeclarations('{ [SOME_OTHER_COMPUTED_KEY]: [value] }')).toThrow(/unrecognised computed metadata key/);
	});
});

// ---------------------------------------------------------------------------
// E. A DECLARED finding is prose-independent. This is the property the whole file exists
//    to make true: after a declaration, wording is wording.
// ---------------------------------------------------------------------------

/** Sites whose author stated the missing-control decision structurally, either way. */
const DECLARED_SITES = CLASSIFIABLE.filter((s) => typeof parseMetadata(s.metadataSource)?.missingControl === 'boolean');

/** Prose engineered to match `MISSING_CONTROL_REGEX` on every branch it has. */
const HOSTILE_TITLE = 'Missing required control';
const HOSTILE_DETAIL = 'No SPF record found. The control is missing and a policy is required; it was not found.';

describe('missing-control intent — a declared finding is prose-independent', () => {
	it('the declared population is non-empty and exercises BOTH directions', () => {
		expect(DECLARED_SITES.length, 'no site declares metadata.missingControl — the sweep below is vacuous').toBeGreaterThan(5);
		const directions = new Set(DECLARED_SITES.map((s) => parseMetadata(s.metadataSource)!.missingControl));
		expect(
			[...directions].sort(),
			'both `true` (zero this category) and `false` (this is a graded deficiency, not an absence claim) ' +
				'must appear, or only half the contract is under test.',
		).toEqual([false, true]);
	});

	it.each(DECLARED_SITES.map((s) => [ref(s), s] as const))('%s keeps its verdict through any reword', (_ref, site) => {
		const declared = parseMetadata(site.metadataSource)!.missingControl as boolean;
		const base = toFinding(site);
		const hostile: Finding = { ...base, title: HOSTILE_TITLE, detail: HOSTILE_DETAIL };
		const innocuous: Finding = { ...base, title: 'Observation', detail: 'The zone is configured as described.' };

		expect(findingsIndicateMissingControl([base]), 'the site does not honour its own declaration').toBe(declared);
		expect(
			findingsIndicateMissingControl([hostile]),
			`${ref(site)} changes its scoring verdict when its prose is reworded into the trigger words. A declared ` +
				'finding must be immune to its own wording — that is the entire point of declaring.',
		).toBe(declared);
		expect(
			findingsIndicateMissingControl([innocuous]),
			`${ref(site)} changes its scoring verdict when its prose is reworded into neutral text.`,
		).toBe(declared);
	});

	it('is NOT vacuous: the DKIM absence finding would zero its category on prose alone', () => {
		// The site the whole ticket turns on. Its title MATCHES the missing-control regex, `dkim`
		// is a critical category in mail_enabled/enterprise_mail, and before scoring model 1.35.0
		// the only thing between it and a zeroed core category (plus the 64 ceiling → grade D) was
		// its `confidence: 'heuristic'` metadata, seconded by a literal `'among tested selectors'`
		// inside inferFindingConfidence. Prose defending against prose.
		const dkim = CLASSIFIABLE.find(
			(s) => s.file === 'checks/check-dkim.ts' && neutralText(s.title) === 'No DKIM records found among tested selectors',
		);
		expect(dkim, 'the DKIM absence site was not recovered — this pin is watching nothing').toBeDefined();
		expect(parseMetadata(dkim!.metadataSource)?.missingControl).toBe(false);
		expect(severityOf(dkim!)).toBe('high');

		// Strip the declaration and the declared confidence: what remains is the sentence, and the
		// sentence still says "No DKIM records found". If this ever goes false the sentence stopped
		// being dangerous on its own and the assertions above stopped proving anything.
		const proseOnly: Finding = { ...toFinding(dkim!), metadata: { confidence: 'deterministic' } };
		expect(scoreIndicatesMissingControl([proseOnly]), 'the regex leg no longer reads this sentence').toBe(true);
		expect(findingsIndicateMissingControl([toFinding(dkim!)]), 'the declaration must beat that prose').toBe(false);
	});
});

// ---------------------------------------------------------------------------
// F. No score may rest on the prose-inferred CONFIDENCE sniff.
//    `inferFindingConfidence` sniffs seven adjectives ("possible", "potential", "inferred", …)
//    and downgrades to `heuristic`, which disarms the gate. That is a display heuristic being
//    used as a scoring control from the opposite direction: a copy edit that deletes the word
//    "potential" arms a zeroing nobody asked for. Measured across both source trees at the
//    time of writing: zero sites depend on it. This assertion keeps it that way.
// ---------------------------------------------------------------------------

describe('missing-control intent — no verdict may depend on the prose-confidence sniff', () => {
	it('every site decides identically with and without the adjective sniff', () => {
		const dependent = CLASSIFIABLE.filter((s) => zeroesCategory(s) !== zeroesCategoryWithoutProseConfidence(s)).map(label);
		expect(
			dependent,
			'These findings are held out of (or pushed into) the missing-control gate by an ADJECTIVE. Deleting the ' +
				'word "possible"/"potential"/"inferred" from one of these sentences would zero its category and, for a ' +
				'critical category, cap the whole domain at 64. Declare the intent instead: `missingControl: false` for ' +
				'a graded deficiency, `missingControl: true` for a measured absence. Both outrank prose.',
		).toEqual([]);
	});

	it('is NOT vacuous: the sniff still disarms a planted finding', () => {
		const planted: Site = {
			file: 'checks/__planted__.ts',
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
