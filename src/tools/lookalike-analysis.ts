// SPDX-License-Identifier: BUSL-1.1

/**
 * Lookalike domain generation utilities.
 * Generates typosquat/lookalike domain permutations using multiple strategies:
 * adjacent key swaps, character omission, character duplication, dot insertion,
 * common TLD swaps, and homoglyph substitution.
 */

import { LABEL_REGEX, MAX_DOMAIN_LENGTH, MAX_LABEL_LENGTH } from '../lib/config';

/**
 * QWERTY keyboard adjacency map for typosquat detection.
 *
 * Exported so {@link COGNITIVE_SUBSTITUTIONS} can be proven disjoint from it —
 * a "non-adjacent" substitution pair that is in fact adjacent adds no reach
 * over the motor pass and is silently dead weight.
 */
export const QWERTY_ADJACENT: Record<string, string[]> = {
	q: ['w', 'a'],
	w: ['q', 'e', 's', 'a'],
	e: ['w', 'r', 'd', 's'],
	r: ['e', 't', 'f', 'd'],
	t: ['r', 'y', 'g', 'f'],
	y: ['t', 'u', 'h', 'g'],
	u: ['y', 'i', 'j', 'h'],
	i: ['u', 'o', 'k', 'j'],
	o: ['i', 'p', 'l', 'k'],
	p: ['o', 'l'],
	a: ['q', 'w', 's', 'z'],
	s: ['a', 'w', 'e', 'd', 'z', 'x'],
	d: ['s', 'e', 'r', 'f', 'x', 'c'],
	f: ['d', 'r', 't', 'g', 'c', 'v'],
	g: ['f', 't', 'y', 'h', 'v', 'b'],
	h: ['g', 'y', 'u', 'j', 'b', 'n'],
	j: ['h', 'u', 'i', 'k', 'n', 'm'],
	k: ['j', 'i', 'o', 'l', 'm'],
	l: ['k', 'o', 'p'],
	z: ['a', 's', 'x'],
	x: ['z', 's', 'd', 'c'],
	c: ['x', 'd', 'f', 'v'],
	v: ['c', 'f', 'g', 'b'],
	b: ['v', 'g', 'h', 'n'],
	n: ['b', 'h', 'j', 'm'],
	m: ['n', 'j', 'k'],
};

/** Homoglyph substitution pairs (one substitution at a time) */
const HOMOGLYPHS: Array<[string, string]> = [
	['o', '0'],
	['0', 'o'],
	['l', '1'],
	['1', 'l'],
	['i', '1'],
	['1', 'i'],
	['l', 'i'],
	['i', 'l'],
	['rn', 'm'],
	['m', 'rn'],
	['vv', 'w'],
	['w', 'vv'],
];

/** Common TLD swap pairs */
const TLD_SWAPS: Array<[string, string]> = [
	['.com', '.co'],
	['.com', '.net'],
	['.com', '.org'],
	['.com', '.io'],
	['.co.nz', '.com'],
	['.com.au', '.com'],
];

/** Maximum number of permutations to return */
const MAX_PERMUTATIONS = 50;

/**
 * Split a domain into base (before TLD) and TLD parts.
 * Handles multi-part TLDs like .co.nz and .com.au.
 */
function splitDomainTld(domain: string): { base: string; tld: string } {
	const multiPartTlds = ['.co.nz', '.com.au', '.co.uk', '.org.uk', '.net.au', '.org.au'];
	for (const multiTld of multiPartTlds) {
		if (domain.endsWith(multiTld)) {
			return { base: domain.slice(0, -multiTld.length), tld: multiTld };
		}
	}
	const lastDot = domain.lastIndexOf('.');
	if (lastDot === -1) return { base: domain, tld: '' };
	return { base: domain.slice(0, lastDot), tld: domain.slice(lastDot) };
}

/**
 * Check whether a domain string is structurally valid.
 * Labels must be 1-63 chars, alphanumeric + hyphens, total <= 253 chars.
 */
function isDomainValid(domain: string): boolean {
	if (domain.length > MAX_DOMAIN_LENGTH) return false;
	const labels = domain.split('.');
	if (labels.length < 2) return false;
	for (const label of labels) {
		if (label.length === 0 || label.length > MAX_LABEL_LENGTH) return false;
		if (!LABEL_REGEX.test(label)) return false;
	}
	return true;
}

/**
 * Generate lookalike/typosquat domain permutations for a given domain.
 * Applies six strategies: adjacent key swaps, character omission, character duplication,
 * dot insertion, common TLD swaps, and homoglyph substitution.
 *
 * Returns up to 50 unique, valid, alphabetically sorted permutations.
 */
export function generateLookalikes(domain: string): string[] {
	const normalizedDomain = domain.toLowerCase();
	const { base, tld } = splitDomainTld(normalizedDomain);
	const candidates = new Set<string>();

	// 1. Adjacent key swaps — swap each char in base with QWERTY adjacent keys
	for (let i = 0; i < base.length; i++) {
		const ch = base[i];
		const adjacent = QWERTY_ADJACENT[ch];
		if (adjacent) {
			for (const adj of adjacent) {
				const permuted = base.slice(0, i) + adj + base.slice(i + 1);
				candidates.add(permuted + tld);
			}
		}
	}

	// 2. Character omission — remove one char at a time from base
	for (let i = 0; i < base.length; i++) {
		const permuted = base.slice(0, i) + base.slice(i + 1);
		if (permuted.length > 0) {
			candidates.add(permuted + tld);
		}
	}

	// 3. Character duplication — double one char at a time in base
	for (let i = 0; i < base.length; i++) {
		const permuted = base.slice(0, i) + base[i] + base[i] + base.slice(i + 1);
		candidates.add(permuted + tld);
	}

	// 4. Dot insertion — insert dots between chars in base (both parts must be >= 2 chars)
	for (let i = 1; i < base.length; i++) {
		const left = base.slice(0, i);
		const right = base.slice(i);
		if (left.length >= 2 && right.length >= 2) {
			candidates.add(left + '.' + right + tld);
		}
	}

	// 5. Common TLD swaps — swap to different TLD if original matches
	for (const [fromTld, toTld] of TLD_SWAPS) {
		if (tld === fromTld) {
			candidates.add(base + toTld);
		} else if (tld === toTld) {
			candidates.add(base + fromTld);
		}
	}

	// 6. Homoglyph substitution — one substitution at a time in base
	for (const [from, to] of HOMOGLYPHS) {
		let searchIdx = 0;
		while (searchIdx <= base.length - from.length) {
			const idx = base.indexOf(from, searchIdx);
			if (idx === -1) break;
			const permuted = base.slice(0, idx) + to + base.slice(idx + from.length);
			candidates.add(permuted + tld);
			searchIdx = idx + 1;
		}
	}

	// Filter, dedup, and cap
	const results = Array.from(candidates)
		.filter((candidate) => candidate !== normalizedDomain && isDomainValid(candidate))
		.sort();

	return results.slice(0, MAX_PERMUTATIONS);
}

/* -------------------------------------------------------------------------
 * COGNITIVE-ERROR GENERATION
 *
 * Everything above this line models a MOTOR error — a slip of the finger by
 * someone who knows the correct spelling: a neighbouring key, a dropped
 * character, a doubled character, a swapped TLD, a glyph that looks like
 * another glyph.
 *
 * A Mandela-effect misspelling is a COGNITIVE error: the spelling a large
 * population believes IS correct. It is typed deliberately, repeatedly, and
 * without the typist ever noticing — which makes it strictly more valuable to
 * an attacker than a motor typo, because the traffic is sustained rather than
 * accidental. `sketchers` (Skechers), `berenstein` (Berenstain) and `febreeze`
 * (Febreze) are the canonical examples.
 *
 * The motor operation set CANNOT reach one except by coincidence: it reaches
 * `febreeze` only because vowel lengthening happens to look like a duplicated
 * character, and it never reaches `sketchers` (an inserted letter) or
 * `berenstein` (a substitution across the keyboard). The three operations
 * below close that gap and are deliberately kept in their OWN function with
 * their OWN cap, so they cannot displace motor candidates through
 * `generateLookalikes`' alphabetical MAX_PERMUTATIONS truncation.
 * ---------------------------------------------------------------------- */

/**
 * OPERATION 1 — non-adjacent substitution.
 *
 * Phonetically confusable letter pairs: a speller who has only ever HEARD the
 * name picks the wrong grapheme for the right phoneme. Every pair here is
 * NON-adjacent on QWERTY by construction (pinned by a test against
 * {@link QWERTY_ADJACENT}) — an adjacent pair would already be covered by the
 * keyboard pass and would only burn probe budget. That is why `s`/`z`, `f`/`v`
 * and `d`/`c` are deliberately absent: the keyboard pass already emits them.
 */
export const COGNITIVE_SUBSTITUTIONS: ReadonlyArray<readonly [string, string]> = [
	// Vowel confusions — by far the largest real-world class.
	['a', 'e'],
	['e', 'a'],
	['e', 'i'],
	['i', 'e'],
	['i', 'y'],
	['y', 'i'],
	['o', 'u'],
	['u', 'o'],
	['a', 'o'],
	['o', 'a'],
	// Consonant graphemes sharing a phoneme.
	['c', 'k'],
	['k', 'c'],
	['c', 's'],
	['s', 'c'],
	['g', 'j'],
	['j', 'g'],
	['k', 'q'],
	['q', 'k'],
];

/**
 * OPERATION 2 — arbitrary insertion, bounded by English orthography.
 *
 * Unbounded insertion is `positions x 26` candidates, which at one DNS probe
 * each is not affordable. The bound is linguistic rather than arbitrary: an
 * inserted letter only counts when it COMPLETES a cluster that really occurs
 * in English spelling. That is exactly the mechanism behind `sketchers` —
 * `/tʃ/` after a short vowel is spelled `tch` far more often than `ch`, so
 * writers "restore" a `t` that was never there.
 *
 * Trigraphs are ranked ahead of digraphs when the cap bites: completing a
 * three-letter cluster is a much stronger orthographic signal than completing
 * a two-letter one.
 */
const ORTHOGRAPHIC_TRIGRAPHS: readonly string[] = ['tch', 'sch', 'ght', 'dge', 'tio', 'sio', 'ough', 'aigh'];
const ORTHOGRAPHIC_DIGRAPHS: readonly string[] = [
	'ck',
	'ng',
	'nk',
	'mp',
	'nd',
	'st',
	'sh',
	'ch',
	'th',
	'ph',
	'wh',
	'kn',
	'wr',
	'mb',
	'gh',
	'qu',
	'dg',
	'ct',
	'ps',
	'rh',
	'll',
	'ss',
	'tt',
	'nn',
	'rr',
	'ee',
	'oo',
	'ea',
	'ie',
	'ei',
	'ou',
	'ai',
	'au',
	'oa',
	'ue',
];
/**
 * Letters that carry the insertion. Restricted to the graphemes that actually
 * participate in the clusters above — inserting `x` or `z` never completes one,
 * so trying them would only cost cycles.
 */
const INSERTION_LETTERS: readonly string[] = ['a', 'c', 'e', 'g', 'h', 'i', 'k', 'n', 'o', 'r', 's', 't', 'u', 'w'];

/**
 * OPERATION 3 — morpheme swap.
 *
 * Whole-morpheme substitution: the speller reaches for a DIFFERENT, more
 * familiar morpheme that sounds the same. This is the operation that has no
 * single-character analogue at all — `tunes`->`toons` is four edits, so no
 * edit-distance mutator will ever propose it, yet it is one of the most
 * reliably mis-remembered spellings there is.
 *
 * Ordered longest-first so a specific morpheme wins over a generic affix.
 */
const MORPHEME_SWAPS: ReadonlyArray<readonly [string, string]> = [
	['tunes', 'toons'],
	['toons', 'tunes'],
	['stain', 'stein'],
	['stein', 'stain'],
	['froot', 'fruit'],
	['fruit', 'froot'],
	['tion', 'sion'],
	['sion', 'tion'],
	['ance', 'ence'],
	['ence', 'ance'],
	['ise', 'ize'],
	['ize', 'ise'],
	['our', 'or'],
	['ant', 'ent'],
	['ent', 'ant'],
	['ph', 'f'],
	['f', 'ph'],
	['ey', 'y'],
	['ie', 'y'],
	['re', 'er'],
	['er', 're'],
];

/**
 * Cap on cognitive permutations returned. Bounds the extra DNS-probe cost the
 * same way {@link MAX_COMBOSQUATS} does for the combosquat lane. The ordering
 * below is by OPERATION CLASS, not alphabetical, precisely so this cap can
 * never evict a morpheme swap or a substitution in favour of a low-signal
 * insertion — the failure mode `generateLookalikes`' alphabetical `.sort()`
 * + `.slice()` truncation has.
 *
 * SIZED ON MEASUREMENT, not taste. Against the four-brand Mandela corpus the
 * known cognitive spelling lands at rank 1 (`berenstein`, `jcpenny`), 13
 * (`sketchers`) and 16 (`febreeze`) — so 30 carries roughly 2x headroom over
 * the observed worst case. It also bounds what this lane costs
 * `check_lookalikes`, whose candidate set (motor + cognitive + combosquat)
 * goes from ~70 to ~96 probes on a saturating brand.
 */
export const MAX_COGNITIVE_LOOKALIKES = 30;

/** Apply a table of one-at-a-time string rewrites at every occurrence. */
function applyRewrites(base: string, pairs: ReadonlyArray<readonly [string, string]>): string[] {
	const out: string[] = [];
	for (const [from, to] of pairs) {
		let idx = base.indexOf(from);
		while (idx !== -1) {
			out.push(base.slice(0, idx) + to + base.slice(idx + from.length));
			idx = base.indexOf(from, idx + 1);
		}
	}
	return out;
}

/**
 * Insert one letter at every position, keeping only insertions that complete a
 * real English cluster. Returns trigraph-completing insertions before
 * digraph-completing ones (see {@link ORTHOGRAPHIC_TRIGRAPHS}).
 */
function orthographicInsertions(base: string): string[] {
	const trigraphHits: string[] = [];
	const digraphHits: string[] = [];
	for (let i = 0; i <= base.length; i++) {
		for (const letter of INSERTION_LETTERS) {
			const candidate = base.slice(0, i) + letter + base.slice(i);
			// A cluster counts only when it CONTAINS the inserted character —
			// otherwise every candidate would qualify off a cluster the seed
			// already had, and the bound would do nothing.
			let tier: 0 | 2 | 3 = 0;
			for (const cluster of ORTHOGRAPHIC_TRIGRAPHS) {
				const from = Math.max(0, i - cluster.length + 1);
				if (candidate.slice(from, i + cluster.length).includes(cluster)) {
					tier = 3;
					break;
				}
			}
			if (tier === 0) {
				for (const cluster of ORTHOGRAPHIC_DIGRAPHS) {
					const from = Math.max(0, i - cluster.length + 1);
					if (candidate.slice(from, i + cluster.length).includes(cluster)) {
						tier = 2;
						break;
					}
				}
			}
			if (tier === 3) trigraphHits.push(candidate);
			else if (tier === 2) digraphHits.push(candidate);
		}
	}
	return [...trigraphHits, ...digraphHits];
}

/**
 * Generate COGNITIVE-error lookalike permutations — the misspellings a large
 * population believes are correct, which the motor operation set in
 * {@link generateLookalikes} cannot reach.
 *
 * Applies three operations, emitted in descending signal order so the
 * {@link MAX_COGNITIVE_LOOKALIKES} cap only ever truncates the weakest class:
 *   1. morpheme swap (no edit-distance mutator can propose these at all),
 *   2. non-adjacent phonetic substitution,
 *   3. orthographically-bounded arbitrary insertion.
 *
 * Deliberately a SEPARATE function with its own cap rather than more branches
 * inside `generateLookalikes()`: that function sorts alphabetically and slices
 * at `MAX_PERMUTATIONS`, so folding these in would silently evict existing
 * motor candidates on any brand that already saturates the cap (most do).
 *
 * Returns up to {@link MAX_COGNITIVE_LOOKALIKES} unique, valid permutations.
 * Deterministic; only the label is mutated, never the (possibly multi-part)
 * eTLD.
 */
export function generateCognitiveLookalikes(domain: string): string[] {
	const normalizedDomain = domain.toLowerCase();
	const { base, tld } = splitDomainTld(normalizedDomain);
	if (!base || !tld) return [];

	const ordered = [
		...applyRewrites(base, MORPHEME_SWAPS),
		...applyRewrites(base, COGNITIVE_SUBSTITUTIONS),
		...orthographicInsertions(base),
	];

	const seen = new Set<string>();
	const results: string[] = [];
	for (const permuted of ordered) {
		const candidate = permuted + tld;
		if (candidate === normalizedDomain || seen.has(candidate)) continue;
		if (!isDomainValid(candidate)) continue;
		seen.add(candidate);
		results.push(candidate);
		if (results.length >= MAX_COGNITIVE_LOOKALIKES) break;
	}
	return results;
}

/**
 * Credential-phishing affixes used for combosquat *generation*. Deliberately a
 * focused subset of the highest-signal lure words — generation pays one DNS
 * probe per candidate, so it has a tighter cost/recall tradeoff than the
 * free pattern-matching `LURE_KEYWORDS` set used for detection in
 * `domain-similarity.ts`. Tune for probe budget, not for recall.
 */
const COMBOSQUAT_AFFIXES = ['login', 'signin', 'secure', 'verify', 'account', 'support', 'billing', 'update', 'mail', 'pay'] as const;

/** Cap on combosquat permutations returned — bounds the extra DNS-probe cost. */
const MAX_COMBOSQUATS = 20;

/**
 * Generate combosquat permutations: the brand label combined with a
 * credential-phishing affix, hyphen-delimited, in both positions
 * (`brand-login.com`, `login-brand.com`).
 *
 * Combosquats defeat whole-label edit distance (appending a token collapses the
 * normalized score), so the typo-based {@link generateLookalikes} never produces
 * them — this is the proactive counterpart to the detection-side
 * `combosquatMatch`. Returns up to {@link MAX_COMBOSQUATS} unique, valid,
 * alphabetically sorted permutations. Delimited-only by design: undelimited
 * concatenations are too collision-prone to probe speculatively.
 */
export function generateCombosquats(domain: string): string[] {
	const normalizedDomain = domain.toLowerCase();
	const { base, tld } = splitDomainTld(normalizedDomain);
	if (!base || !tld) return [];

	const candidates = new Set<string>();
	for (const affix of COMBOSQUAT_AFFIXES) {
		candidates.add(`${base}-${affix}${tld}`);
		candidates.add(`${affix}-${base}${tld}`);
	}

	return Array.from(candidates)
		.filter((candidate) => candidate !== normalizedDomain && isDomainValid(candidate))
		.sort()
		.slice(0, MAX_COMBOSQUATS);
}
