// SPDX-License-Identifier: BUSL-1.1

/**
 * Markov Chain candidate domain generator.
 *
 * Implements a character-level trigram model to generate "brand-sounding"
 * domain names statistically similar to a seed domain.
 */

import { LABEL_REGEX, MAX_LABEL_LENGTH } from '../lib/config';
import { generateCognitiveLookalikes } from './lookalike-analysis';

/**
 * Trigram model: map of "prefix" (2 chars) to map of "next char" to frequency.
 */
type TrigramModel = Map<string, Map<string, number>>;

/**
 * Start and end markers for sequences.
 */
const START_MARKER = '^';
const END_MARKER = '$';

/**
 * Train a trigram model on a set of strings.
 */
export function trainTrigramModel(samples: string[]): TrigramModel {
	const model: TrigramModel = new Map();

	for (const sample of samples) {
		const padded = START_MARKER + sample + END_MARKER;
		for (let i = 0; i < padded.length - 2; i++) {
			const prefix = padded.slice(i, i + 2);
			const next = padded[i + 2];

			let transitions = model.get(prefix);
			if (!transitions) {
				transitions = new Map();
				model.set(prefix, transitions);
			}
			transitions.set(next, (transitions.get(next) || 0) + 1);
		}
	}

	return model;
}

/**
 * Generate a candidate name from a trigram model.
 */
export function generateFromModel(model: TrigramModel, minLength = 3, maxLength = MAX_LABEL_LENGTH): string {
	let attempts = 0;
	while (attempts < 50) {
		attempts++;
		let result = '';
		let currentPrefix = START_MARKER + START_MARKER;

		// If the specific START_MARKER^2 prefix isn't found, try finding any prefix starting with ^
		if (!model.has(currentPrefix)) {
			const startPrefixes = Array.from(model.keys()).filter((k) => k.startsWith(START_MARKER));
			if (startPrefixes.length === 0) return '';
			currentPrefix = startPrefixes[Math.floor(Math.random() * startPrefixes.length)];
			result = currentPrefix.slice(1);
		}

		while (result.length < maxLength) {
			const transitions = model.get(currentPrefix);
			if (!transitions) break;

			const next = pickNextChar(transitions);
			if (next === END_MARKER) break;

			result += next;
			currentPrefix = (currentPrefix + next).slice(-2);
		}

		if (result.length >= minLength && LABEL_REGEX.test(result)) {
			return result;
		}
	}
	return '';
}

/**
 * Weighted random selection of the next character.
 */
function pickNextChar(transitions: Map<string, number>): string {
	const total = Array.from(transitions.values()).reduce((sum, count) => sum + count, 0);
	let r = Math.random() * total;
	for (const [char, count] of transitions.entries()) {
		r -= count;
		if (r <= 0) return char;
	}
	return Array.from(transitions.keys())[0];
}

/**
 * Common brand-related affixes to provide branching points for the Markov model.
 */
const BRAND_AFFIXES = ['auth', 'login', 'verify', 'cloud', 'secure', 'api', 'dev', 'cdn', 'mail', 'apps', 'portal', 'support', 'update'];

/**
 * Generate brand-related lookalike candidates for the brand-discovery
 * candidate universe.
 *
 * TWO LANES, unioned:
 *
 *  1. COGNITIVE misspellings ({@link generateCognitiveLookalikes}) — the
 *     spellings a large population believes are correct (`sketchers`,
 *     `berenstein`). These are ADDITIVE and carry their own cap, so `count`
 *     still governs the Markov lane exactly as before. They are added because
 *     a Mandela spelling that only reached `check_lookalikes` would remain
 *     invisible to `discover_brand_domains`, which builds its universe from
 *     this function alone.
 *
 *  2. The trigram Markov lane — `count` brand-SOUNDING names sampled from a
 *     model trained on the base label plus {@link BRAND_AFFIXES}. This is a
 *     different target: plausible-but-unseen names, not known misspellings.
 *
 * The two are disjoint in intent and near-disjoint in output; the union is
 * deduped and sorted.
 */
export function generateMarkovLookalikes(domain: string, count = 20): string[] {
	const normalized = domain.toLowerCase();
	const lastDot = normalized.lastIndexOf('.');
	if (lastDot === -1) return [];

	const base = normalized.slice(0, lastDot);
	const tld = normalized.slice(lastDot);

	// Train on the base name and common brand affixes to create branching points.
	// We add both prefix and suffix variations.
	const samples = [base];
	for (const affix of BRAND_AFFIXES) {
		samples.push(base + affix);
		samples.push(affix + base);
		samples.push(base + '-' + affix);
		samples.push(affix + '-' + base);
	}

	const model = trainTrigramModel(samples);

	// Lane 1 — cognitive misspellings. Additive: seeded before the Markov loop
	// but NOT counted against `count`, so the trigram lane still yields the
	// same number of samples it did before this union existed.
	const candidates = new Set<string>(generateCognitiveLookalikes(normalized));
	const markovCandidates = new Set<string>();
	let attempts = 0;
	// Lane 2 — we want candidates that sound like the brand but aren't just the
	// brand. Sized against `markovCandidates`, never the union, so a brand with
	// many cognitive misspellings does not starve the trigram lane.
	while (markovCandidates.size < count && attempts < count * 20) {
		attempts++;
		const generated = generateFromModel(model, Math.max(3, base.length - 3), base.length + 10);
		if (generated && generated !== base && !BRAND_AFFIXES.includes(generated)) {
			markovCandidates.add(generated + tld);
		}
	}

	for (const candidate of markovCandidates) candidates.add(candidate);
	return Array.from(candidates).sort();
}
