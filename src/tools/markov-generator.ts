// SPDX-License-Identifier: BUSL-1.1

/**
 * Markov Chain candidate domain generator.
 *
 * Implements a character-level trigram model to generate "brand-sounding"
 * domain names statistically similar to a seed domain.
 */

import { LABEL_REGEX, MAX_LABEL_LENGTH } from '../lib/config';

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
const BRAND_AFFIXES = [
	'auth',
	'login',
	'verify',
	'cloud',
	'secure',
	'api',
	'dev',
	'cdn',
	'mail',
	'apps',
	'portal',
	'support',
	'update',
];

/**
 * Generate brand-related lookalike candidates using a Markov Chain approach.
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

	const candidates = new Set<string>();
	let attempts = 0;
	// We want candidates that sound like the brand but aren't just the brand.
	while (candidates.size < count && attempts < count * 20) {
		attempts++;
		const generated = generateFromModel(model, Math.max(3, base.length - 3), base.length + 10);
		if (generated && generated !== base && !BRAND_AFFIXES.includes(generated)) {
			candidates.add(generated + tld);
		}
	}

	return Array.from(candidates).sort();
}
