// SPDX-License-Identifier: BUSL-1.1

/**
 * Guards against #984: `SCORING_MODEL_VERSION` reused for different content
 * across two PRs authored against a stale base (#956/#958/#959 collided with
 * #971's 1.26.0). See scripts/ci/check-scoring-model-history.mjs for exactly
 * what this catches and what it does not.
 *
 * Needs real `node:fs` to read the live source (parsing the hand-maintained
 * JSDoc history comment, not just the runtime export), so this runs in the
 * Node vitest project — registered in scripts/vitest-node-suites.mjs.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { evaluateScoringVersionHistory, parseVersionHistory } from '../../scripts/ci/check-scoring-model-history.mjs';
import { SCORING_MODEL_VERSION } from '../../src/lib/scoring-version';

const SOURCE_PATH = resolve(__dirname, '../../src/lib/scoring-version.ts');

describe('scoring-version history guard (#984)', () => {
	it('parses at least one version-history bullet from the live source', () => {
		const source = readFileSync(SOURCE_PATH, 'utf8');
		expect(parseVersionHistory(source).length).toBeGreaterThan(0);
	});

	it('the live history log never reuses a superseded version, and SCORING_MODEL_VERSION matches the newest entry', () => {
		const source = readFileSync(SOURCE_PATH, 'utf8');
		const versions = parseVersionHistory(source);
		const result = evaluateScoringVersionHistory(versions, SCORING_MODEL_VERSION);
		expect(result.errors).toEqual([]);
		expect(result.ok).toBe(true);
	});

	it('flags a version resurrected after the log advanced past it (the #956/#958/#959 shape)', () => {
		// Same shape as the incident: 1.26.0 shipped (#971), then something
		// based on the pre-#971 tip claims 1.27.0 and re-adds a 1.26.0 entry.
		const result = evaluateScoringVersionHistory(['1.25.0', '1.26.0', '1.27.0', '1.26.0'], '1.27.0');
		expect(result.ok).toBe(false);
		expect(result.errors.length).toBeGreaterThan(0);
	});

	it('flags a version going backward between adjacent entries', () => {
		const result = evaluateScoringVersionHistory(['1.5.0', '1.6.0', '1.4.0'], '1.6.0');
		expect(result.ok).toBe(false);
	});

	it('flags SCORING_MODEL_VERSION drifting from the newest logged entry', () => {
		const result = evaluateScoringVersionHistory(['1.0.0', '1.1.0'], '1.2.0');
		expect(result.ok).toBe(false);
		expect(result.errors[0]).toMatch(/newest history entry/);
	});

	it('accepts adjacent duplicate entries as one shipped batch (the historical 1.8.0 shape)', () => {
		const result = evaluateScoringVersionHistory(['1.7.0', '1.8.0', '1.8.0', '1.8.0', '1.9.0'], '1.9.0');
		expect(result.ok).toBe(true);
		expect(result.errors).toEqual([]);
	});
});
