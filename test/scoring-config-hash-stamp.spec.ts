// SPDX-License-Identifier: BUSL-1.1

/**
 * The reproducibility stamp must not lie.
 *
 * `computeScoringConfigHash()` returns the literal `'default'` marker when called
 * with no argument, and two producer call sites called it argument-free:
 * `buildStructuredScanResult`'s fallback and `batchScan`'s error placeholder. Both
 * therefore stamped `scoringConfigHash: 'default'` — a claim that the result is
 * reproducible under the default scoring policy — even while a live
 * `SCORING_CONFIG` override was in force. A prod override existed for an unknown
 * period while every scan stamped `'default'`; these tests make that state
 * unrepresentable.
 *
 * The hash ALGORITHM is deliberately untested here (that is `scoring-version.spec.ts`);
 * what is locked is that the stamp tracks the EFFECTIVE config at every producer.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { setupFetchMock } from './helpers/dns-mock';
import { parseScoringConfigCached, resetScoringConfigCache } from '../src/lib/scoring-config';
import { computeScoringConfigHash } from '../src/lib/scoring-version';

const { restore } = setupFetchMock();

beforeEach(() => {
	IN_MEMORY_CACHE.clear();
	resetScoringConfigCache();
	// Blanket mock: every check errors/parses-empty, which is irrelevant here — the
	// stamp is metadata about the CONFIG, not about what the checks measured.
	globalThis.fetch = vi.fn().mockResolvedValue(new Response('OK', { status: 200, headers: { 'content-type': 'text/plain' } }));
});

afterEach(() => {
	restore();
	resetScoringConfigCache();
});

/**
 * An override that is deliberately NOT score-bearing: `baselineFailureRates` only
 * feeds the adaptive-weight baseline, which never reaches a reported score. It still
 * produces a distinct effective config, which is exactly what the stamp must
 * reflect — the fingerprint has to move whenever the config object moves, whether or
 * not that particular key moved a score. (Picking a score-bearing key here would
 * conflate "the stamp tracks the config" with "the config changed the numbers".)
 */
const OVERRIDE_RAW = JSON.stringify({ baselineFailureRates: { dmarc: 0.5 } });

describe('scoringConfigHash — scan_domain', () => {
	it('stamps the effective config even when NO enrichment is threaded', async () => {
		const { scanDomain, buildStructuredScanResult } = await import('../src/tools/scan-domain');

		const plain = await scanDomain('hash-stamp-plain.example', undefined, {
			scoringConfig: parseScoringConfigCached(undefined),
		});
		// The un-enriched call is the one that used to lie — every npm-package consumer
		// of the exported `buildStructuredScanResult` takes this path.
		const stamped = buildStructuredScanResult(plain).scoringConfigHash;

		expect(stamped).not.toBe('default');
		expect(stamped).toBe(computeScoringConfigHash(parseScoringConfigCached(undefined)));
	});

	it('a run WITH an override stamps a different hash than a run without', async () => {
		const { scanDomain, buildStructuredScanResult } = await import('../src/tools/scan-domain');

		const withoutOverride = await scanDomain('hash-stamp-a.example', undefined, {
			scoringConfig: parseScoringConfigCached(undefined),
		});
		resetScoringConfigCache();
		const withOverride = await scanDomain('hash-stamp-b.example', undefined, {
			scoringConfig: parseScoringConfigCached(OVERRIDE_RAW),
		});

		const plainHash = buildStructuredScanResult(withoutOverride).scoringConfigHash;
		const overrideHash = buildStructuredScanResult(withOverride).scoringConfigHash;

		expect(plainHash).not.toBe('default');
		expect(overrideHash).not.toBe('default');
		expect(overrideHash).not.toBe(plainHash);
	});

	it('an explicitly threaded enrichment hash still wins over the result stamp', async () => {
		const { scanDomain, buildStructuredScanResult } = await import('../src/tools/scan-domain');

		const result = await scanDomain('hash-stamp-enrich.example', undefined, {
			scoringConfig: parseScoringConfigCached(undefined),
		});
		expect(buildStructuredScanResult(result, { scoringConfigHash: 'abc123' }).scoringConfigHash).toBe('abc123');
	});

	it('a hand-built result carrying no stamp still degrades to the default marker', async () => {
		// The `'default'` marker is not removed, only demoted: it remains the honest
		// answer for a result that never passed through `scanDomain` at all.
		const { buildStructuredScanResult } = await import('../src/tools/scan-domain');
		const { scanDomain } = await import('../src/tools/scan-domain');

		const real = await scanDomain('hash-stamp-strip.example', undefined, {
			scoringConfig: parseScoringConfigCached(undefined),
		});
		const { scoringConfigHash: _dropped, ...withoutStamp } = real;
		expect(buildStructuredScanResult(withoutStamp).scoringConfigHash).toBe('default');
	});
});

describe('scoringConfigHash — batch_scan', () => {
	it('the never-measured error placeholder carries the batch’s effective config, not the default marker', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');

		const results = await batchScan(['not a valid domain'], {
			runtimeOptions: { scoringConfig: parseScoringConfigCached(OVERRIDE_RAW) },
		});

		expect(results).toHaveLength(1);
		expect(results[0].error).toBeTruthy();
		expect(results[0].measured).toBe(false);
		expect(results[0].scoringConfigHash).not.toBe('default');
		expect(results[0].scoringConfigHash).toBe(computeScoringConfigHash(parseScoringConfigCached(OVERRIDE_RAW)));
	});

	it('an error placeholder and a scanned sibling agree on the stamp within one batch', async () => {
		const { batchScan } = await import('../src/tools/batch-scan');

		const results = await batchScan(['not a valid domain', 'hash-stamp-batch.com'], {
			runtimeOptions: { scoringConfig: parseScoringConfigCached(OVERRIDE_RAW) },
		});

		expect(results).toHaveLength(2);
		expect(results[0].error).toBeTruthy();
		expect(results[1].error).toBeUndefined();
		// The disagreement this asserts against was real: the placeholder said 'default'
		// while its sibling in the same response said the override hash.
		expect(results[0].scoringConfigHash).toBe(results[1].scoringConfigHash);
	});
});
