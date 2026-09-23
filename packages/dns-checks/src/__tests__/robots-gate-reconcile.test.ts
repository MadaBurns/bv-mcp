// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

/**
 * Exercises `reconcileCacheState` (robots-gate.ts:250-274), which is not exported.
 * It is reached only through the caller-owned {@link RobotsGroupCache}'s exported
 * surface — `createRobotsGroupCache`, `getRobotsGroupCacheStats`, and
 * `withRobotsGate(..., { cache })` — by mutating `cache.entries` directly, exactly
 * as an external owner of the opaque map is documented to be able to do.
 */

import { describe, it, expect, vi } from 'vitest';
import { createRobotsGroupCache, getRobotsGroupCacheStats, withRobotsGate } from '../robots-gate';

function textResponse(body: string, ok = true): Response {
	return new Response(body, { status: ok ? 200 : 404 });
}

describe('reconcileCacheState (via the caller-owned cache surface)', () => {
	it('accounts for an externally deleted entry without going negative, and refetches on the next request', async () => {
		const robotsFetches = vi.fn();
		const inner = async (url: string) => {
			if (url.endsWith('/robots.txt')) {
				robotsFetches();
				return textResponse('User-agent: *\nDisallow: /private\n');
			}
			return textResponse('ok');
		};
		const cache = createRobotsGroupCache();
		const gated = withRobotsGate(inner, { groupCache: cache });

		await gated('https://a.example.com/');
		const populated = getRobotsGroupCacheStats(cache);
		expect(populated.entries).toBe(1);
		expect(populated.retainedBytes).toBeGreaterThan(0);

		// An external owner mutates the opaque map directly, outside the gate's own bookkeeping.
		cache.entries.delete('a.example.com');

		const afterExternalDelete = getRobotsGroupCacheStats(cache);
		expect(afterExternalDelete.entries).toBe(0);
		expect(afterExternalDelete.retainedBytes).toBe(0);

		await gated('https://a.example.com/again');
		expect(robotsFetches).toHaveBeenCalledTimes(2);
	});

	it('adopts an externally inserted entry into accounting, weighing it into retained bytes', () => {
		const cache = createRobotsGroupCache();
		expect(getRobotsGroupCacheStats(cache)).toMatchObject({ entries: 0, retainedBytes: 0 });

		cache.entries.set('short', Promise.resolve(null));
		const afterShort = getRobotsGroupCacheStats(cache);
		expect(afterShort.entries).toBe(1);
		expect(afterShort.retainedBytes).toBeGreaterThan(0);

		cache.entries.set('a-much-longer-external-key', Promise.resolve(null));
		const afterLonger = getRobotsGroupCacheStats(cache);
		expect(afterLonger.entries).toBe(2);

		// The longer key's own weight (not a flat per-entry charge) must be counted:
		// its contribution to retained bytes must exceed the shorter entry's own weight.
		const longerEntryWeight = afterLonger.retainedBytes - afterShort.retainedBytes;
		expect(longerEntryWeight).toBeGreaterThan(afterShort.retainedBytes);
	});

	it('expires an externally inserted entry on the next reconcile after its TTL', () => {
		let now = 1_000;
		const ttlMs = 50;
		const cache = createRobotsGroupCache({ ttlMs, now: () => now });

		cache.entries.set('ghost.example.com', Promise.resolve(null));
		// Reconciling now (now=1000) is what stamps the expiry at now + ttlMs = 1050.
		const adopted = getRobotsGroupCacheStats(cache);
		expect(adopted.entries).toBe(1);

		now = 1_049; // one ms before expiry: still retained
		expect(getRobotsGroupCacheStats(cache).entries).toBe(1);

		now = 1_050; // at expiry: the next reconcile deletes it
		const expired = getRobotsGroupCacheStats(cache);
		expect(expired.entries).toBe(0);
		expect(expired.retainedBytes).toBe(0);
		expect(cache.entries.has('ghost.example.com')).toBe(false);
	});

	it('evicts oldest-first when external inserts push entries.size past maxEntries', () => {
		const cache = createRobotsGroupCache({ maxEntries: 2 });
		cache.entries.set('first', Promise.resolve(null));
		cache.entries.set('second', Promise.resolve(null));
		cache.entries.set('third', Promise.resolve(null));

		const stats = getRobotsGroupCacheStats(cache);
		expect(stats.entries).toBe(2);
		expect(stats.entries).toBeLessThanOrEqual(stats.maxEntries);
		expect(cache.entries.has('first')).toBe(false); // oldest evicted
		expect(cache.entries.has('second')).toBe(true); // survivors are the newest
		expect(cache.entries.has('third')).toBe(true);
	});

	it('evicts oldest-first when external inserts push retainedBytes past maxBytes', () => {
		// Calibrate one entry's weight at runtime rather than hardcoding the module's
		// private per-entry overhead constant.
		const calibration = createRobotsGroupCache();
		calibration.entries.set('aaa', Promise.resolve(null));
		const singleEntryWeight = getRobotsGroupCacheStats(calibration).retainedBytes;

		const cache = createRobotsGroupCache({ maxBytes: singleEntryWeight + 1 });
		cache.entries.set('aaa', Promise.resolve(null)); // same key length as calibration: same weight
		cache.entries.set('bbb', Promise.resolve(null));

		const stats = getRobotsGroupCacheStats(cache);
		expect(stats.entries).toBe(1);
		expect(stats.retainedBytes).toBeLessThanOrEqual(stats.maxBytes);
		expect(cache.entries.has('aaa')).toBe(false); // oldest evicted to fit the byte budget
		expect(cache.entries.has('bbb')).toBe(true); // survivor is the newest
	});

	it('never drives retained bytes below zero under repeated external deletes', async () => {
		const inner = async (url: string) =>
			url.endsWith('/robots.txt') ? textResponse('User-agent: *\nDisallow: /private\n') : textResponse('ok');
		const cache = createRobotsGroupCache();
		const gated = withRobotsGate(inner, { groupCache: cache });

		await gated('https://a.example.com/');
		await gated('https://b.example.com/');

		cache.entries.delete('a.example.com');
		cache.entries.delete('a.example.com'); // repeat: already gone, must not underflow accounting
		cache.entries.delete('b.example.com');
		cache.entries.delete('nonexistent.example.com'); // was never tracked at all

		const stats = getRobotsGroupCacheStats(cache);
		expect(stats.entries).toBe(0);
		expect(stats.retainedBytes).toBe(0);
	});
});
