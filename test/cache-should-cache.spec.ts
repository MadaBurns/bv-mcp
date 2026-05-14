// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the `shouldCache` predicate on runWithCache / runWithCacheTracked.
 *
 * Regression gate for bv-web 2026-05-14 analytics remediation (cluster F5):
 * the call site in src/handlers/tools.ts used to kv.put every result and then
 * kv.delete partial ones — driving ~13M wasted SCAN_CACHE writes/week. The
 * shouldCache predicate skips the put entirely.
 *
 * Layer: unit. Uses real IN_MEMORY_CACHE (sociable); KV is mocked only where
 * verifying the kv.put side-effect is the point.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { runWithCache, runWithCacheTracked, IN_MEMORY_CACHE } from '../src/lib/cache';

const notPartial = (r: { partial?: boolean }) => !r.partial;

afterEach(() => {
	vi.restoreAllMocks();
	IN_MEMORY_CACHE.clear();
});

describe('runWithCache — shouldCache predicate', () => {
	it('skips cache write when predicate returns false (no-KV / in-memory path)', async () => {
		await runWithCache(
			'inmem:partial',
			async () => ({ partial: true, value: 'x' }),
			undefined,
			undefined,
			undefined,
			notPartial,
		);
		expect(IN_MEMORY_CACHE.get('inmem:partial')).toBeUndefined();
	});

	it('still writes cache when predicate returns true (no-KV / in-memory path)', async () => {
		await runWithCache(
			'inmem:complete',
			async () => ({ partial: false, value: 'y' }),
			undefined,
			undefined,
			undefined,
			notPartial,
		);
		expect(IN_MEMORY_CACHE.get('inmem:complete')).toEqual({ partial: false, value: 'y' });
	});

	it('does not invoke kv.put on the result key when predicate returns false', async () => {
		// KV is the external boundary; mocking it is principle-8 compliant.
		const mockKV = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		await runWithCache(
			'kv:partial',
			async () => ({ partial: true }),
			mockKV as unknown as KVNamespace,
			300,
			undefined,
			notPartial,
		);
		const resultPut = mockKV.put.mock.calls.find(
			(c) => (c[0] as string) === 'kv:partial',
		);
		// The whole point of the F5 fix: no result-key put for partial results.
		expect(resultPut).toBeUndefined();
		// Sentinel cleanup must still run so future callers don't poll a stale lock.
		expect(mockKV.delete).toHaveBeenCalledWith('kv:partial:computing');
	});

	it('runWithCacheTracked threads the predicate through', async () => {
		const { data, cacheStatus } = await runWithCacheTracked(
			'tracked:partial',
			async () => ({ partial: true, value: 'z' }),
			undefined,
			undefined,
			undefined,
			notPartial,
		);
		expect(data).toEqual({ partial: true, value: 'z' });
		expect(cacheStatus).toBe('miss');
		expect(IN_MEMORY_CACHE.get('tracked:partial')).toBeUndefined();
	});
});
