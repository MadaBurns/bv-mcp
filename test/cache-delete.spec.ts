// SPDX-License-Identifier: BUSL-1.1

/**
 * `cacheDelete` removes a key from the in-memory store and, when a KV namespace is supplied,
 * from KV too. KV failures are swallowed (best-effort) and never leave the in-memory copy behind.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import { IN_MEMORY_CACHE, cacheDelete, cacheGet, cacheSet } from '../src/lib/cache';

afterEach(() => {
	IN_MEMORY_CACHE.clear();
});

function fakeKv(deleteImpl: (key: string) => Promise<void>) {
	const del = vi.fn(deleteImpl);
	return { kv: { delete: del } as unknown as KVNamespace, del };
}

describe('cacheDelete', () => {
	it('removes the in-memory entry when no KV namespace is given', async () => {
		await cacheSet('k-mem', { v: 1 }, undefined, 30);
		expect(await cacheGet('k-mem')).toEqual({ v: 1 });

		await cacheDelete('k-mem');

		expect(await cacheGet('k-mem')).toBeUndefined();
	});

	it('deletes the key from KV as well as memory', async () => {
		const { kv, del } = fakeKv(async () => undefined);
		await cacheSet('k-both', 'cached', undefined, 30);

		await cacheDelete('k-both', kv);

		expect(del).toHaveBeenCalledTimes(1);
		expect(del).toHaveBeenCalledWith('k-both');
		expect(IN_MEMORY_CACHE.get('k-both')).toBeUndefined();
	});

	it('swallows a KV delete failure and still clears memory', async () => {
		const { kv, del } = fakeKv(async () => {
			throw new Error('KV unavailable');
		});
		await cacheSet('k-err', 'cached', undefined, 30);

		await expect(cacheDelete('k-err', kv)).resolves.toBeUndefined();

		expect(del).toHaveBeenCalledTimes(1);
		expect(IN_MEMORY_CACHE.get('k-err')).toBeUndefined();
	});
});
