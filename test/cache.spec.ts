import { describe, it, expect, vi, afterEach } from 'vitest';
import { TTLCache, cacheGet, cacheSet, inMemoryCache, runWithCache } from '../src/lib/cache';

afterEach(() => {
	vi.restoreAllMocks();
	inMemoryCache.clear();
});

describe('TTLCache', () => {
	it('should store and retrieve values correctly', () => {
		const cache = new TTLCache<string>();
		cache.set('a', 'hello');
		expect(cache.get('a')).toBe('hello');
	});

	it('should return undefined for missing keys', () => {
		const cache = new TTLCache<string>();
		expect(cache.get('missing')).toBeUndefined();
	});

	it('should return undefined after TTL expires', () => {
		const now = Date.now();
		vi.spyOn(Date, 'now').mockReturnValue(now);
		const cache = new TTLCache<string>({ ttlMs: 100 });
		cache.set('a', 'value');
		expect(cache.get('a')).toBe('value');
		vi.spyOn(Date, 'now').mockReturnValue(now + 101);
		expect(cache.get('a')).toBeUndefined();
	});

	it('should override default TTL per set call', () => {
		const now = Date.now();
		vi.spyOn(Date, 'now').mockReturnValue(now);
		const cache = new TTLCache<string>({ ttlMs: 1000 });
		cache.set('short', 'val', 50);
		vi.spyOn(Date, 'now').mockReturnValue(now + 51);
		expect(cache.get('short')).toBeUndefined();
	});

	it('should return true for existing and false for missing/expired keys', () => {
		const now = Date.now();
		vi.spyOn(Date, 'now').mockReturnValue(now);
		const cache = new TTLCache<string>({ ttlMs: 100 });
		cache.set('a', 'val');
		expect(cache.has('a')).toBe(true);
		expect(cache.has('missing')).toBe(false);
		vi.spyOn(Date, 'now').mockReturnValue(now + 101);
		expect(cache.has('a')).toBe(false);
	});

	it('should remove entry and return true; return false for missing', () => {
		const cache = new TTLCache<string>();
		cache.set('a', 'val');
		expect(cache.delete('a')).toBe(true);
		expect(cache.delete('missing')).toBe(false);
	});

	it('delete removes entry so get returns undefined', () => {
		const cache = new TTLCache<string>();
		cache.set('a', 'val');
		cache.delete('a');
		expect(cache.get('a')).toBeUndefined();
		expect(cache.delete('a')).toBe(false);
	});

	it('clear empties all entries and size becomes 0', () => {
		const cache = new TTLCache<string>();
		cache.set('a', '1');
		cache.set('b', '2');
		expect(cache.size).toBe(2);
		cache.clear();
		expect(cache.size).toBe(0);
	});

	it('size returns correct count', () => {
		const cache = new TTLCache<string>();
		expect(cache.size).toBe(0);
		cache.set('a', '1');
		expect(cache.size).toBe(1);
		cache.set('b', '2');
		expect(cache.size).toBe(2);
	});

	it('evicts expired entries first when at maxEntries', () => {
		const now = Date.now();
		vi.spyOn(Date, 'now').mockReturnValue(now);

		const cache = new TTLCache<string>({ ttlMs: 100, maxEntries: 2 });
		cache.set('old', 'val1');
		cache.set('recent', 'val2');

		// Advance time so 'old' and 'recent' are expired
		vi.spyOn(Date, 'now').mockReturnValue(now + 101);
		cache.set('new', 'val3');

		// Expired entries should be evicted, only 'new' remains
		expect(cache.size).toBe(1);
		expect(cache.get('new')).toBe('val3');
	});

	it('removes oldest entry (FIFO) when at maxEntries and nothing expired', () => {
		const cache = new TTLCache<string>({ ttlMs: 60000, maxEntries: 2 });
		cache.set('first', 'a');
		cache.set('second', 'b');
		cache.set('third', 'c');

		// 'first' should have been evicted as oldest
		expect(cache.get('first')).toBeUndefined();
		expect(cache.get('second')).toBe('b');
		expect(cache.get('third')).toBe('c');
		expect(cache.size).toBe(2);
	});

	it('evictExpired returns count of evicted entries', () => {
		const now = Date.now();
		vi.spyOn(Date, 'now').mockReturnValue(now);

		const cache = new TTLCache<string>({ ttlMs: 100 });
		cache.set('a', '1');
		cache.set('b', '2');
		cache.set('c', '3');

		vi.spyOn(Date, 'now').mockReturnValue(now + 101);
		const evicted = cache.evictExpired();
		expect(evicted).toBe(3);
		expect(cache.size).toBe(0);
	});
});

describe('cacheGet / cacheSet (KV-backed)', () => {
	it('without KV: cacheGet returns value from in-memory cache', async () => {
		inMemoryCache.set('key1', 'memval');
		const result = await cacheGet<string>('key1');
		expect(result).toBe('memval');
	});

	it('without KV: cacheSet writes to in-memory cache', async () => {
		await cacheSet('key2', 'written');
		expect(inMemoryCache.get('key2')).toBe('written');
	});

	it('with KV: cacheGet returns value from KV', async () => {
		const mockKV = {
			get: vi.fn().mockResolvedValue({ data: 'from-kv' }),
			put: vi.fn(),
		};
		const result = await cacheGet<{ data: string }>('key', mockKV as unknown as KVNamespace);
		expect(result).toEqual({ data: 'from-kv' });
		expect(mockKV.get).toHaveBeenCalledWith('key', 'json');
	});

	it('with KV: cacheSet writes to KV with correct expirationTtl', async () => {
		const mockKV = {
			get: vi.fn(),
			put: vi.fn().mockResolvedValue(undefined),
		};
		await cacheSet('key', { val: 1 }, mockKV as unknown as KVNamespace);
		expect(mockKV.put).toHaveBeenCalledWith('key', JSON.stringify({ val: 1 }), { expirationTtl: 300 });
	});

	it('KV error on get: silently falls back to in-memory', async () => {
		inMemoryCache.set('fallback', 'inmem');
		const mockKV = {
			get: vi.fn().mockRejectedValue(new Error('KV failure')),
			put: vi.fn(),
		};
		const result = await cacheGet<string>('fallback', mockKV as unknown as KVNamespace);
		expect(result).toBe('inmem');
	});

	it('KV error on set: silently falls back to in-memory', async () => {
		const mockKV = {
			get: vi.fn(),
			put: vi.fn().mockRejectedValue(new Error('KV failure')),
		};
		await cacheSet('errkey', 'errval', mockKV as unknown as KVNamespace);
		expect(inMemoryCache.get('errkey')).toBe('errval');
	});

	it('inMemoryCache is the global in-memory TTLCache instance', () => {
		expect(inMemoryCache).toBeInstanceOf(TTLCache);
		inMemoryCache.set('test', 'val');
		expect(inMemoryCache.get('test')).toBe('val');
	});
});

describe('runWithCache (stampede protection)', () => {
	it('deduplicates concurrent calls for the same key', async () => {
		let callCount = 0;
		const run = () => {
			callCount++;
			return new Promise<string>((resolve) => setTimeout(() => resolve('result'), 50));
		};
		const [r1, r2, r3] = await Promise.all([
			runWithCache('dedup-test', run),
			runWithCache('dedup-test', run),
			runWithCache('dedup-test', run),
		]);
		expect(callCount).toBe(1);
		expect(r1).toBe('result');
		expect(r2).toBe('result');
		expect(r3).toBe('result');
	});

	it('allows new calls after previous in-flight promise resolves', async () => {
		let callCount = 0;
		const run = () => {
			callCount++;
			return Promise.resolve('value-' + callCount);
		};
		const r1 = await runWithCache('reuse-test', run);
		expect(r1).toBe('value-1');

		// Clear the cache so the second call actually runs
		inMemoryCache.clear();

		const r2 = await runWithCache('reuse-test', run);
		expect(r2).toBe('value-2');
		expect(callCount).toBe(2);
	});

	it('cleans up in-flight entry on rejection so retries work', async () => {
		let attempt = 0;
		const run = () => {
			attempt++;
			if (attempt === 1) return Promise.reject(new Error('fail'));
			return Promise.resolve('recovered');
		};

		await expect(runWithCache('fail-test', run)).rejects.toThrow('fail');

		const r2 = await runWithCache('fail-test', run);
		expect(r2).toBe('recovered');
		expect(attempt).toBe(2);
	});

	it('uses different keys independently', async () => {
		let countA = 0;
		let countB = 0;
		const runA = () => {
			countA++;
			return new Promise<string>((resolve) => setTimeout(() => resolve('a'), 50));
		};
		const runB = () => {
			countB++;
			return new Promise<string>((resolve) => setTimeout(() => resolve('b'), 50));
		};

		const [rA, rB] = await Promise.all([runWithCache('key-a', runA), runWithCache('key-b', runB)]);
		expect(rA).toBe('a');
		expect(rB).toBe('b');
		expect(countA).toBe(1);
		expect(countB).toBe(1);
	});
});
