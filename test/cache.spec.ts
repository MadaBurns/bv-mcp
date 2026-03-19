import { describe, it, expect, vi, afterEach } from 'vitest';
import { TTLCache, cacheGet, cacheSet, scanCache } from '../src/lib/cache';

afterEach(() => {
	vi.restoreAllMocks();
	scanCache.clear();
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
		scanCache.set('key1', 'memval');
		const result = await cacheGet<string>('key1');
		expect(result).toBe('memval');
	});

	it('without KV: cacheSet writes to in-memory cache', async () => {
		await cacheSet('key2', 'written');
		expect(scanCache.get('key2')).toBe('written');
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
		scanCache.set('fallback', 'inmem');
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
		expect(scanCache.get('errkey')).toBe('errval');
	});

	it('scanCache is the global in-memory TTLCache instance', () => {
		expect(scanCache).toBeInstanceOf(TTLCache);
		scanCache.set('test', 'val');
		expect(scanCache.get('test')).toBe('val');
	});
});
