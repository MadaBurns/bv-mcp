import { describe, it, expect, vi, afterEach } from 'vitest';
import { TTLCache, cacheGet, cacheSet } from '../src/lib/cache';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('TTLCache', () => {
	it('set/get stores and retrieves values correctly', () => {
		const cache = new TTLCache<string>();
		cache.set('a', 'hello');
		expect(cache.get('a')).toBe('hello');
	});

	it('get returns undefined for missing keys', () => {
		const cache = new TTLCache<string>();
		expect(cache.get('missing')).toBeUndefined();
	});

	it('returns undefined after TTL expires', () => {
		const now = Date.now();
		vi.spyOn(Date, 'now').mockReturnValue(now);

		const cache = new TTLCache<string>({ ttlMs: 100 });
		cache.set('a', 'value');
		expect(cache.get('a')).toBe('value');

		vi.spyOn(Date, 'now').mockReturnValue(now + 101);
		expect(cache.get('a')).toBeUndefined();
	});

	it('custom TTL per set call overrides default', () => {
		const now = Date.now();
		vi.spyOn(Date, 'now').mockReturnValue(now);

		const cache = new TTLCache<string>({ ttlMs: 1000 });
		cache.set('short', 'val', 50);

		vi.spyOn(Date, 'now').mockReturnValue(now + 51);
		expect(cache.get('short')).toBeUndefined();
	});

	it('has returns true for existing and false for missing/expired keys', () => {
		const now = Date.now();
		vi.spyOn(Date, 'now').mockReturnValue(now);

		const cache = new TTLCache<string>({ ttlMs: 100 });
		cache.set('a', 'val');
		expect(cache.has('a')).toBe(true);
		expect(cache.has('missing')).toBe(false);

		vi.spyOn(Date, 'now').mockReturnValue(now + 101);
		expect(cache.has('a')).toBe(false);
	});

	it('delete removes entry and returns true; returns false for missing', () => {
		const cache = new TTLCache<string>();
		cache.set('a', 'val');
		expect(cache.delete('a')).toBe(true);
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

describe('cacheGet / cacheSet', () => {
	it('cacheGet returns value from in-memory cache', async () => {
		await cacheSet('key1', 'memval');
		const result = await cacheGet<string>('key1');
		expect(result).toBe('memval');
	});

	it('cacheSet writes to in-memory cache', async () => {
		await cacheSet('key2', 'written');
		const result = await cacheGet<string>('key2');
		expect(result).toBe('written');
	});

	it('cacheGet returns undefined for missing keys', async () => {
		const result = await cacheGet<string>('nonexistent');
		expect(result).toBeUndefined();
	});
});
