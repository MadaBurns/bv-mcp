import { describe, it, expect, vi, afterEach } from 'vitest';
import { TTLCache, cacheGet, cacheSet, runWithCache, IN_MEMORY_CACHE } from '../src/lib/cache';

afterEach(() => {
	vi.restoreAllMocks();
	IN_MEMORY_CACHE.clear();
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
		IN_MEMORY_CACHE.set('key1', 'memval');
		const result = await cacheGet<string>('key1');
		expect(result).toBe('memval');
	});

	it('without KV: cacheSet writes to in-memory cache', async () => {
		await cacheSet('key2', 'written');
		expect(IN_MEMORY_CACHE.get('key2')).toBe('written');
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
		IN_MEMORY_CACHE.set('fallback', 'inmem');
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
		expect(IN_MEMORY_CACHE.get('errkey')).toBe('errval');
	});

	it('IN_MEMORY_CACHE is the global in-memory TTLCache instance', () => {
		expect(IN_MEMORY_CACHE).toBeInstanceOf(TTLCache);
		IN_MEMORY_CACHE.set('test', 'val');
		expect(IN_MEMORY_CACHE.get('test')).toBe('val');
	});
});

describe('runWithCache', () => {
	it('returns cached value when available', async () => {
		IN_MEMORY_CACHE.set('rw:hit', 'cached-value');
		const run = vi.fn().mockResolvedValue('fresh-value');
		const result = await runWithCache('rw:hit', run);
		expect(result).toBe('cached-value');
		expect(run).not.toHaveBeenCalled();
	});

	it('calls run() and caches result on cache miss', async () => {
		const run = vi.fn().mockResolvedValue('computed');
		const result = await runWithCache('rw:miss', run);
		expect(result).toBe('computed');
		expect(run).toHaveBeenCalledOnce();
		// Value should now be in cache
		expect(IN_MEMORY_CACHE.get('rw:miss')).toBe('computed');
	});

	it('passes custom ttlSeconds to cacheSet', async () => {
		const mockKV = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
		};
		const run = vi.fn().mockResolvedValue('data');
		await runWithCache('rw:ttl', run, mockKV as unknown as KVNamespace, 600);
		expect(mockKV.put).toHaveBeenCalledWith('rw:ttl', JSON.stringify('data'), { expirationTtl: 600 });
	});

	it('bypasses cache when skipCache is true', async () => {
		IN_MEMORY_CACHE.set('rw:skip', 'stale');
		const run = vi.fn().mockResolvedValue('fresh');
		const result = await runWithCache('rw:skip', run, undefined, undefined, true);
		expect(result).toBe('fresh');
		expect(run).toHaveBeenCalledOnce();
		// The fresh value should now be cached
		expect(IN_MEMORY_CACHE.get('rw:skip')).toBe('fresh');
	});

	it('uses cache when skipCache is false (default)', async () => {
		IN_MEMORY_CACHE.set('rw:noskip', 'cached');
		const run = vi.fn().mockResolvedValue('fresh');
		const result = await runWithCache('rw:noskip', run, undefined, undefined, false);
		expect(result).toBe('cached');
		expect(run).not.toHaveBeenCalled();
	});
});

describe('runWithCache — cross-isolate dedup', () => {
	it('writes sentinel to KV before executing on cache miss', async () => {
		const mockKV = {
			get: vi.fn()
				.mockResolvedValueOnce(null)  // cacheGet
				.mockResolvedValueOnce(null), // sentinel check
			put: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		const run = vi.fn().mockResolvedValue('computed');
		await runWithCache('sentinel:write', run, mockKV as unknown as KVNamespace);
		expect(run).toHaveBeenCalledOnce();
		// Sentinel was written (second put call — first is the result cache write)
		const sentinelPut = mockKV.put.mock.calls.find(
			(c: [string, string, Record<string, unknown>]) => c[0] === 'sentinel:write:computing'
		);
		expect(sentinelPut).toBeDefined();
	});

	it('writes sentinel with 10-second TTL', async () => {
		const mockKV = {
			get: vi.fn()
				.mockResolvedValueOnce(null)  // cacheGet
				.mockResolvedValueOnce(null), // sentinel check
			put: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		const run = vi.fn().mockResolvedValue('result');
		await runWithCache('sentinel:ttl', run, mockKV as unknown as KVNamespace);
		const sentinelPut = mockKV.put.mock.calls.find(
			(c: [string, string, Record<string, unknown>]) => c[0] === 'sentinel:ttl:computing'
		);
		expect(sentinelPut).toBeDefined();
		// Sentinel TTL should be 10 seconds (tightened from 30s)
		expect(sentinelPut![2]).toEqual({ expirationTtl: 10 });
	});

	it('cleans up sentinel after successful computation', async () => {
		const mockKV = {
			get: vi.fn()
				.mockResolvedValueOnce(null)  // cacheGet
				.mockResolvedValueOnce(null), // sentinel check
			put: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		const run = vi.fn().mockResolvedValue('result');
		await runWithCache('sentinel:cleanup', run, mockKV as unknown as KVNamespace);
		expect(mockKV.delete).toHaveBeenCalledWith('sentinel:cleanup:computing');
	});

	it('cleans up sentinel on computation failure', async () => {
		const mockKV = {
			get: vi.fn()
				.mockResolvedValueOnce(null)  // cacheGet
				.mockResolvedValueOnce(null), // sentinel check
			put: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		const run = vi.fn().mockRejectedValue(new Error('fail'));
		await expect(runWithCache('sentinel:fail', run, mockKV as unknown as KVNamespace)).rejects.toThrow('fail');
		expect(mockKV.delete).toHaveBeenCalledWith('sentinel:fail:computing');
	});

	it('polls and returns result when sentinel exists and result appears', async () => {
		const mockKV = {
			get: vi.fn()
				.mockResolvedValueOnce(null)       // cacheGet — no cached result
				.mockResolvedValueOnce('12345')     // sentinel exists (another isolate computing)
				.mockResolvedValueOnce('polled-result'), // poll attempt 1 succeeds
			put: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		const run = vi.fn().mockResolvedValue('should-not-run');
		const result = await runWithCache('sentinel:poll', run, mockKV as unknown as KVNamespace);
		expect(result).toBe('polled-result');
		expect(run).not.toHaveBeenCalled();
	});

	it('falls back to execution when polling exhausts without result (3 polls)', async () => {
		const mockKV = {
			get: vi.fn()
				.mockResolvedValueOnce(null)   // cacheGet — no cached result
				.mockResolvedValueOnce('12345') // sentinel exists
				.mockResolvedValueOnce(null)    // poll 1 (250ms) — nothing
				.mockResolvedValueOnce(null)    // poll 2 (500ms) — nothing
				.mockResolvedValueOnce(null),   // poll 3 (750ms) — nothing
			put: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		const run = vi.fn().mockResolvedValue('fallback-executed');
		const result = await runWithCache('sentinel:exhaust', run, mockKV as unknown as KVNamespace);
		expect(result).toBe('fallback-executed');
		expect(run).toHaveBeenCalledOnce();
	});

	it('skips sentinel logic when KV is unavailable', async () => {
		const run = vi.fn().mockResolvedValue('no-kv');
		const result = await runWithCache('sentinel:nokv', run);
		expect(result).toBe('no-kv');
		expect(run).toHaveBeenCalledOnce();
	});

	it('skips sentinel logic when skipCache is true', async () => {
		const mockKV = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		const run = vi.fn().mockResolvedValue('forced');
		const result = await runWithCache('sentinel:skip', run, mockKV as unknown as KVNamespace, undefined, true);
		expect(result).toBe('forced');
		// Sentinel check should NOT have been called (only the result cache put)
		const sentinelCheck = mockKV.get.mock.calls.find(
			(c: [string, ...unknown[]]) => c[0] === 'sentinel:skip:computing'
		);
		expect(sentinelCheck).toBeUndefined();
	});

	it('degrades gracefully when KV sentinel operations fail', async () => {
		const mockKV = {
			get: vi.fn()
				.mockResolvedValueOnce(null)          // cacheGet
				.mockRejectedValueOnce(new Error('KV down')), // sentinel check fails
			put: vi.fn().mockResolvedValue(undefined),
			delete: vi.fn().mockResolvedValue(undefined),
		};
		const run = vi.fn().mockResolvedValue('degraded-ok');
		const result = await runWithCache('sentinel:degrade', run, mockKV as unknown as KVNamespace);
		expect(result).toBe('degraded-ok');
		expect(run).toHaveBeenCalledOnce();
	});
});

describe('runWithCache sentinel lifecycle', () => {
	function makeMockKv() {
		const store = new Map<string, { value: string; expiresAt?: number }>();
		const writeLog: Array<{ key: string; value: string; ttl?: number; op: 'put' | 'delete' }> = [];
		const kv = {
			async get(key: string) {
				const e = store.get(key);
				if (!e) return null;
				if (e.expiresAt && Date.now() > e.expiresAt) {
					store.delete(key);
					return null;
				}
				return e.value;
			},
			async put(key: string, value: string, opts?: { expirationTtl?: number }) {
				const expiresAt = opts?.expirationTtl ? Date.now() + opts.expirationTtl * 1000 : undefined;
				store.set(key, { value, expiresAt });
				writeLog.push({ key, value, ttl: opts?.expirationTtl, op: 'put' });
			},
			async delete(key: string) {
				store.delete(key);
				writeLog.push({ key, value: '', op: 'delete' });
			},
		} as unknown as KVNamespace;
		return { kv, writeLog, store };
	}

	it('sentinel TTL is <= 10 seconds', async () => {
		const { kv, writeLog } = makeMockKv();
		const { runWithCache } = await import('../src/lib/cache');
		await runWithCache('sentinel-ttl-key', async () => ({ ok: true }), kv);
		const sentinelWrite = writeLog.find((e) => e.op === 'put' && e.key === 'sentinel-ttl-key:computing');
		expect(sentinelWrite).toBeDefined();
		expect(sentinelWrite!.ttl).toBeDefined();
		expect(sentinelWrite!.ttl!).toBeLessThanOrEqual(10);
	});

	it('sentinel is deleted in finally even when run() throws', async () => {
		const { kv, store } = makeMockKv();
		const { runWithCache } = await import('../src/lib/cache');
		await expect(runWithCache('sentinel-throw-key', async () => { throw new Error('boom'); }, kv)).rejects.toThrow('boom');
		expect(store.get('sentinel-throw-key:computing')).toBeUndefined();
	});

	it('sentinel delete happens AFTER result put (racing poller sees result first)', async () => {
		const { kv, writeLog } = makeMockKv();
		const { runWithCache } = await import('../src/lib/cache');
		await runWithCache('sentinel-order-key', async () => ({ hit: true }), kv);
		const putResultIdx = writeLog.findIndex((e) => e.op === 'put' && e.key === 'sentinel-order-key');
		const deleteSentinelIdx = writeLog.findIndex((e) => e.op === 'delete' && e.key === 'sentinel-order-key:computing');
		expect(putResultIdx).toBeGreaterThanOrEqual(0);
		expect(deleteSentinelIdx).toBeGreaterThanOrEqual(0);
		expect(deleteSentinelIdx).toBeGreaterThan(putResultIdx);
	});
});
