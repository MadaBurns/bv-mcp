// SPDX-License-Identifier: BUSL-1.1

import { INFLIGHT_CLEANUP_MS } from './config';
import { logError } from './log';

/**
 * TTL cache for DNS scan results.
 *
 * Uses Cloudflare KV for persistent caching when available,
 * with in-memory fallback when KV is not configured.
 *
 * Cloudflare Workers compatible - no Node.js APIs.
 */

interface CacheEntry<T> {
	value: T;
	expiresAt: number;
}

interface CacheOptions {
	/** Time-to-live in milliseconds. Default: 5 minutes (300_000ms) */
	ttlMs?: number;
	/** Maximum number of entries. Default: 1000 */
	maxEntries?: number;
}

const DEFAULT_TTL_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_TTL_SECONDS = 300; // 5 minutes in seconds (for KV expirationTtl)
const DEFAULT_MAX_ENTRIES = 1000;

export class TTLCache<T = unknown> {
	private readonly store = new Map<string, CacheEntry<T>>();
	private readonly ttlMs: number;
	private readonly maxEntries: number;

	constructor(options: CacheOptions = {}) {
		this.ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
		this.maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
	}

	/**
	 * Get a cached value by key. Returns undefined if not found or expired.
	 */
	get(key: string): T | undefined {
		const entry = this.store.get(key);
		if (!entry) {
			return undefined;
		}
		if (Date.now() > entry.expiresAt) {
			this.store.delete(key);
			return undefined;
		}
		return entry.value;
	}

	/**
	 * Set a value in the cache with optional custom TTL.
	 */
	set(key: string, value: T, ttlMs?: number): void {
		// Evict expired entries if at capacity
		if (this.store.size >= this.maxEntries && !this.store.has(key)) {
			this.evictExpired();
		}
		// If still at capacity after eviction, remove oldest entry
		if (this.store.size >= this.maxEntries && !this.store.has(key)) {
			const firstKey = this.store.keys().next().value;
			if (firstKey !== undefined) {
				this.store.delete(firstKey);
			}
		}
		this.store.set(key, {
			value,
			expiresAt: Date.now() + (ttlMs ?? this.ttlMs),
		});
	}

	/**
	 * Check if a key exists and is not expired.
	 */
	has(key: string): boolean {
		return this.get(key) !== undefined;
	}

	/**
	 * Delete a specific key from the cache.
	 */
	delete(key: string): boolean {
		return this.store.delete(key);
	}

	/**
	 * Remove all entries from the cache.
	 */
	clear(): void {
		this.store.clear();
	}

	/**
	 * Get the number of entries (including potentially expired ones).
	 */
	get size(): number {
		return this.store.size;
	}

	/**
	 * Remove all expired entries from the cache.
	 */
	evictExpired(): number {
		const now = Date.now();
		let evicted = 0;
		for (const [key, entry] of this.store) {
			if (now > entry.expiresAt) {
				this.store.delete(key);
				evicted++;
			}
		}
		return evicted;
	}
}

/** In-flight promise map for cache stampede (thundering herd) protection */
const INFLIGHT = new Map<string, Promise<unknown>>();

/** In-memory cache instance used as fallback when KV is unavailable */
export const IN_MEMORY_CACHE = new TTLCache<unknown>({
	ttlMs: DEFAULT_TTL_MS,
	maxEntries: DEFAULT_MAX_ENTRIES,
});

// ---------------------------------------------------------------------------
// KV-backed cache functions
// ---------------------------------------------------------------------------

/**
 * Get a cached value by key.
 * Uses KV when available, falls back to in-memory.
 *
 * @param key - Cache key
 * @param kv - Optional KV namespace for persistent caching
 */
export async function cacheGet<T>(key: string, kv?: KVNamespace): Promise<T | undefined> {
       if (kv) {
	       try {
		       const val = await kv.get(key, 'json');
		       return (val ?? undefined) as T | undefined; // KV.get('json') returns unknown; generic T is caller-enforced
	       } catch {
		       // KV error — log warning and fall through to in-memory
		       logError('[cache] KV get failed, falling back to in-memory');
	       }
       }
       return IN_MEMORY_CACHE.get(key) as T | undefined;
}

/**
 * Set a cached value with configurable TTL.
 * Uses KV when available, falls back to in-memory.
 *
 * @param key - Cache key
 * @param value - Value to cache (must be JSON-serializable for KV)
 * @param kv - Optional KV namespace for persistent caching
 * @param ttlSeconds - Cache TTL in seconds (default: 300 = 5 minutes)
 */
/**
 * Set a cached value, deferring the KV write via ctx.waitUntil() to avoid blocking the response.
 * Falls back to synchronous cacheSet when no ExecutionContext is provided.
 */
export function cacheSetDeferred(key: string, value: unknown, ctx: ExecutionContext, kv?: KVNamespace, ttlSeconds?: number): void {
	ctx.waitUntil(cacheSet(key, value, kv, ttlSeconds));
}

export async function cacheSet(key: string, value: unknown, kv?: KVNamespace, ttlSeconds?: number): Promise<void> {
       const ttl = ttlSeconds ?? DEFAULT_TTL_SECONDS;
       if (kv) {
	       try {
		       await kv.put(key, JSON.stringify(value), { expirationTtl: ttl });
		       return;
	       } catch {
		       // KV error — log warning and fall through to in-memory
		       logError('[cache] KV put failed, falling back to in-memory');
	       }
       }
       IN_MEMORY_CACHE.set(key, value, ttl * 1000);
}

/**
 * Run a function with cache-aside logic: returns cached value if available,
 * otherwise executes the function and caches the result.
 * Includes in-flight deduplication to prevent cache stampedes.
 *
 * When KV is available, uses a sentinel key (`key:computing`) for cross-isolate
 * deduplication. If another isolate is already computing, polls KV for the result
 * with exponential backoff before falling back to re-execution.
 *
 * @param key - Cache key
 * @param run - Async function to execute on cache miss
 * @param kv - Optional KV namespace for persistent caching
 * @param ttlSeconds - Cache TTL in seconds (default: 300 = 5 minutes)
 * @param skipCache - When true, bypass cache lookup and always execute the function (result is still cached)
 * @returns The cached or freshly computed result
 */
export async function runWithCache<T>(key: string, run: () => Promise<T>, kv?: KVNamespace, ttlSeconds?: number, skipCache?: boolean): Promise<T> {
	if (!skipCache) {
		const cached = await cacheGet<T>(key, kv);
		if (cached !== undefined) return cached;
	}

	// Per-isolate INFLIGHT dedup (same as before)
	const existing = INFLIGHT.get(key);
	if (existing) return existing as Promise<T>;

	// Cross-isolate dedup via KV sentinel (best-effort)
	if (kv && !skipCache) {
		const sentinelKey = `${key}:computing`;
		try {
			const sentinel = await kv.get(sentinelKey);
			if (sentinel) {
				// Another isolate is computing — poll for result
				const polled = await pollForResult<T>(key, kv);
				if (polled !== undefined) return polled;
				// Poll exhausted — fall through and re-execute (acceptable double-execution)
			} else {
				// Claim the computation
				await kv.put(sentinelKey, String(Date.now()), { expirationTtl: SENTINEL_TTL_SECONDS });
			}
		} catch {
			// KV error — proceed without cross-isolate dedup
		}
	}

	const cleanup = setTimeout(() => INFLIGHT.delete(key), INFLIGHT_CLEANUP_MS);
	const promise = run()
		.then(async (result) => {
			await cacheSet(key, result, kv, ttlSeconds);
			// Clean up sentinel
			if (kv) {
				try { await kv.delete(`${key}:computing`); } catch { /* best-effort */ }
			}
			return result;
		})
		.catch(async (err) => {
			// Clean up sentinel on failure
			if (kv) {
				try { await kv.delete(`${key}:computing`); } catch { /* best-effort */ }
			}
			throw err;
		})
		.finally(() => {
			clearTimeout(cleanup);
			INFLIGHT.delete(key);
		});

	INFLIGHT.set(key, promise);
	return promise;
}

/** Sentinel TTL — matches INFLIGHT_CLEANUP_MS in seconds. */
const SENTINEL_TTL_SECONDS = 30;

/** Poll intervals for cross-isolate dedup (exponential backoff). */
const POLL_DELAYS_MS = [500, 1000, 2000];

/** Poll KV for a result with exponential backoff. */
async function pollForResult<T>(key: string, kv: KVNamespace): Promise<T | undefined> {
	for (const delay of POLL_DELAYS_MS) {
		await new Promise((r) => setTimeout(r, delay));
		try {
			const val = await kv.get(key, 'json');
			if (val !== null) return val as T;
		} catch {
			return undefined; // KV error — stop polling
		}
	}
	return undefined;
}
