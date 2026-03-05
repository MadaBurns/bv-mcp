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
const inflight = new Map<string, Promise<unknown>>();

/** In-memory cache instance used as fallback when KV is unavailable */
export const inMemoryCache = new TTLCache<unknown>({
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
		       return (val ?? undefined) as T | undefined;
	       } catch (err) {
		       // KV error — log warning and fall through to in-memory
		       console.warn('[cache] KV get failed, falling back to in-memory:', (err instanceof Error ? err.message : err));
	       }
       }
       return inMemoryCache.get(key) as T | undefined;
}

/**
 * Set a cached value with 5-minute TTL.
 * Uses KV when available, falls back to in-memory.
 *
 * @param key - Cache key
 * @param value - Value to cache (must be JSON-serializable for KV)
 * @param kv - Optional KV namespace for persistent caching
 */
export async function cacheSet(key: string, value: unknown, kv?: KVNamespace): Promise<void> {
       if (kv) {
	       try {
		       await kv.put(key, JSON.stringify(value), { expirationTtl: DEFAULT_TTL_SECONDS });
		       return;
	       } catch (err) {
		       // KV error — log warning and fall through to in-memory
		       console.warn('[cache] KV put failed, falling back to in-memory:', (err instanceof Error ? err.message : err));
	       }
       }
       inMemoryCache.set(key, value);
}

/**
 * Run a function with cache-aside logic: returns cached value if available,
 * otherwise executes the function and caches the result.
 * Includes in-flight deduplication to prevent cache stampedes.
 *
 * @param key - Cache key
 * @param run - Async function to execute on cache miss
 * @param kv - Optional KV namespace for persistent caching
 * @returns The cached or freshly computed result
 */
export async function runWithCache<T>(key: string, run: () => Promise<T>, kv?: KVNamespace): Promise<T> {
	const cached = await cacheGet<T>(key, kv);
	if (cached !== undefined) return cached;

	const existing = inflight.get(key);
	if (existing) return existing as Promise<T>;

	const promise = run()
		.then(async (result) => {
			await cacheSet(key, result, kv);
			return result;
		})
		.finally(() => {
			inflight.delete(key);
		});

	inflight.set(key, promise);
	return promise;
}
