// SPDX-License-Identifier: BUSL-1.1

import { INFLIGHT_CLEANUP_MS } from './config';
import { logError } from './log';
import { SERVER_VERSION } from './server-version';

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

// ---------------------------------------------------------------------------
// Versioned cache-key builders
// ---------------------------------------------------------------------------
//
// Every scan/check KV cache key embeds the server version (`cache:v<version>:`).
// Deliberate trade-off: each deploy bumps SERVER_VERSION, so ALL keys change and
// the cache cold-starts on the first request after a deploy. That is the correct
// behaviour — the bug this fixes was the opposite: domain-only keys kept serving
// stale pre-deploy results until the TTL expired, forcing a "scan a fresh domain
// to verify the fix is live" workaround. For this scanner's traffic the cold
// start is acceptable; correctness after deploy beats a few extra cache misses.
//
// Both call sites (handlers dispatch + scan-domain orchestrator) MUST use these
// helpers so the per-check and top-level keys stay version-consistent — the
// analyze_drift `baseline: "cached"` path reads the top-level scan key directly,
// so a drift between the two key shapes would silently break cached baselines.

/** Cache key prefix shared by scan and per-check results. */
export const CACHE_KEY_PREFIX = 'cache:';

/**
 * Build the versioned cache key for a single check result.
 * Shape: `cache:v<version>:<domain>:check:<checkName>`.
 *
 * @param version - Defaults to the live {@link SERVER_VERSION}; overridable for tests.
 */
export function buildCheckCacheKey(domain: string, checkName: string, version: string = SERVER_VERSION): string {
	return `${CACHE_KEY_PREFIX}v${version}:${domain}:check:${checkName}`;
}

/**
 * Build the versioned cache key for a top-level scan result.
 * Shape: `cache:v<version>:<domain>` (default profile) or
 * `cache:v<version>:<domain>:profile:<profile>` when an explicit profile is set.
 *
 * @param version - Defaults to the live {@link SERVER_VERSION}; overridable for tests.
 */
export function buildScanCacheKey(domain: string, profile?: string, version: string = SERVER_VERSION): string {
	const base = `${CACHE_KEY_PREFIX}v${version}:${domain}`;
	return profile ? `${base}:profile:${profile}` : base;
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
 * Delete a cached value by key from both KV and in-memory stores.
 * Best-effort: silently ignores KV errors.
 */
export async function cacheDelete(key: string, kv?: KVNamespace): Promise<void> {
	IN_MEMORY_CACHE.delete(key);
	if (kv) {
		try { await kv.delete(key); } catch { /* best-effort */ }
	}
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
 * @param shouldCache - Optional predicate. When provided and returns false for the computed
 *   result, the result is NOT written to KV / in-memory cache. Sentinel cleanup still runs.
 *   Used to suppress caching of partial results (e.g. lookalike timeouts) without the
 *   put-then-delete anti-pattern. See bv-web 2026-05-14 analytics remediation (cluster F5).
 * @param skipSentinel - When true, skips the cross-isolate KV sentinel (`key:computing`
 *   get/put/delete) while keeping the main-key cache read, INFLIGHT in-isolate dedup, and
 *   result write. Cuts 2 KV ops per check on high-volume low-contention paths (e.g. scan
 *   per-check, ~98% unique domains) where sentinel overhead exceeds the rare stampede it
 *   prevents. INFLIGHT still dedups concurrent calls within the same isolate.
 * @returns The cached or freshly computed result
 */
export async function runWithCache<T>(key: string, run: () => Promise<T>, kv?: KVNamespace, ttlSeconds?: number, skipCache?: boolean, shouldCache?: (result: T) => boolean, skipSentinel?: boolean): Promise<T> {
	if (!skipCache) {
		const cached = await cacheGet<T>(key, kv);
		if (cached !== undefined) return cached;
	}

	// Per-isolate INFLIGHT dedup (same as before)
	const existing = INFLIGHT.get(key);
	if (existing) return existing as Promise<T>;

	// Cross-isolate dedup via KV sentinel (best-effort)
	if (kv && !skipCache && !skipSentinel) {
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
			// Only persist if the caller's predicate accepts the result.
			// Default (no predicate) is to cache everything.
			if (!shouldCache || shouldCache(result)) {
				await cacheSet(key, result, kv, ttlSeconds);
			}
			// Clean up sentinel regardless — we still claimed the computation slot.
			if (kv && !skipSentinel) {
				try { await kv.delete(`${key}:computing`); } catch { /* best-effort */ }
			}
			return result;
		})
		.catch(async (err) => {
			// Clean up sentinel on failure
			if (kv && !skipSentinel) {
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

export interface CacheResult<T> {
	data: T;
	cacheStatus: 'hit' | 'miss';
}

/**
 * Like `runWithCache`, but returns cache hit/miss metadata alongside the result.
 * Used where callers need to report cache status (e.g. analytics).
 *
 * @param shouldCache - Optional predicate. When provided and returns false, the
 *   freshly-computed result is NOT written to KV. See {@link runWithCache} for context.
 */
export async function runWithCacheTracked<T>(
	key: string,
	run: () => Promise<T>,
	kv?: KVNamespace,
	ttlSeconds?: number,
	skipCache?: boolean,
	shouldCache?: (result: T) => boolean,
): Promise<CacheResult<T>> {
	if (!skipCache) {
		const cached = await cacheGet<T>(key, kv);
		if (cached !== undefined) return { data: cached, cacheStatus: 'hit' };
	}

	const data = await runWithCache(key, run, kv, ttlSeconds, true, shouldCache);
	return { data, cacheStatus: 'miss' };
}

/** Sentinel TTL — short-lived to avoid stale dedup locks. */
const SENTINEL_TTL_SECONDS = 10;

/** Poll intervals for cross-isolate dedup. */
const POLL_DELAYS_MS = [250, 500, 750];

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
