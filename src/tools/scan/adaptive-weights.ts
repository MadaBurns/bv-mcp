// SPDX-License-Identifier: BUSL-1.1

/**
 * ProfileAccumulator adaptive-weight fetch with its per-isolate in-memory cache.
 * Split out of scan-domain.ts (SQ-537) with no behaviour change. The cache is
 * module-level state: it lives ONLY here and scan-domain.ts re-exports the same
 * binding for tests.
 */

import type { AdaptiveWeightsResponse } from '../../lib/adaptive-weights';
import { disposeUnreadResponseBody, readJsonResponseCapped } from '../../lib/response-body';

const ADAPTIVE_WEIGHTS_MAX_BODY_BYTES = 128 * 1024;

/** In-memory cache for adaptive weight responses from the ProfileAccumulator DO. */
const adaptiveWeightCache = new Map<string, { weights: AdaptiveWeightsResponse; expires: number }>();

/** TTL for the in-memory adaptive weight cache (ms). */
const ADAPTIVE_CACHE_TTL_MS = 60_000;

/** Maximum entries in the adaptive weight cache before eviction. */
const ADAPTIVE_CACHE_MAX_ENTRIES = 100;

/** Timeout for fetching adaptive weights from the DO (ms). */
const ADAPTIVE_FETCH_TIMEOUT_MS = 200;

/**
 * Fetch adaptive weights from the ProfileAccumulator DO with in-memory caching.
 * Returns null on failure or timeout (silently falls back to static weights).
 */
export async function fetchAdaptiveWeights(
	accumulator: DurableObjectNamespace,
	profile: string,
	provider: string | null,
	shardName: string = 'global',
): Promise<AdaptiveWeightsResponse | null> {
	// Include the shard name in the cache key so a routing-mode change never
	// serves a stale cross-shard entry. Profile is already implied by shardName
	// in 'profile' mode but kept for the legacy 'global' shard.
	const cacheKey = `${shardName}:${profile}:${provider ?? ''}`;
	const now = Date.now();

	// Check in-memory cache first
	const cached = adaptiveWeightCache.get(cacheKey);
	if (cached && cached.expires > now) {
		return cached.weights;
	}

	try {
		const stub = accumulator.get(accumulator.idFromName(shardName));
		const url = new URL('https://do/weights');
		url.searchParams.set('profile', profile);
		if (provider) url.searchParams.set('provider', provider);

		const controller = new AbortController();
		const timeoutId = setTimeout(
			() => controller.abort(new DOMException('Adaptive weight fetch timed out', 'TimeoutError')),
			ADAPTIVE_FETCH_TIMEOUT_MS,
		);
		let response: Response;
		try {
			response = await stub.fetch(new Request(url.toString(), { signal: controller.signal }));
			if (!response.ok) {
				await disposeUnreadResponseBody(response);
				return null;
			}

			const data = await readJsonResponseCapped<AdaptiveWeightsResponse>(response, ADAPTIVE_WEIGHTS_MAX_BODY_BYTES);
			if (!data) return null;
			if (adaptiveWeightCache.size >= ADAPTIVE_CACHE_MAX_ENTRIES) {
				evictAdaptiveWeightCache();
			}
			adaptiveWeightCache.set(cacheKey, { weights: data, expires: now + ADAPTIVE_CACHE_TTL_MS });
			return data;
		} finally {
			clearTimeout(timeoutId);
		}
	} catch {
		return null;
	}
}

/**
 * Evict entries from the adaptive weight cache.
 * Removes expired entries first, then if still at capacity, evicts the entry with the oldest expiry time.
 */
export function evictAdaptiveWeightCache(): void {
	const now = Date.now();

	// First pass: remove all expired entries
	for (const [key, entry] of adaptiveWeightCache) {
		if (entry.expires <= now) {
			adaptiveWeightCache.delete(key);
		}
	}

	// If still at capacity after removing expired entries, evict the oldest by expiry
	if (adaptiveWeightCache.size >= ADAPTIVE_CACHE_MAX_ENTRIES) {
		let oldestKey: string | null = null;
		let oldestExpiry = Infinity;
		for (const [key, entry] of adaptiveWeightCache) {
			if (entry.expires < oldestExpiry) {
				oldestExpiry = entry.expires;
				oldestKey = key;
			}
		}
		if (oldestKey !== null) {
			adaptiveWeightCache.delete(oldestKey);
		}
	}
}

/** Exposed for testing only — do not use in production code. */
export const _adaptiveWeightCacheForTest = adaptiveWeightCache;
