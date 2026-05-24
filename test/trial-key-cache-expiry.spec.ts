// SPDX-License-Identifier: BUSL-1.1

/**
 * FIND-15: re-check trial-key expiry on tier-cache hit.
 *
 * A trial key cached as a valid tier must not bypass expiry enforcement
 * for the remainder of the cache TTL. The cache entry now stores
 * `trialExpiresAt`; the cache-hit branch re-checks it and evicts +
 * returns unauthenticated when it has passed.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('FIND-15 — trial-key expiry re-check on tier-cache hit', () => {
	it('returns unauthenticated when cached trialExpiresAt is in the past', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		// KV stub: return a trial-tier cache entry whose expiry is 1 second ago
		const kv = {
			get: vi.fn().mockResolvedValue(
				JSON.stringify({ tier: 'developer', revokedAt: null, trialExpiresAt: Date.now() - 1000 }),
			),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier('TOKEN', { RATE_LIMIT: kv } as unknown as Parameters<typeof resolveTier>[1], '203.0.113.1', 'https://t/mcp');

		expect(result.authenticated).toBe(false);
		// The stale cache entry must be deleted so the next request re-validates
		expect(kv.delete).toHaveBeenCalledWith(expect.stringMatching(/^tier:[a-f0-9]{64}$/));
	});

	it('authenticates when cached trialExpiresAt is in the future', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		// KV stub: trial expiry is 60 seconds from now
		const kv = {
			get: vi.fn().mockResolvedValue(
				JSON.stringify({ tier: 'developer', revokedAt: null, trialExpiresAt: Date.now() + 60_000 }),
			),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier('TOKEN', { RATE_LIMIT: kv } as unknown as Parameters<typeof resolveTier>[1], '203.0.113.1', 'https://t/mcp');

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('developer');
		// No eviction for a still-valid entry
		expect(kv.delete).not.toHaveBeenCalled();
	});
});
