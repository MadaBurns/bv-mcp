import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('tier-auth KV cache validation', () => {
	it('returns valid cached tier correctly', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(JSON.stringify({ tier: 'enterprise', revokedAt: null })),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier('test-token', { RATE_LIMIT: kv }, undefined, 'https://example.com/mcp');
		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('enterprise');
	});

	it('treats cached entry with invalid tier as cache miss', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(JSON.stringify({ tier: 'invalid_tier_value', revokedAt: null })),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		// No service binding, no BV_API_KEY — should fall through to unauthenticated
		const result = await resolveTier('test-token', { RATE_LIMIT: kv }, undefined, 'https://example.com/mcp');
		expect(result.authenticated).toBe(false);
		// Bad KV entry should be deleted
		expect(kv.delete).toHaveBeenCalled();
	});

	it('treats cached entry with missing tier field as cache miss', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(JSON.stringify({ revokedAt: null })),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier('test-token', { RATE_LIMIT: kv }, undefined, 'https://example.com/mcp');
		expect(result.authenticated).toBe(false);
		expect(kv.delete).toHaveBeenCalled();
	});

	it('treats cached entry with non-string tier as cache miss', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(JSON.stringify({ tier: 123, revokedAt: null })),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier('test-token', { RATE_LIMIT: kv }, undefined, 'https://example.com/mcp');
		expect(result.authenticated).toBe(false);
		expect(kv.delete).toHaveBeenCalled();
	});

	it('treats cached entry with non-number revokedAt as cache miss', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(JSON.stringify({ tier: 'enterprise', revokedAt: 'yesterday' })),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier('test-token', { RATE_LIMIT: kv }, undefined, 'https://example.com/mcp');
		expect(result.authenticated).toBe(false);
		expect(kv.delete).toHaveBeenCalled();
	});

	it('handles revoked entries correctly', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(JSON.stringify({ tier: 'free', revokedAt: Date.now() })),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier('test-token', { RATE_LIMIT: kv }, undefined, 'https://example.com/mcp');
		expect(result.authenticated).toBe(false);
		// Valid revokedAt structure, should NOT be deleted
		expect(kv.delete).not.toHaveBeenCalled();
	});

	it('accepts all valid McpApiKeyTier values', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const validTiers = ['free', 'agent', 'developer', 'enterprise', 'partner', 'owner'];

		for (const tier of validTiers) {
			const kv = {
				get: vi.fn().mockResolvedValue(JSON.stringify({ tier, revokedAt: null })),
				put: vi.fn(),
				delete: vi.fn(),
			} as unknown as KVNamespace;

			const result = await resolveTier(`token-for-${tier}`, { RATE_LIMIT: kv }, undefined, 'https://example.com/mcp');
			expect(result.authenticated).toBe(true);
			expect(result.tier).toBe(tier);
		}
	});

	it('downgrades cached owner tier when the request IP is outside OWNER_ALLOW_IPS', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(JSON.stringify({ tier: 'owner', revokedAt: null })),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier(
			'cached-owner-key',
			{ RATE_LIMIT: kv, OWNER_ALLOW_IPS: '203.0.113.10' },
			'198.51.100.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('partner');
	});

	it('authenticates a valid tier returned by the bv-web service binding', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(Response.json({ tier: 'developer' })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'service-bound-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('developer');
		expect(bvWeb.fetch).toHaveBeenCalledOnce();
		expect(kv.put).toHaveBeenCalledWith(
			`tier:${result.keyHash}`,
			JSON.stringify({ tier: 'developer', revokedAt: null }),
			{ expirationTtl: 300 },
		);
	});

	it('downgrades service-bound owner tier when the request IP is outside OWNER_ALLOW_IPS', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(Response.json({ tier: 'owner' })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'service-bound-owner-key',
			{
				RATE_LIMIT: kv,
				BV_WEB: bvWeb,
				BV_WEB_INTERNAL_KEY: 'internal-key',
				OWNER_ALLOW_IPS: '203.0.113.10',
			},
			'198.51.100.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('partner');
		expect(kv.put).toHaveBeenCalledWith(
			`tier:${result.keyHash}`,
			JSON.stringify({ tier: 'owner', revokedAt: null }),
			{ expirationTtl: 300 },
		);
	});

	it('treats null tier from bv-web as an unauthenticated revoked or unknown key', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(Response.json({ tier: null })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'unknown-service-bound-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(false);
		expect(bvWeb.fetch).toHaveBeenCalledOnce();
		const putArgs = vi.mocked(kv.put).mock.calls[0];
		expect(putArgs[0]).toMatch(/^tier:[a-f0-9]{64}$/);
		expect(JSON.parse(String(putArgs[1]))).toEqual({ tier: 'free', revokedAt: expect.any(Number) });
		expect(putArgs[2]).toEqual({ expirationTtl: 300 });
	});

	it('downgrades BV_INTERNAL_DEV_KEY when the request IP is outside OWNER_ALLOW_IPS', async () => {
		// Internal static keys are production bearer credentials too. When
		// OWNER_ALLOW_IPS is configured, every owner-tier path must enforce it.
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier(
			'dev-key-secret',
			{
				RATE_LIMIT: kv,
				BV_INTERNAL_DEV_KEY: 'dev-key-secret',
				OWNER_ALLOW_IPS: '203.0.113.10',
			},
			'198.51.100.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('partner');
	});

	it('keeps BV_INTERNAL_DEV_KEY at owner tier when the request IP is allowlisted', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier(
			'dev-key-secret',
			{
				RATE_LIMIT: kv,
				BV_INTERNAL_DEV_KEY: 'dev-key-secret',
				OWNER_ALLOW_IPS: '203.0.113.10',
			},
			'203.0.113.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('owner');
	});

	it('BV_INTERNAL_DEV_KEY wins over a stale cache and over a bv-web validate-key result, then applies OWNER_ALLOW_IPS', async () => {
		// The dev key is an internal static secret — it must be authoritative
		// before the KV cache or bv-web validate-key fallback can demote it.
		// Otherwise a prior IP-gated resolution can poison the cache and the
		// dev key gets stuck at partner-tier until the entry expires.
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(JSON.stringify({ tier: 'partner', revokedAt: null })),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(Response.json({ tier: 'developer' })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'dev-key-secret',
			{
				RATE_LIMIT: kv,
				BV_WEB: bvWeb,
				BV_WEB_INTERNAL_KEY: 'internal-key',
				BV_INTERNAL_DEV_KEY: 'dev-key-secret',
				OWNER_ALLOW_IPS: '203.0.113.10',
			},
			'198.51.100.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('partner');
		// Dev-key resolution must not depend on the bv-web round-trip — it's a
		// hardcoded internal secret.
		expect(bvWeb.fetch).not.toHaveBeenCalled();
	});

	it('keeps BV_API_KEY (customer-facing) IP-gated to partner when client IP is outside OWNER_ALLOW_IPS', async () => {
		// Regression guard: dev-key bypass must NOT extend to BV_API_KEY.
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier(
			'customer-api-key',
			{
				RATE_LIMIT: kv,
				BV_API_KEY: 'customer-api-key',
				OWNER_ALLOW_IPS: '203.0.113.10',
			},
			'198.51.100.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('partner');
	});

	it('does not negative-cache malformed bv-web validation responses', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(Response.json({ tier: 'invalid-tier' })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'malformed-service-bound-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(false);
		expect(bvWeb.fetch).toHaveBeenCalledOnce();
		expect(kv.put).not.toHaveBeenCalled();
	});
});

describe('tier-auth LKG (last-known-good) fallback', () => {
	// ─── LKG WRITE on success ──────────────────────────────────────────────────

	it('writes tier:lkg:{keyHash} with expirationTtl 86400 on successful bv-web resolution', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(Response.json({ tier: 'enterprise' })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'lkg-success-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('enterprise');

		// Must write the short-lived cache entry AND the long-lived LKG entry
		const putCalls = vi.mocked(kv.put).mock.calls;
		const lkgCall = putCalls.find((c) => c[0] === `tier:lkg:${result.keyHash}`);
		expect(lkgCall).toBeDefined();
		expect(lkgCall![1]).toBe('enterprise');
		expect(lkgCall![2]).toEqual({ expirationTtl: 86400 });
	});

	it('does not write LKG for null tier (definitive revocation) from bv-web', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(Response.json({ tier: null })),
		} as unknown as Fetcher;

		await resolveTier(
			'revoked-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		const putCalls = vi.mocked(kv.put).mock.calls;
		const lkgCall = putCalls.find((c) => String(c[0]).startsWith('tier:lkg:'));
		expect(lkgCall).toBeUndefined();
	});

	// ─── LKG READ when bv-web throws (network/connection failure) ─────────────

	it('returns LKG tier when bv-web throws (network error) and LKG entry exists', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const keyHash = await (async () => {
			// Pre-compute keyHash for 'lkg-throw-key' to build the correct KV mock
			const raw = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('lkg-throw-key')));
			return Array.from(raw)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');
		})();

		const kv = {
			get: vi.fn((key: string) => {
				if (key === `tier:lkg:${keyHash}`) return Promise.resolve('developer');
				return Promise.resolve(null); // no short-lived cache
			}),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockRejectedValue(new Error('network error')),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'lkg-throw-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('developer');
		expect(result.keyHash).toBe(keyHash);
	});

	it('falls through to BV_API_KEY when bv-web throws and no LKG entry exists', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null), // no cache, no LKG
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockRejectedValue(new Error('network error')),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'no-lkg-throw-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		// No LKG, no BV_API_KEY match → falls through to unauthenticated
		expect(result.authenticated).toBe(false);
	});

	// ─── LKG READ when bv-web returns a 5xx (server error / outage) ──────────
	// NOTE: fetch() resolves on HTTP errors — 5xx does NOT throw, it returns a
	// Response with response.ok === false. A catch-only implementation misses this
	// case. Both ambiguous-failure branches must consult LKG.

	it('returns LKG tier when bv-web returns 503 and LKG entry exists', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const keyHash = await (async () => {
			const raw = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('lkg-503-key')));
			return Array.from(raw)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');
		})();

		const kv = {
			get: vi.fn((key: string) => {
				if (key === `tier:lkg:${keyHash}`) return Promise.resolve('enterprise');
				return Promise.resolve(null);
			}),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(new Response('Service Unavailable', { status: 503 })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'lkg-503-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('enterprise');
		expect(result.keyHash).toBe(keyHash);
	});

	it('falls through to unauthenticated when bv-web returns 503 and no LKG entry exists', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(new Response('Service Unavailable', { status: 503 })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'no-lkg-503-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(false);
	});

	// ─── 4xx is definitive — LKG must NOT be consulted ────────────────────────

	it('does not serve LKG when bv-web returns 401 (definitive rejection)', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const keyHash = await (async () => {
			const raw = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('lkg-401-key')));
			return Array.from(raw)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');
		})();

		const kv = {
			get: vi.fn((key: string) => {
				// LKG entry exists — but should NOT be used for a 4xx response
				if (key === `tier:lkg:${keyHash}`) return Promise.resolve('enterprise');
				return Promise.resolve(null);
			}),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(new Response('Unauthorized', { status: 401 })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'lkg-401-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(false);
	});

	// ─── OWNER_ALLOW_IPS gate applied to LKG tier ─────────────────────────────

	it('applies OWNER_ALLOW_IPS gate to the tier returned from LKG on bv-web throw', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const keyHash = await (async () => {
			const raw = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('lkg-owner-gate-key')));
			return Array.from(raw)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');
		})();

		const kv = {
			get: vi.fn((key: string) => {
				if (key === `tier:lkg:${keyHash}`) return Promise.resolve('owner');
				return Promise.resolve(null);
			}),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockRejectedValue(new Error('unreachable')),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'lkg-owner-gate-key',
			{
				RATE_LIMIT: kv,
				BV_WEB: bvWeb,
				BV_WEB_INTERNAL_KEY: 'internal-key',
				OWNER_ALLOW_IPS: '203.0.113.10',
			},
			'198.51.100.10', // NOT in allowlist
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('partner'); // downgraded from owner
	});

	// ─── Definitive "no entitlement" — LKG must NOT be consulted ─────────────

	it('does not consult LKG when bv-web returns definitive null tier (revocation)', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const keyHash = await (async () => {
			const raw = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('revoked-lkg-key')));
			return Array.from(raw)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join('');
		})();

		const kv = {
			get: vi.fn((key: string) => {
				// LKG entry exists — should NOT be consulted on a definitive null response
				if (key === `tier:lkg:${keyHash}`) return Promise.resolve('enterprise');
				return Promise.resolve(null);
			}),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(Response.json({ tier: null })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'revoked-lkg-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		// Definitive revocation must still downgrade, even if LKG says 'enterprise'
		expect(result.authenticated).toBe(false);
	});
});

describe('tier-auth second internal dev key (BV_INTERNAL_DEV_KEY_2)', () => {
	it('resolves BV_INTERNAL_DEV_KEY_2 to owner tier when the request IP is allowlisted', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier(
			'second-dev-key-secret',
			{
				RATE_LIMIT: kv,
				BV_INTERNAL_DEV_KEY_2: 'second-dev-key-secret',
				OWNER_ALLOW_IPS: '203.0.113.10',
			},
			'203.0.113.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('owner');
	});

	it('downgrades BV_INTERNAL_DEV_KEY_2 to partner when the request IP is outside OWNER_ALLOW_IPS', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier(
			'second-dev-key-secret',
			{
				RATE_LIMIT: kv,
				BV_INTERNAL_DEV_KEY_2: 'second-dev-key-secret',
				OWNER_ALLOW_IPS: '203.0.113.10',
			},
			'198.51.100.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('partner');
	});

	it('treats BV_INTERNAL_DEV_KEY_2 as authoritative over a stale cache and a bv-web validate-key result', async () => {
		// Same invariant as the primary dev key: an internal static secret must be
		// resolved before the KV cache or bv-web fallback can demote it.
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(JSON.stringify({ tier: 'partner', revokedAt: null })),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(Response.json({ tier: 'developer' })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'second-dev-key-secret',
			{
				RATE_LIMIT: kv,
				BV_WEB: bvWeb,
				BV_WEB_INTERNAL_KEY: 'internal-key',
				BV_INTERNAL_DEV_KEY_2: 'second-dev-key-secret',
				OWNER_ALLOW_IPS: '203.0.113.10',
			},
			'203.0.113.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('owner');
		expect(bvWeb.fetch).not.toHaveBeenCalled();
	});

	it('keeps the primary BV_INTERNAL_DEV_KEY working when both dev keys are configured', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier(
			'primary-dev-key-secret',
			{
				RATE_LIMIT: kv,
				BV_INTERNAL_DEV_KEY: 'primary-dev-key-secret',
				BV_INTERNAL_DEV_KEY_2: 'second-dev-key-secret',
				OWNER_ALLOW_IPS: '203.0.113.10',
			},
			'203.0.113.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('owner');
	});

	it('does not authenticate a token that matches neither dev key', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;

		const result = await resolveTier(
			'not-a-dev-key',
			{
				RATE_LIMIT: kv,
				BV_INTERNAL_DEV_KEY: 'primary-dev-key-secret',
				BV_INTERNAL_DEV_KEY_2: 'second-dev-key-secret',
				OWNER_ALLOW_IPS: '203.0.113.10',
			},
			'203.0.113.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(false);
	});
});
