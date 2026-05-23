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
