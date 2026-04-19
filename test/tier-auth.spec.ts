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
		const validTiers = ['free', 'agent', 'developer', 'enterprise', 'partner'];

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
});
