import { describe, it, expect, vi, afterEach } from 'vitest';
import { resetAllRateLimits } from '../src/lib/rate-limiter';

afterEach(() => {
	resetAllRateLimits();
	vi.useRealTimers();
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
		expect(kv.put).toHaveBeenCalledWith(`tier:${result.keyHash}`, JSON.stringify({ tier: 'developer', revokedAt: null }), {
			expirationTtl: 300,
		});
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
		expect(kv.put).toHaveBeenCalledWith(`tier:${result.keyHash}`, JSON.stringify({ tier: 'owner', revokedAt: null }), {
			expirationTtl: 300,
		});
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
		const putArgs = vi.mocked(kv.put).mock.calls.find(([key]) => /^tier:[a-f0-9]{64}$/.test(String(key)))!;
		expect(putArgs).toBeDefined();
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

	it('keeps BV_API_KEY IP-gated to partner when client IP is outside OWNER_ALLOW_IPS', async () => {
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
		expect(vi.mocked(kv.put).mock.calls.some(([key]) => /^tier:[a-f0-9]{64}$/.test(String(key)))).toBe(false);
	});

	it('caps and cancels an oversized bv-web validation response', async () => {
		const { BV_WEB_VALIDATE_KEY_MAX_BODY_BYTES, resolveTier } = await import('../src/lib/tier-auth');
		const cancelled = vi.fn();
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new Uint8Array(BV_WEB_VALIDATE_KEY_MAX_BODY_BYTES + 1));
			},
			cancel: cancelled,
		});
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(new Response(body, { status: 200 })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'oversized-service-bound-key',
			{ BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			'203.0.113.91',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(false);
		expect(cancelled).toHaveBeenCalledOnce();
	});

	it('cancels an unread non-2xx bv-web validation response body', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const cancelled = vi.fn();
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(new Response(new ReadableStream<Uint8Array>({ cancel: cancelled }), { status: 400 })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'rejected-service-bound-key',
			{ BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			'203.0.113.92',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(false);
		expect(cancelled).toHaveBeenCalledOnce();
	});

	it('aborts a stalled bv-web validation request at its timeout', async () => {
		const { fetchBvWebValidateKey } = await import('../src/lib/tier-auth');
		let requestSignal: AbortSignal | undefined;
		const bvWeb = {
			fetch: vi.fn().mockImplementation((request: Request) => {
				requestSignal = request.signal;
				return new Promise<Response>((_resolve, reject) => {
					request.signal.addEventListener('abort', () => reject(request.signal.reason), { once: true });
				});
			}),
		} as unknown as Fetcher;

		await expect(fetchBvWebValidateKey(bvWeb, 'internal-key', 'a'.repeat(64), 5)).rejects.toMatchObject({
			name: 'TimeoutError',
		});
		expect(requestSignal?.aborted).toBe(true);
	});

	it('keeps the bv-web timeout active after headers while the response body stalls', async () => {
		const { fetchBvWebValidateKey } = await import('../src/lib/tier-auth');
		let requestSignal: AbortSignal | undefined;
		const bvWeb = {
			fetch: vi.fn().mockImplementation((request: Request) => {
				requestSignal = request.signal;
				let bodyController: ReadableStreamDefaultController<Uint8Array>;
				const body = new ReadableStream<Uint8Array>({
					start(controller) {
						bodyController = controller;
					},
				});
				request.signal.addEventListener('abort', () => bodyController.error(request.signal.reason), { once: true });
				return Promise.resolve(new Response(body, { status: 200 }));
			}),
		} as unknown as Fetcher;

		await expect(fetchBvWebValidateKey(bvWeb, 'internal-key', 'b'.repeat(64), 5)).rejects.toMatchObject({
			name: 'TimeoutError',
		});
		expect(requestSignal?.aborted).toBe(true);
	});
});

describe('tier-auth configured static API key', () => {
	function statefulKv() {
		const entries = new Map<string, string>();
		const kv = {
			get: vi.fn(async (key: string) => entries.get(key) ?? null),
			put: vi.fn(async (key: string, value: string) => {
				entries.set(key, value);
			}),
			delete: vi.fn(async (key: string) => {
				entries.delete(key);
			}),
		} as unknown as KVNamespace;
		return { kv, entries };
	}

	it('authenticates consecutive requests without caching a remote rejection of the static key', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const { kv } = statefulKv();
		const bvWeb = { fetch: vi.fn(async () => Response.json({ tier: null })) } as unknown as Fetcher;
		const env = { BV_API_KEY: 'static-api-key', RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' };

		const first = await resolveTier('static-api-key', env, '192.0.2.10', 'https://example.com/mcp');
		const second = await resolveTier('static-api-key', env, '192.0.2.10', 'https://example.com/mcp');

		expect(first).toMatchObject({ authenticated: true, tier: 'owner' });
		expect(second).toEqual(first);
		expect(first.keyHash).toMatch(/^[a-f0-9]{64}$/);
		expect(first.credentialHash).toBe(first.keyHash);
		expect(first.legacyOwnerId).toBe(first.keyHash?.slice(0, 16));
		expect(bvWeb.fetch).not.toHaveBeenCalled();
		expect(kv.put).not.toHaveBeenCalled();
	});

	it.each([
		['negative', { tier: 'free', revokedAt: 1 }],
		['positive', { tier: 'developer', revokedAt: null }],
	])('ignores a stale %s entitlement cache and rechecks the owner IP gate on every request', async (_label, cached) => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const token = 'static-api-key';
		const keyHash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))))
			.map((byte) => byte.toString(16).padStart(2, '0'))
			.join('');
		const { kv, entries } = statefulKv();
		entries.set(`tier:${keyHash}`, JSON.stringify(cached));
		const bvWeb = { fetch: vi.fn(async () => Response.json({ tier: null })) } as unknown as Fetcher;
		const env = {
			BV_API_KEY: token,
			RATE_LIMIT: kv,
			BV_WEB: bvWeb,
			BV_WEB_INTERNAL_KEY: 'internal-key',
			OWNER_ALLOW_IPS: '192.0.2.10',
		};

		for (const [clientIp, tier] of [
			['192.0.2.10', 'owner'],
			['198.51.100.20', 'partner'],
			[undefined, 'partner'],
			['192.0.2.10', 'owner'],
		]) {
			expect(await resolveTier(token, env, clientIp, 'https://example.com/mcp')).toMatchObject({ authenticated: true, tier, keyHash });
		}
		expect(bvWeb.fetch).not.toHaveBeenCalled();
		expect(kv.get).not.toHaveBeenCalled();
	});

	it('continues to reject and negative-cache unrelated credentials with a static key configured', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const { kv } = statefulKv();
		const bvWeb = { fetch: vi.fn(async () => Response.json({ tier: null })) } as unknown as Fetcher;
		const env = { BV_API_KEY: 'static-api-key', RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' };

		expect(await resolveTier('unrelated-api-key', env, '192.0.2.10', 'https://example.com/mcp')).toEqual({ authenticated: false });
		expect(await resolveTier('unrelated-api-key', env, '192.0.2.10', 'https://example.com/mcp')).toEqual({ authenticated: false });
		expect(bvWeb.fetch).toHaveBeenCalledOnce();
	});
});

describe('tier-auth fail-closed entitlement validation', () => {
	// ─── Successful validation only writes the bounded positive cache ───────────

	it('does not write a long-lived positive entitlement cache after successful validation', async () => {
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

		// A revoked bearer must not remain usable through a long-lived stale entry.
		const putCalls = vi.mocked(kv.put).mock.calls;
		const lkgCall = putCalls.find((c) => c[0] === `tier:lkg:${result.keyHash}`);
		expect(lkgCall).toBeUndefined();
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

	// ─── Network failures fail closed ──────────────────────────────────────────

	it('does not authorize from an LKG entry when bv-web throws', async () => {
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

		expect(result.authenticated).toBe(false);
		expect(vi.mocked(kv.get).mock.calls.some(([key]) => String(key) === `tier:lkg:${keyHash}`)).toBe(false);
	});

	it('rejects an unmatched credential when bv-web throws and no LKG entry exists', async () => {
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

	// ─── Server failures fail closed ────────────────────────────────────────────

	it('does not authorize from an LKG entry when bv-web returns 503', async () => {
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

		expect(result.authenticated).toBe(false);
		expect(vi.mocked(kv.get).mock.calls.some(([key]) => String(key) === `tier:lkg:${keyHash}`)).toBe(false);
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

	// ─── Stale owner results never authorize ────────────────────────────────────

	it('does not authorize a stale owner LKG entry when bv-web throws', async () => {
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

		expect(result.authenticated).toBe(false);
		expect(vi.mocked(kv.get).mock.calls.some(([key]) => String(key) === `tier:lkg:${keyHash}`)).toBe(false);
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

describe('tier-auth dedicated production load-test key', () => {
	it('resolves to owner only from an explicitly allowlisted source IP', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const result = await resolveTier(
			'load-test-key-secret',
			{
				BV_LOAD_TEST_KEY: 'load-test-key-secret',
				BV_LOAD_TEST_ALLOW_IPS: '192.0.2.10, 198.51.100.20',
			},
			'198.51.100.20',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('owner');
		expect(result.credentialHash).toMatch(/^[a-f0-9]{64}$/);
	});

	it.each([
		['a non-allowlisted IP', '203.0.113.30', '192.0.2.10'],
		['a missing client IP', undefined, '192.0.2.10'],
		['an empty allowlist', '192.0.2.10', ''],
		['a missing allowlist', '192.0.2.10', undefined],
	])('fails closed for %s', async (_label, clientIp, allowIps) => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const result = await resolveTier(
			'load-test-key-secret',
			{
				BV_LOAD_TEST_KEY: 'load-test-key-secret',
				BV_LOAD_TEST_ALLOW_IPS: allowIps,
				BV_API_KEY: 'load-test-key-secret',
			},
			clientIp,
			'https://example.com/mcp',
		);

		expect(result).toEqual({ authenticated: false });
	});

	it('does not disturb permanent dev-key resolution', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const result = await resolveTier(
			'permanent-dev-key',
			{
				BV_LOAD_TEST_KEY: 'load-test-key-secret',
				BV_LOAD_TEST_ALLOW_IPS: '192.0.2.10',
				BV_INTERNAL_DEV_KEY: 'permanent-dev-key',
				OWNER_ALLOW_IPS: '192.0.2.10',
			},
			'192.0.2.10',
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('owner');
	});
});

describe('tier-auth bearer JWT strong-state outage (SQ-234)', () => {
	const SECRET = 'a'.repeat(32);
	const ISSUER = 'https://example.com';
	const REQUEST_URL = 'https://example.com/mcp';

	function rejectingKv(): KVNamespace {
		const fail = () => Promise.reject(new Error('KV unavailable (SQ-234)'));
		return { get: fail, put: fail, delete: fail, list: fail, getWithMetadata: fail } as unknown as KVNamespace;
	}

	function healthyKv(): KVNamespace {
		return {
			get: async () => null,
			put: async () => undefined,
			delete: async () => undefined,
			list: async () => ({ keys: [], list_complete: true, cursor: undefined }),
		} as unknown as KVNamespace;
	}

	async function mint(secret = SECRET, ttlSeconds = 3600): Promise<string> {
		const { signJwt, newJti } = await import('../src/oauth/jwt');
		return signJwt(
			{ sub: 'owner', jti: newJti(), tier: 'owner', client_id: 'test-client' },
			{ secret, ttlSeconds, issuer: ISSUER, audience: `${ISSUER}/mcp` },
		);
	}

	it('returns storageUnavailable (not a plain unauthenticated result) for a valid JWT when SESSION_STORE rejects', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const result = await resolveTier(
			await mint(),
			{ OAUTH_SIGNING_SECRET: SECRET, OAUTH_ISSUER: ISSUER, SESSION_STORE: rejectingKv() },
			undefined,
			REQUEST_URL,
		);
		expect(result).toEqual({ authenticated: false, storageUnavailable: true });
	});

	it('returns storageUnavailable for a valid JWT when the DO coordinator fails', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const failingCoordinator = {
			getByName: () => ({
				dispatch: () => Promise.reject(new Error('DO unavailable (SQ-234)')),
			}),
		} as unknown as DurableObjectNamespace<import('../src/lib/quota-coordinator').QuotaCoordinator>;
		const result = await resolveTier(
			await mint(),
			{ OAUTH_SIGNING_SECRET: SECRET, OAUTH_ISSUER: ISSUER, SESSION_STORE: healthyKv(), QUOTA_COORDINATOR: failingCoordinator },
			undefined,
			REQUEST_URL,
		);
		expect(result).toEqual({ authenticated: false, storageUnavailable: true });
	});

	it('keeps a plain 401-shaped result for a wrong-signature JWT even with SESSION_STORE rejecting', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const result = await resolveTier(
			await mint('b'.repeat(32)),
			{ OAUTH_SIGNING_SECRET: SECRET, OAUTH_ISSUER: ISSUER, SESSION_STORE: rejectingKv() },
			undefined,
			REQUEST_URL,
		);
		expect(result.authenticated).toBe(false);
		expect(result.storageUnavailable).toBeUndefined();
	});

	it('keeps a plain unauthenticated result for an expired JWT even with SESSION_STORE rejecting', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const token = await mint(SECRET, 60);
		vi.useFakeTimers();
		vi.setSystemTime(Date.now() + 3600 * 1000);
		const result = await resolveTier(
			token,
			{ OAUTH_SIGNING_SECRET: SECRET, OAUTH_ISSUER: ISSUER, SESSION_STORE: rejectingKv() },
			undefined,
			REQUEST_URL,
		);
		expect(result.authenticated).toBe(false);
		expect(result.storageUnavailable).toBeUndefined();
	});

	it('does not flag a non-JWT bearer as storageUnavailable when SESSION_STORE rejects', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const result = await resolveTier(
			'not-a-jwt-token',
			{ OAUTH_SIGNING_SECRET: SECRET, OAUTH_ISSUER: ISSUER, SESSION_STORE: rejectingKv() },
			undefined,
			REQUEST_URL,
		);
		expect(result.authenticated).toBe(false);
		expect(result.storageUnavailable).toBeUndefined();
	});

	// SQ-236: outage-path coverage for tokens the strong state (or its KV mirror) already
	// proves are NOT valid. A known-bad token must stay a plain 401-shaped result — only a token
	// whose validity is genuinely unknowable may become storageUnavailable (503).
	type CoordinatorPayload = { kind: string };
	type CoordinatorNamespace = DurableObjectNamespace<import('../src/lib/quota-coordinator').QuotaCoordinator>;

	function fakeCoordinator(handler: (payload: CoordinatorPayload) => unknown): CoordinatorNamespace {
		return {
			getByName: () => ({ dispatch: async (payload: CoordinatorPayload) => handler(payload) }),
		} as unknown as CoordinatorNamespace;
	}

	/** KV that holds only the legacy pre-strong-state revocation mirror entry for every jti. */
	function legacyRevokedKv(): KVNamespace {
		return {
			get: async (key: string) => (key.includes(':revoked:') ? '1' : null),
			put: async () => undefined,
			delete: async () => undefined,
			list: async () => ({ keys: [], list_complete: true, cursor: undefined }),
		} as unknown as KVNamespace;
	}

	async function mintWithVersion(ver: number): Promise<string> {
		const { signJwt, newJti } = await import('../src/oauth/jwt');
		return signJwt(
			{ sub: 'owner', jti: newJti(), tier: 'owner', client_id: 'test-client', ver },
			{ secret: SECRET, ttlSeconds: 3600, issuer: ISSUER, audience: `${ISSUER}/mcp` },
		);
	}

	it('a revoked token (strong marker present) stays a plain unauthenticated result even with SESSION_STORE rejecting', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const result = await resolveTier(
			await mint(),
			{
				OAUTH_SIGNING_SECRET: SECRET,
				OAUTH_ISSUER: ISSUER,
				SESSION_STORE: rejectingKv(),
				QUOTA_COORDINATOR: fakeCoordinator((payload) => (payload.kind === 'marker-has' ? { present: true } : undefined)),
			},
			undefined,
			REQUEST_URL,
		);
		expect(result.authenticated).toBe(false);
		expect(result.storageUnavailable).toBeUndefined();
	});

	it('a legacy-revoked token stays revoked (not storageUnavailable) when the migration write throws', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const result = await resolveTier(
			await mint(),
			{
				OAUTH_SIGNING_SECRET: SECRET,
				OAUTH_ISSUER: ISSUER,
				SESSION_STORE: legacyRevokedKv(),
				QUOTA_COORDINATOR: fakeCoordinator((payload) => {
					if (payload.kind === 'marker-has') return { present: false };
					throw new Error('DO unavailable (SQ-236)');
				}),
			},
			undefined,
			REQUEST_URL,
		);
		expect(result.authenticated).toBe(false);
		expect(result.storageUnavailable).toBeUndefined();
	});

	it('a legacy-revoked token stays revoked (not storageUnavailable) when the migration write returns a malformed reply', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const result = await resolveTier(
			await mint(),
			{
				OAUTH_SIGNING_SECRET: SECRET,
				OAUTH_ISSUER: ISSUER,
				SESSION_STORE: legacyRevokedKv(),
				QUOTA_COORDINATOR: fakeCoordinator((payload) => (payload.kind === 'marker-has' ? { present: false } : { unexpected: true })),
			},
			undefined,
			REQUEST_URL,
		);
		expect(result.authenticated).toBe(false);
		expect(result.storageUnavailable).toBeUndefined();
	});

	it('a legacy-revoked token is still migrated into strong state when the coordinator is healthy', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const kinds: string[] = [];
		const result = await resolveTier(
			await mint(),
			{
				OAUTH_SIGNING_SECRET: SECRET,
				OAUTH_ISSUER: ISSUER,
				SESSION_STORE: legacyRevokedKv(),
				QUOTA_COORDINATOR: fakeCoordinator((payload) => {
					kinds.push(payload.kind);
					return { present: payload.kind === 'marker-set' };
				}),
			},
			undefined,
			REQUEST_URL,
		);
		expect(result.authenticated).toBe(false);
		expect(result.storageUnavailable).toBeUndefined();
		expect(kinds).toContain('marker-set');
	});

	it('a stale token-version token is a plain unauthenticated result when the strong version store answers', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const result = await resolveTier(
			await mintWithVersion(1),
			{
				OAUTH_SIGNING_SECRET: SECRET,
				OAUTH_ISSUER: ISSUER,
				SESSION_STORE: healthyKv(),
				QUOTA_COORDINATOR: fakeCoordinator((payload) => (payload.kind === 'marker-has' ? { present: false } : { value: 2 })),
			},
			undefined,
			REQUEST_URL,
		);
		expect(result.authenticated).toBe(false);
		expect(result.storageUnavailable).toBeUndefined();
	});

	it('a stale-version token whose version read fails is storageUnavailable, never authenticated', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const result = await resolveTier(
			await mintWithVersion(1),
			{
				OAUTH_SIGNING_SECRET: SECRET,
				OAUTH_ISSUER: ISSUER,
				SESSION_STORE: healthyKv(),
				QUOTA_COORDINATOR: fakeCoordinator((payload) => {
					if (payload.kind === 'marker-has') return { present: false };
					throw new Error('DO unavailable (SQ-236)');
				}),
			},
			undefined,
			REQUEST_URL,
		);
		expect(result).toEqual({ authenticated: false, storageUnavailable: true });
	});
});

describe('tier-auth trial key strong-state outage (SQ-289)', () => {
	const REQUEST_URL = 'https://example.com/mcp';

	function trialKv(): { kv: KVNamespace; puts: Array<[string, string]> } {
		const puts: Array<[string, string]> = [];
		const record = JSON.stringify({
			tier: 'developer',
			expiresAt: Date.now() + 3_600_000,
			maxUses: 10,
			currentUses: 0,
			label: 'sq-289-trial',
			createdAt: Date.now(),
		});
		const kv = {
			get: vi.fn(async (key: string) => (key.startsWith('trial:') ? record : null)),
			put: vi.fn(async (key: string, value: string) => {
				puts.push([key, value]);
			}),
			delete: vi.fn(async () => undefined),
		} as unknown as KVNamespace;
		return { kv, puts };
	}

	it('returns storageUnavailable and does not write a tier: negative cache entry when QUOTA_COORDINATOR throws', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const { kv, puts } = trialKv();
		const failingCoordinator = {
			getByName: () => ({ dispatch: () => Promise.reject(new Error('DO unavailable (SQ-289)')) }),
		} as unknown as DurableObjectNamespace<import('../src/lib/quota-coordinator').QuotaCoordinator>;

		const result = await resolveTier('trial-token', { RATE_LIMIT: kv, QUOTA_COORDINATOR: failingCoordinator }, '203.0.113.1', REQUEST_URL);

		expect(result).toEqual({ authenticated: false, storageUnavailable: true });
		expect(puts.filter(([key]) => key.startsWith('tier:'))).toEqual([]);
	});

	it('still negative-caches an exhausted trial key (reason other than unavailable)', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const { kv, puts } = trialKv();
		const exhaustedCoordinator = {
			getByName: () => ({
				dispatch: async (payload: { kind: string }) =>
					payload.kind === 'marker-has' ? { present: false } : { allowed: false, used: 10, limit: 10 },
			}),
		} as unknown as DurableObjectNamespace<import('../src/lib/quota-coordinator').QuotaCoordinator>;

		const result = await resolveTier(
			'trial-token',
			{ RATE_LIMIT: kv, QUOTA_COORDINATOR: exhaustedCoordinator },
			'203.0.113.1',
			REQUEST_URL,
		);

		expect(result.authenticated).toBe(false);
		expect(result.storageUnavailable).toBeUndefined();
		expect(puts.filter(([key]) => key.startsWith('tier:'))).toHaveLength(1);
	});
});
