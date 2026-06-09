// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: bv-web → bv-mcp validate-key WIRE surface (resolveTier step 3).
 *
 * Endpoint: POST /api/internal/mcp/validate-key over the BV_WEB service binding.
 * Wire shape: { tier: TierSchema | null } — ValidateKeyResponseSchema (frozen).
 * Consumer: src/lib/tier-auth.ts:234-318 (the cache-miss fallback).
 *
 * THE load-bearing pre-cutover fixture mandated by
 * docs/superpowers/specs/2026-06-06-bv-mcp-contract-guardrail.md §6 #1.
 *
 * It pins that the producer's FOUR distinct answers drive FOUR distinct
 * behaviors, and — the life-or-death-for-revenue point (spec line 36,
 * "These two MUST stay distinct") — that `200 {tier:null}` behavior is the
 * OPPOSITE of `5xx` behavior under an IDENTICAL precondition (an LKG entry
 * present). A null is a definitive revoke (LKG ignored); a 5xx is "I don't
 * know" (LKG consulted, paying customer re-authenticated).
 *
 * Distinct from oauth-tier.contract.test.ts: that guards step-0
 * CustomerOAuthTierSchema; this guards step-3 service-binding resolution.
 *
 * Mocks mirror test/tier-auth.spec.ts (KV get/put/delete + bvWeb fetch).
 */
import { describe, expect, it, vi, afterEach } from 'vitest';

afterEach(() => {
	vi.restoreAllMocks();
});

/** hex(SHA-256(token)) — same derivation resolveTier uses for the KV keyHash. */
async function keyHashOf(token: string): Promise<string> {
	const raw = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
	return Array.from(raw)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

describe('validate-key wire contract (resolveTier step 3)', () => {
	// ─── Behavior 1: 200 {tier:<t>} → authenticate + cache 5min + LKG 24h ──────
	it('200 {tier} → authenticates, writes tier:{hash} (300s) AND tier:lkg:{hash} (86400s)', async () => {
		const { resolveTier } = await import('../../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(Response.json({ tier: 'developer' })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'confirmed-entitlement-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('developer');
		expect(bvWeb.fetch).toHaveBeenCalledOnce();

		// Short-lived positive cache entry (5 min).
		expect(kv.put).toHaveBeenCalledWith(
			`tier:${result.keyHash}`,
			JSON.stringify({ tier: 'developer', revokedAt: null }),
			{ expirationTtl: 300 },
		);
		// Long-lived last-known-good entry (24 h) — the outage fail-safe.
		expect(kv.put).toHaveBeenCalledWith(`tier:lkg:${result.keyHash}`, 'developer', { expirationTtl: 86400 });
	});

	// ─── Behavior 2: 200 {tier:null} → negative-cache, LKG NEITHER read NOR written
	// Precondition deliberately mirrors Behavior 3 (an LKG entry is present) to
	// prove the asymmetry: a definitive revoke IGNORES the present LKG.
	it('200 {tier:null} → negative-caches {tier:free,revokedAt}, ignores present LKG, writes no LKG', async () => {
		const { resolveTier } = await import('../../src/lib/tier-auth');

		const keyHash = await keyHashOf('definitive-revoke-key');
		const kv = {
			get: vi.fn((key: string) => {
				// An LKG entry EXISTS — a null answer must NOT consult it.
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
			'definitive-revoke-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		// Definitive revoke: unauthenticated even though LKG says 'enterprise'.
		expect(result.authenticated).toBe(false);
		expect(bvWeb.fetch).toHaveBeenCalledOnce();

		// Negative cache written to the short-lived key…
		const putCalls = vi.mocked(kv.put).mock.calls;
		const negCall = putCalls.find((c) => c[0] === `tier:${keyHash}`);
		expect(negCall).toBeDefined();
		expect(JSON.parse(String(negCall![1]))).toEqual({ tier: 'free', revokedAt: expect.any(Number) });
		expect(negCall![2]).toEqual({ expirationTtl: 300 });

		// …and the LKG key was NEITHER read NOR written.
		expect(vi.mocked(kv.get).mock.calls.some((c) => c[0] === `tier:lkg:${keyHash}`)).toBe(false);
		expect(putCalls.some((c) => String(c[0]).startsWith('tier:lkg:'))).toBe(false);
	});

	// ─── Behavior 3a: 5xx → AMBIGUOUS → read LKG, re-authenticate (don't downgrade)
	// Same precondition as Behavior 2 (LKG present) → OPPOSITE outcome. This pair
	// IS the contract (spec line 36).
	it('5xx → reads present LKG and re-authenticates the paying customer (no downgrade)', async () => {
		const { resolveTier } = await import('../../src/lib/tier-auth');

		const keyHash = await keyHashOf('ambiguous-5xx-key');
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
			'ambiguous-5xx-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		// Re-authenticated from LKG — the opposite of the null case above.
		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('enterprise');
		expect(result.keyHash).toBe(keyHash);
		expect(vi.mocked(kv.get).mock.calls.some((c) => c[0] === `tier:lkg:${keyHash}`)).toBe(true);
	});

	// ─── Behavior 3b: fetch throws → AMBIGUOUS → same LKG path as 5xx ──────────
	it('fetch throws (network/binding failure) → reads present LKG and re-authenticates', async () => {
		const { resolveTier } = await import('../../src/lib/tier-auth');

		const keyHash = await keyHashOf('ambiguous-throw-key');
		const kv = {
			get: vi.fn((key: string) => {
				if (key === `tier:lkg:${keyHash}`) return Promise.resolve('developer');
				return Promise.resolve(null);
			}),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockRejectedValue(new Error('network error')),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'ambiguous-throw-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('developer');
		expect(result.keyHash).toBe(keyHash);
	});

	// ─── Behavior 4: 4xx → DEFINITIVE REJECT → no LKG, fall through to static key
	// An LKG entry is present AND a matching BV_API_KEY is configured. The single
	// `tier === 'owner'` assertion proves BOTH halves: LKG was skipped (else we'd
	// get 'enterprise') and the static BV_API_KEY path engaged.
	it('4xx → ignores present LKG and falls through to static BV_API_KEY (→ owner)', async () => {
		const { resolveTier } = await import('../../src/lib/tier-auth');

		const keyHash = await keyHashOf('static-fallthrough-key');
		const kv = {
			get: vi.fn((key: string) => {
				// LKG entry present — a 4xx is definitive and must NOT consult it.
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
			'static-fallthrough-key',
			{
				RATE_LIMIT: kv,
				BV_WEB: bvWeb,
				BV_WEB_INTERNAL_KEY: 'internal-key',
				// The same token also matches the static self-hosted key.
				BV_API_KEY: 'static-fallthrough-key',
			},
			undefined,
			'https://example.com/mcp',
		);

		// Static path engaged → owner tier; LKG ('enterprise') was NOT served.
		expect(result.authenticated).toBe(true);
		expect(result.tier).toBe('owner');
		expect(result.tier).not.toBe('enterprise');
	});

	// ─── Wire shape (spec §6 #1 line 121): malformed/mistyped tier → silent deny
	// ValidateKeyResponseSchema safeParse-fails a non-Tier value, so resolveTier
	// emits no tier AND does not negative-cache (it is not a definitive answer).
	it('200 with mistyped tier → safeParse-fails, no auth, no negative cache (silent deny)', async () => {
		const { resolveTier } = await import('../../src/lib/tier-auth');

		const kv = {
			get: vi.fn().mockResolvedValue(null),
			put: vi.fn(),
			delete: vi.fn(),
		} as unknown as KVNamespace;
		const bvWeb = {
			fetch: vi.fn().mockResolvedValue(Response.json({ tier: 'not-a-real-tier' })),
		} as unknown as Fetcher;

		const result = await resolveTier(
			'malformed-shape-key',
			{ RATE_LIMIT: kv, BV_WEB: bvWeb, BV_WEB_INTERNAL_KEY: 'internal-key' },
			undefined,
			'https://example.com/mcp',
		);

		expect(result.authenticated).toBe(false);
		expect(bvWeb.fetch).toHaveBeenCalledOnce();
		// Not a definitive answer → must NOT negative-cache.
		expect(kv.put).not.toHaveBeenCalled();
	});
});
