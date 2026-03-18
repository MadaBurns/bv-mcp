// SPDX-License-Identifier: BUSL-1.1

/**
 * Tier-based API key authentication.
 *
 * Resolves a bearer token to its tier via:
 * 1. KV cache (sub-ms, 5-min TTL)
 * 2. bv-web service binding (cache miss fallback)
 * 3. Static BV_API_KEY comparison (self-hosted fallback)
 */

import type { McpApiKeyTier } from './config';

export interface TierAuthResult {
	authenticated: boolean;
	tier?: McpApiKeyTier;
	keyHash?: string;
}

const TIER_KV_CACHE_TTL = 300; // 5 minutes

/** SHA-256 hash a bearer token to match the key_hash stored in platform DB. */
async function hashToken(token: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(token);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	return Array.from(new Uint8Array(hashBuffer))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

/**
 * Resolve a bearer token to its API key tier.
 *
 * Resolution order:
 * 1. KV cache lookup (`tier:{hash}`)
 * 2. Service binding to bv-web (`POST /api/internal/mcp/validate-key`)
 * 3. Static BV_API_KEY comparison (backward compat for self-hosted)
 */
export async function resolveTier(
	token: string | null,
	env: {
		BV_API_KEY?: string;
		RATE_LIMIT?: KVNamespace;
		BV_WEB?: Fetcher;
		BV_WEB_INTERNAL_KEY?: string;
	},
): Promise<TierAuthResult> {
	if (!token) {
		console.log('[tier-auth] no token provided');
		return { authenticated: false };
	}

	const keyHash = await hashToken(token);
	console.log('[tier-auth] token present, keyHash prefix:', keyHash.slice(0, 12));

	// 1. Try KV cache
	if (env.RATE_LIMIT) {
		try {
			const cached = await env.RATE_LIMIT.get(`tier:${keyHash}`);
			console.log('[tier-auth] KV cache result:', cached ? 'HIT' : 'MISS');
			if (cached) {
				const parsed = JSON.parse(cached) as { tier: string; revokedAt: number | null };
				if (parsed.revokedAt) return { authenticated: false };
				return { authenticated: true, tier: parsed.tier as McpApiKeyTier, keyHash };
			}
		} catch (err: unknown) {
			console.log('[tier-auth] KV cache error:', err instanceof Error ? err.message : String(err));
		}
	} else {
		console.log('[tier-auth] RATE_LIMIT KV not available');
	}

	// 2. Try service binding to bv-web
	// Send both X-Internal-Key and Authorization Bearer so the endpoint can validate
	// regardless of whether BV_WEB_INTERNAL_KEY was provisioned as INTERNAL_API_KEY
	// or ADMIN_API_KEY.
	console.log('[tier-auth] BV_WEB binding available:', !!env.BV_WEB);
	console.log('[tier-auth] BV_WEB_INTERNAL_KEY available:', !!env.BV_WEB_INTERNAL_KEY);
	if (env.BV_WEB_INTERNAL_KEY) {
		console.log('[tier-auth] BV_WEB_INTERNAL_KEY prefix:', env.BV_WEB_INTERNAL_KEY.slice(0, 8));
	}
	if (env.BV_WEB && env.BV_WEB_INTERNAL_KEY) {
		try {
			console.log('[tier-auth] calling BV_WEB service binding...');
			const response = await env.BV_WEB.fetch(
				new Request('https://internal/api/internal/mcp/validate-key', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'X-Internal-Key': env.BV_WEB_INTERNAL_KEY,
						'Authorization': `Bearer ${env.BV_WEB_INTERNAL_KEY}`,
					},
					body: JSON.stringify({ keyHash }),
				}),
			);

			console.log('[tier-auth] BV_WEB response status:', response.status);
			console.log('[tier-auth] BV_WEB response headers:', JSON.stringify(Object.fromEntries(response.headers.entries())));

			if (response.ok) {
				const data = (await response.json()) as { tier: string | null };
				console.log('[tier-auth] BV_WEB response data:', JSON.stringify(data));
				if (data.tier) {
					// Cache the result
					if (env.RATE_LIMIT) {
						await env.RATE_LIMIT.put(
							`tier:${keyHash}`,
							JSON.stringify({ tier: data.tier, revokedAt: null }),
							{ expirationTtl: TIER_KV_CACHE_TTL },
						);
					}
					return { authenticated: true, tier: data.tier as McpApiKeyTier, keyHash };
				}
				console.log('[tier-auth] BV_WEB returned null tier — key not found in DB');
			} else {
				const text = await response.text();
				console.log('[tier-auth] BV_WEB non-ok response body:', text.slice(0, 500));
			}
		} catch (err: unknown) {
			console.log('[tier-auth] BV_WEB service binding error:', err instanceof Error ? err.message : String(err));
			if (err instanceof Error && err.stack) {
				console.log('[tier-auth] BV_WEB error stack:', err.stack);
			}
		}
	}

	// 3. Fallback: compare against static BV_API_KEY (self-hosted/dev)
	console.log('[tier-auth] BV_API_KEY available:', !!env.BV_API_KEY);
	if (env.BV_API_KEY && token === env.BV_API_KEY) {
		console.log('[tier-auth] matched static BV_API_KEY fallback');
		return { authenticated: true, tier: 'enterprise', keyHash };
	}

	console.log('[tier-auth] all auth methods exhausted, returning unauthenticated');
	return { authenticated: false };
}
