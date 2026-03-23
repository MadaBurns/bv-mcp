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

/** SHA-256 hash a bearer token to a hex string (for KV keys and service binding payloads). */
async function hashToken(token: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(token);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	return Array.from(new Uint8Array(hashBuffer))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

/** SHA-256 digest as raw bytes (for constant-time comparison). */
async function hashTokenRaw(token: string): Promise<Uint8Array> {
	const encoder = new TextEncoder();
	const data = encoder.encode(token);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	return new Uint8Array(hashBuffer);
}

/**
 * Resolve a bearer token to its API key tier.
 *
 * Resolution order:
 * 1. KV cache lookup (`tier:{hash}`)
 * 2. Service binding to bv-web (`POST /internal/validate-key`)
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
	if (!token) return { authenticated: false };

	const keyHash = await hashToken(token);

	// 1. Try KV cache
	if (env.RATE_LIMIT) {
		try {
			const cached = await env.RATE_LIMIT.get(`tier:${keyHash}`);
			if (cached) {
				const parsed = JSON.parse(cached) as { tier: string; revokedAt: number | null };
				if (parsed.revokedAt) return { authenticated: false };
				return { authenticated: true, tier: parsed.tier as McpApiKeyTier, keyHash };
			}
		} catch {
			// Invalid cache entry, fall through
		}
	}

	// 2. Try service binding to bv-web
	if (env.BV_WEB && env.BV_WEB_INTERNAL_KEY) {
		try {
			const response = await env.BV_WEB.fetch(
				new Request('https://internal/internal/validate-key', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Authorization': `Bearer ${env.BV_WEB_INTERNAL_KEY}`,
					},
					body: JSON.stringify({ keyHash }),
				}),
			);

			if (response.ok) {
				const data = (await response.json()) as { tier: string | null };
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
			}
		} catch {
			// Service binding failed, fall through to BV_API_KEY
		}
	}

	// 3. Fallback: compare against static BV_API_KEY (self-hosted/dev)
	if (env.BV_API_KEY) {
		// Constant-time comparison: XOR raw SHA-256 digests byte-by-byte
		// (same pattern as auth.ts — avoids timing side-channels from === on strings)
		const [a, b] = await Promise.all([hashTokenRaw(token), hashTokenRaw(env.BV_API_KEY)]);
		let mismatch = 0;
		for (let i = 0; i < a.byteLength; i++) {
			mismatch |= a[i] ^ b[i];
		}
		if (mismatch === 0) {
			return { authenticated: true, tier: 'enterprise', keyHash };
		}
	}

	return { authenticated: false };
}
