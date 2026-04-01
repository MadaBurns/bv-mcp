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
import { TierCacheEntrySchema, ValidateKeyResponseSchema } from '../schemas/auth';

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
 * 2. Service binding to companion app (validate-key endpoint)
 * 3. Static BV_API_KEY comparison (self-hosted fallback → owner tier)
 *
 * Owner tier requires IP allowlist (OWNER_ALLOW_IPS env var, comma-separated).
 * If the key matches BV_API_KEY but the IP is not in the allowlist,
 * the request is downgraded to partner tier.
 */
export async function resolveTier(
	token: string | null,
	env: {
		BV_API_KEY?: string;
		OWNER_ALLOW_IPS?: string;
		RATE_LIMIT?: KVNamespace;
		BV_WEB?: Fetcher;
		BV_WEB_INTERNAL_KEY?: string;
	},
	clientIp?: string,
): Promise<TierAuthResult> {
	if (!token) return { authenticated: false };

	const keyHash = await hashToken(token);
	console.log(`[auth] Resolving tier for keyHash=${keyHash.slice(0, 8)}... ip=${clientIp}`);

	// 1. Try KV cache
	if (env.RATE_LIMIT) {
		try {
			const cached = await env.RATE_LIMIT.get(`tier:${keyHash}`);
			if (cached) {
				const raw = JSON.parse(cached);
				const cacheResult = TierCacheEntrySchema.safeParse(raw);
				if (!cacheResult.success) {
					await env.RATE_LIMIT.delete(`tier:${keyHash}`);
				} else {
					if (cacheResult.data.revokedAt) return { authenticated: false };
					return { authenticated: true, tier: cacheResult.data.tier, keyHash };
				}
			}
		} catch {
			// Invalid cache entry, fall through
		}
	}

	// 2. Try service binding to bv-web
	if (env.BV_WEB && env.BV_WEB_INTERNAL_KEY) {
		try {
			const response = await env.BV_WEB.fetch(
				new Request('https://internal/api/internal/mcp/validate-key', {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'Authorization': `Bearer ${env.BV_WEB_INTERNAL_KEY}`,
					},
					body: JSON.stringify({ keyHash }),
				}),
			);

			if (response.ok) {
				const rawData = await response.json();
				const keyResult = ValidateKeyResponseSchema.safeParse(rawData);
				if (keyResult.success) {
					const data = keyResult.data;
					// Cache the valid tier result
					if (env.RATE_LIMIT) {
						await env.RATE_LIMIT.put(
							`tier:${keyHash}`,
							JSON.stringify({ tier: data.tier, revokedAt: null }),
							{ expirationTtl: TIER_KV_CACHE_TTL },
						);
					}
					return { authenticated: true, tier: data.tier, keyHash };
				}
				// Null tier = revoked or unknown key — cache negative result to avoid
				// repeated service binding calls within the TTL window
				if (env.RATE_LIMIT) {
					await env.RATE_LIMIT.put(
						`tier:${keyHash}`,
						JSON.stringify({ tier: 'free', revokedAt: Date.now() }),
						{ expirationTtl: TIER_KV_CACHE_TTL },
					);
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
			// Owner tier requires IP allowlist. If OWNER_ALLOW_IPS is set and the
			// client IP is not in the list, downgrade to partner (still high limits
			// but not unlimited). If OWNER_ALLOW_IPS is unset, owner is unrestricted
			// (backward compat for self-hosted/dev where there's no IP filtering).
			if (env.OWNER_ALLOW_IPS && clientIp) {
				const allowed = env.OWNER_ALLOW_IPS.split(',').map((ip) => ip.trim());
				if (!allowed.includes(clientIp)) {
					return { authenticated: true, tier: 'partner', keyHash };
				}
			}
			return { authenticated: true, tier: 'owner', keyHash };
		}
	}

	return { authenticated: false };
}
