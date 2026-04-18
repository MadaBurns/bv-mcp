// SPDX-License-Identifier: BUSL-1.1

/**
 * Tier-based API key authentication.
 *
 * Resolves a bearer token to its tier via:
 * 1. KV cache (sub-ms, 5-min TTL)
 * 2. Trial key lookup (KV `trial:` prefix, 60s cache TTL)
 * 3. bv-web service binding (cache miss fallback)
 * 4. Static BV_API_KEY comparison (self-hosted fallback)
 */

import type { McpApiKeyTier } from './config';
import { OAUTH_JWT_CLOCK_SKEW_SECONDS, TRIAL_KEY_CACHE_TTL } from './config';
import { TierCacheEntrySchema, ValidateKeyResponseSchema } from '../schemas/auth';
import { resolveTrialKey } from './trial-keys';
import { verifyJwt } from '../oauth/jwt';
import { resolveIssuer } from '../oauth/discovery';
import { isRevoked } from '../oauth/storage';

export interface TierAuthResult {
	authenticated: boolean;
	tier?: McpApiKeyTier;
	keyHash?: string;
}

const TIER_KV_CACHE_TTL = 300; // 5 minutes

/** SHA-256 digest as raw bytes (for constant-time comparison and hex derivation). */
async function hashTokenRaw(token: string): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
}

/**
 * Resolve a bearer token to its API key tier.
 *
 * Resolution order:
 * 1. KV cache lookup (`tier:{hash}`)
 * 2. Trial key lookup (`trial:{hash}` in KV — time + usage limits)
 * 3. Service binding to companion app (validate-key endpoint)
 * 4. Static BV_API_KEY comparison (self-hosted fallback → owner tier)
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
		OAUTH_SIGNING_SECRET?: string;
		OAUTH_ISSUER?: string;
		SESSION_STORE?: KVNamespace;
	},
	clientIp?: string,
	requestUrl?: string,
): Promise<TierAuthResult> {
	if (!token) return { authenticated: false };

	// 0. OAuth 2.1 Bearer JWT path — runs FIRST so a valid access token short-circuits before
	// any KV / service-binding work. Shape check (3 dot-separated segments) is a cheap gate that
	// lets a non-JWT bearer (e.g. static BV_API_KEY) skip straight to the legacy flow without
	// paying a signing-key lookup. OWNER_ALLOW_IPS is NOT re-checked here — it was enforced at
	// the /oauth/authorize consent step (Phase 6 amendment), so minting the JWT already
	// required a permitted IP. The jti revocation lookup is defense-in-depth.
	if (env.OAUTH_SIGNING_SECRET && env.SESSION_STORE && requestUrl && token.split('.').length === 3) {
		try {
			const issuer = resolveIssuer(requestUrl, env.OAUTH_ISSUER);
			const claims = await verifyJwt(token, {
				secret: env.OAUTH_SIGNING_SECRET,
				issuer,
				audience: `${issuer}/mcp`,
				clockSkewSeconds: OAUTH_JWT_CLOCK_SKEW_SECONDS,
			});
			if (claims.sub === 'owner' && claims.tier === 'owner') {
				if (await isRevoked(env.SESSION_STORE, claims.jti)) {
					return { authenticated: false };
				}
				return { authenticated: true, tier: 'owner' };
			}
			// JWT verified but payload doesn't grant owner — fall through so static key path
			// still has a chance (e.g. a future tiered JWT could live alongside BV_API_KEY).
		} catch {
			// Not a valid OAuth JWT — fall through to the legacy static/service-binding path
			// so an operator using a 3-segment static key isn't accidentally rejected.
		}
	}

	const tokenRaw = await hashTokenRaw(token);
	const keyHash = Array.from(tokenRaw)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');

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

	// 2. Try trial key lookup
	if (env.RATE_LIMIT) {
		try {
			const trialResult = await resolveTrialKey(env.RATE_LIMIT, keyHash);
			if (trialResult) {
				if (!trialResult.authenticated) {
					// Expired or exhausted — cache as revoked to avoid repeated lookups
					await env.RATE_LIMIT.put(
						`tier:${keyHash}`,
						JSON.stringify({ tier: 'free', revokedAt: Date.now() }),
						{ expirationTtl: TRIAL_KEY_CACHE_TTL },
					);
					return { authenticated: false };
				}
				// Valid trial key — cache with shorter TTL for faster expiry/exhaustion detection
				await env.RATE_LIMIT.put(
					`tier:${keyHash}`,
					JSON.stringify({ tier: trialResult.tier, revokedAt: null }),
					{ expirationTtl: TRIAL_KEY_CACHE_TTL },
				);
				return { authenticated: true, tier: trialResult.tier, keyHash };
			}
		} catch {
			// Trial lookup failed, fall through
		}
	}

	// 3. Try service binding to bv-web
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

	// 4. Fallback: compare against static BV_API_KEY (self-hosted/dev)
	if (env.BV_API_KEY) {
		// Constant-time comparison: XOR raw SHA-256 digests byte-by-byte
		// (same pattern as auth.ts — avoids timing side-channels from === on strings)
		const a = tokenRaw;
		const b = await hashTokenRaw(env.BV_API_KEY);
		let mismatch = 0;
		for (let i = 0; i < a.byteLength; i++) {
			mismatch |= a[i] ^ b[i];
		}
		if (mismatch === 0) {
			// Owner tier requires IP allowlist. If OWNER_ALLOW_IPS is set and the
			// client IP is not in the list, downgrade to partner (still high limits
			// but not unlimited). If OWNER_ALLOW_IPS is unset, owner is unrestricted
			// (backward compat for self-hosted/dev where there's no IP filtering).
			if (env.OWNER_ALLOW_IPS) {
				const allowed = env.OWNER_ALLOW_IPS.split(',').map((ip) => ip.trim());
				if (!clientIp || !allowed.includes(clientIp)) {
					return { authenticated: true, tier: 'partner', keyHash };
				}
			}
			return { authenticated: true, tier: 'owner', keyHash };
		}
	}

	return { authenticated: false };
}
