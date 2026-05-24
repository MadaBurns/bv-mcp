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
import { OAUTH_JWT_CLOCK_SKEW_SECONDS, parseOwnerAllowIps, TRIAL_KEY_CACHE_TTL } from './config';
import { TierCacheEntrySchema, ValidateKeyResponseSchema } from '../schemas/auth';
import { resolveTrialKey } from './trial-keys';
import { verifyJwt } from '../oauth/jwt';
import { resolveIssuer } from '../oauth/discovery';
import { isRevoked } from '../oauth/storage';
import { z } from 'zod';

/**
 * JWT-issuable tiers. The `/oauth/token` minting paths can only produce these
 * three values (owner via legacy consent, developer/enterprise via paid Stripe
 * entitlement). Verification is locked to this narrower set as defense-in-depth
 * against a future minting regression that quietly stores e.g. tier=partner.
 */
const JwtIssuableTierSchema = z.enum(['owner', 'developer', 'enterprise']);

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

function applyOwnerIpGate(tier: McpApiKeyTier, ownerAllowIps: string | undefined, clientIp: string | undefined): McpApiKeyTier {
	if (tier !== 'owner') return tier;
	const allowed = parseOwnerAllowIps(ownerAllowIps);
	if (allowed.length > 0 && (!clientIp || !allowed.includes(clientIp))) {
		return 'partner';
	}
	return 'owner';
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
		BV_INTERNAL_DEV_KEY?: string;
		OWNER_ALLOW_IPS?: string;
		RATE_LIMIT?: KVNamespace;
		BV_WEB?: Fetcher;
		BV_WEB_INTERNAL_KEY?: string;
		OAUTH_SIGNING_SECRET?: string;
		OAUTH_ISSUER?: string;
		SESSION_STORE?: KVNamespace;
	},
	clientIp: string | undefined,
	requestUrl: string,
): Promise<TierAuthResult> {
	if (!token) return { authenticated: false };

	// 0. OAuth 2.1 Bearer JWT path — runs FIRST so a valid access token short-circuits before
	// any KV / service-binding work. Shape check (3 dot-separated segments) is a cheap gate that
	// lets a non-JWT bearer (e.g. static BV_API_KEY) skip straight to the legacy flow without
	// paying a signing-key lookup. The jti revocation lookup is defense-in-depth.
	//
	// OWNER_ALLOW_IPS is re-checked here for owner-tier claims (M1 fix). Previously the gate
	// was only enforced once at /oauth/authorize consent; that meant anyone briefly on an
	// allowlisted IP could mint a 90-day JWT usable from any subsequent IP. We now mirror the
	// BV_API_KEY path: when OWNER_ALLOW_IPS is configured and the requesting clientIp isn't in
	// it, downgrade to 'partner' tier. Empty/unset allowlist preserves backward compat for
	// self-hosted/dev installations that don't IP-gate their owner.
	if (env.OAUTH_SIGNING_SECRET && env.SESSION_STORE && token.split('.').length === 3) {
		try {
			const issuer = resolveIssuer(requestUrl, env.OAUTH_ISSUER);
			const claims = await verifyJwt(token, {
				secret: env.OAUTH_SIGNING_SECRET,
				issuer,
				audience: `${issuer}/mcp`,
				clockSkewSeconds: OAUTH_JWT_CLOCK_SKEW_SECONDS,
			});
			const tierResult = JwtIssuableTierSchema.safeParse(claims.tier);
			if (typeof claims.sub === 'string' && tierResult.success) {
				if (await isRevoked(env.SESSION_STORE, claims.jti)) {
					return { authenticated: false };
				}
				const resolvedTier = applyOwnerIpGate(tierResult.data, env.OWNER_ALLOW_IPS, clientIp);
				return { authenticated: true, tier: resolvedTier };
			}
			// JWT verified but payload is not a recognized MCP tier — fall through so static key
			// path still has a chance for legacy operators with unusual three-segment keys.
		} catch {
			// Not a valid OAuth JWT — fall through to the legacy static/service-binding path
			// so an operator using a 3-segment static key isn't accidentally rejected.
		}
	}

	const tokenRaw = await hashTokenRaw(token);
	const keyHash = Array.from(tokenRaw)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');

	// 0. Static internal-dev key short-circuit. The dev key is a hardcoded
	// "us only" secret (load tests, ops scripts); it must not be subject to
	// KV-cache staleness or bv-web validate-key fallback — those paths can
	// quietly demote it to partner-tier and crash benchmarks on the 200/mo
	// quota. Comparison is constant-time XOR over raw SHA-256 digests.
	if (env.BV_INTERNAL_DEV_KEY) {
		const a = tokenRaw;
		const b = await hashTokenRaw(env.BV_INTERNAL_DEV_KEY);
		let mismatch = 0;
		for (let i = 0; i < a.byteLength; i++) {
			mismatch |= a[i] ^ b[i];
		}
		if (mismatch === 0) {
			const resolvedTier = applyOwnerIpGate('owner', env.OWNER_ALLOW_IPS, clientIp);
			return { authenticated: true, tier: resolvedTier, keyHash };
		}
	}

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
					// FIND-15: re-check trial-key expiry on cache hit. If the entry carries
					// a trialExpiresAt timestamp and it has passed, evict the stale entry so
					// the next request falls through to a fresh trial lookup / bv-web resolve.
					if (cacheResult.data.trialExpiresAt !== undefined && cacheResult.data.trialExpiresAt < Date.now()) {
						await env.RATE_LIMIT.delete(`tier:${keyHash}`);
						return { authenticated: false };
					}
					const resolvedTier = applyOwnerIpGate(cacheResult.data.tier, env.OWNER_ALLOW_IPS, clientIp);
					return { authenticated: true, tier: resolvedTier, keyHash };
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
				// Valid trial key — cache with shorter TTL for faster expiry/exhaustion detection.
				// Include trialExpiresAt so the cache-hit branch (FIND-15) can re-check expiry
				// without a full trial lookup on every request within the cache window.
				await env.RATE_LIMIT.put(
					`tier:${keyHash}`,
					JSON.stringify({ tier: trialResult.tier, revokedAt: null, trialExpiresAt: trialResult.trialInfo.expiresAt }),
					{ expirationTtl: TRIAL_KEY_CACHE_TTL },
				);
				const resolvedTier = applyOwnerIpGate(trialResult.tier, env.OWNER_ALLOW_IPS, clientIp);
				return { authenticated: true, tier: resolvedTier, keyHash };
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
					if (data.tier !== null) {
						// Cache the valid tier result
						if (env.RATE_LIMIT) {
							await env.RATE_LIMIT.put(
								`tier:${keyHash}`,
								JSON.stringify({ tier: data.tier, revokedAt: null }),
								{ expirationTtl: TIER_KV_CACHE_TTL },
							);
						}
						const resolvedTier = applyOwnerIpGate(data.tier, env.OWNER_ALLOW_IPS, clientIp);
						return { authenticated: true, tier: resolvedTier, keyHash };
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
			// Owner tier requires IP allowlist. If OWNER_ALLOW_IPS is set and non-empty
			// and the client IP is not in the list, downgrade to partner (still high
			// limits but not unlimited). If OWNER_ALLOW_IPS is unset, empty, or whitespace-
			// only, owner is unrestricted (backward compat for self-hosted/dev where
			// there's no IP filtering).
			const resolvedTier = applyOwnerIpGate('owner', env.OWNER_ALLOW_IPS, clientIp);
			return { authenticated: true, tier: resolvedTier, keyHash };
		}
	}

	return { authenticated: false };
}
