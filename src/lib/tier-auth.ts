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
import { OAUTH_JWT_CLOCK_SKEW_SECONDS, OAUTH_JWT_TTL_SECONDS, parseOwnerAllowIps, TRIAL_KEY_CACHE_TTL } from './config';
import { TierCacheEntrySchema, ValidateKeyResponseSchema } from '../schemas/auth';
import { resolveTrialKey } from './trial-keys';
import { parseEnvelopeKey } from './kv-envelope';
import { verifyJwt } from '../oauth/jwt';
import { resolveIssuerStrict } from '../oauth/discovery';
import { getMinimumEntitlementGeneration, isRevoked, getTokenVersion } from '../oauth/storage';
import { z } from 'zod';
import type { QuotaCoordinator } from './quota-coordinator';
import { checkControlPlaneRateLimit } from './rate-limiter';
import { disposeUnreadResponseBody, readJsonResponseCapped } from './response-body';
import { deriveCanonicalOAuthPrincipal } from './auth-principal';

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
	/** Stable 256-bit security principal used for quota, ownership, and downstream authorization. */
	keyHash?: string;
	/** Previous 16-hex owner id for bounded, authenticated durable-row reconciliation. */
	legacyOwnerId?: string;
	/** Full raw credential digest for API-key-backed downstream identity lookup; never set for OAuth JWTs. */
	credentialHash?: string;
	/** Verified OAuth tenant subject; absent for opaque/static credentials. */
	oauthTenantId?: string;
	/** An uncached remote entitlement lookup was denied by the pre-auth abuse gate. */
	rateLimited?: boolean;
	retryAfterMs?: number;
	/**
	 * Per-contract enumeration entitlement (D2 contract-flag gate). Set only from a
	 * JWT `contractFlag` claim; absent/false everywhere until bv-web-prod emits it.
	 * Consumed by `contractFlagBlocks()` — inert until `ENFORCE_CONTRACT_FLAG_GATE`.
	 */
	contractFlag?: boolean;
}

const TIER_KV_CACHE_TTL = 300; // 5 minutes

/** Remote entitlement validation is tiny JSON; anything larger is invalid. */
export const BV_WEB_VALIDATE_KEY_MAX_BODY_BYTES = 16 * 1024;
/** Keep an unavailable entitlement service from pinning public Worker requests. */
export const BV_WEB_VALIDATE_KEY_TIMEOUT_MS = 5_000;
/** Uses the existing 60/minute, 600/hour control-plane thresholds on a distinct key. */
export const AUTH_RESOLUTION_MINUTE_LIMIT = 60;
const AUTH_RESOLUTION_RATE_KEY_PREFIX = 'auth-resolution:';

/** @internal Exported for focused timeout regression tests. */
export async function fetchBvWebValidateKey(
	fetcher: Fetcher,
	internalKey: string,
	keyHash: string,
	timeoutMs = BV_WEB_VALIDATE_KEY_TIMEOUT_MS,
): Promise<{ kind: 'ok'; data: unknown } | { kind: 'http'; status: number }> {
	const controller = new AbortController();
	const timeoutId = setTimeout(
		() => controller.abort(new DOMException('BV_WEB validate-key timed out', 'TimeoutError')),
		timeoutMs,
	);
	try {
		const response = await fetcher.fetch(
			new Request('https://internal/api/internal/mcp/validate-key', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${internalKey}`,
				},
				body: JSON.stringify({ keyHash }),
				signal: controller.signal,
			}),
		);
		if (!response.ok) {
			const status = response.status;
			await disposeUnreadResponseBody(response);
			return { kind: 'http', status };
		}
		const data = await readJsonResponseCapped<unknown>(response, BV_WEB_VALIDATE_KEY_MAX_BODY_BYTES);
		// The bounded reader intentionally converts stream failures to null. Preserve
		// timeout semantics here so a headers-then-stalled body is still denied rather
		// than being mistaken for a valid entitlement response.
		if (controller.signal.aborted) {
			throw controller.signal.reason ?? new DOMException('BV_WEB validate-key timed out', 'TimeoutError');
		}
		return { kind: 'ok', data };
	} finally {
		clearTimeout(timeoutId);
	}
}

/** SHA-256 digest as raw bytes (for constant-time comparison and hex derivation). */
async function hashTokenRaw(token: string): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token)));
}

/**
 * Constant-time comparison of a presented token's raw SHA-256 digest against a
 * candidate static key. Returns false for an absent candidate. Comparison is
 * constant-time XOR over the digests (never short-circuits on first mismatch)
 * so it cannot leak the secret via timing.
 */
async function matchesStaticDevKey(tokenRaw: Uint8Array, candidate: string | undefined): Promise<boolean> {
	if (!candidate) return false;
	const b = await hashTokenRaw(candidate);
	// Both operands are fixed-length 32-byte SHA-256 digests, so iterate the
	// full digest with no length term (matches auth.ts and the step-4 fallback
	// compare below). Never short-circuits on first mismatch → no timing leak.
	let mismatch = 0;
	for (let i = 0; i < tokenRaw.byteLength; i++) {
		mismatch |= tokenRaw[i] ^ b[i];
	}
	return mismatch === 0;
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
		BV_INTERNAL_DEV_KEY_2?: string;
		OWNER_ALLOW_IPS?: string;
		RATE_LIMIT?: KVNamespace;
		BV_WEB?: Fetcher;
		BV_WEB_INTERNAL_KEY?: string;
		OAUTH_SIGNING_SECRET?: string;
		OAUTH_ISSUER?: string;
		SESSION_STORE?: KVNamespace;
		QUOTA_COORDINATOR?: DurableObjectNamespace<QuotaCoordinator>;
		KV_ENVELOPE_KEY?: string;
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
	// allowlisted IP could mint a bearer JWT usable from any subsequent IP. We now mirror the
	// BV_API_KEY path: when OWNER_ALLOW_IPS is configured and the requesting clientIp isn't in
	// it, downgrade to 'partner' tier. Empty/unset allowlist preserves backward compat for
	// self-hosted/dev installations that don't IP-gate their owner.
	if (env.OAUTH_SIGNING_SECRET && env.SESSION_STORE && token.split('.').length === 3) {
		try {
			// Fail closed on a Host that doesn't match a pinned OAUTH_ISSUER: resolveIssuerStrict
			// throws, the surrounding catch swallows it, and control falls through to the static-key
			// path — which a 3-segment JWT can't satisfy, yielding an unauthenticated result. When
			// OAUTH_ISSUER is unset (self-hosts) it stays a no-op Host-derivation, so their tokens
			// still verify against their own Host (security-audit item 9).
			const issuer = resolveIssuerStrict(requestUrl, env.OAUTH_ISSUER);
			const claims = await verifyJwt(token, {
				secret: env.OAUTH_SIGNING_SECRET,
				issuer,
				audience: `${issuer}/mcp`,
				clockSkewSeconds: OAUTH_JWT_CLOCK_SKEW_SECONDS,
				maxLifetimeSeconds: OAUTH_JWT_TTL_SECONDS,
			});
			const tierResult = JwtIssuableTierSchema.safeParse(claims.tier);
			if (typeof claims.sub === 'string' && tierResult.success) {
				if (await isRevoked(env.SESSION_STORE, claims.jti, env.QUOTA_COORDINATOR)) {
					return { authenticated: false };
				}
				// Token-version check (FIND-13): reject tokens whose `ver` claim is
				// less than the current per-subject counter. Absent `ver` defaults to
				// 1 (backward compat for JWTs minted before this feature was deployed).
				const storedVer = await getTokenVersion(env.SESSION_STORE, claims.sub, env.QUOTA_COORDINATOR);
				const tokenVer = typeof claims.ver === 'number' ? claims.ver : 1;
				if (tokenVer < storedVer) {
					return { authenticated: false };
				}
				// A monotonic entitlement generation makes delayed revocation delivery safe:
				// an old event can raise the floor for old tokens without invalidating a token
				// minted after the plan transition. Pre-claim JWTs remain generation 1.
				const minimumEntitlementGeneration = await getMinimumEntitlementGeneration(
					env.SESSION_STORE,
					claims.sub,
					env.QUOTA_COORDINATOR,
				);
				const tokenEntitlementGeneration = typeof claims.entitlementGeneration === 'number' ? claims.entitlementGeneration : 1;
				if (tokenEntitlementGeneration < minimumEntitlementGeneration) {
					return { authenticated: false };
				}
				const resolvedTier = applyOwnerIpGate(tierResult.data, env.OWNER_ALLOW_IPS, clientIp);
				// OAuth access tokens rotate, but the authenticated security principal must
				// not. Key quotas, concurrency limits, audit ownership, and downstream M365
				// authorization to a domain-separated hash of the verified issuer + subject.
				// Including the raw token or jti here would let one subscriber multiply every
				// limit merely by minting another access token and would orphan resources at
				// each hourly renewal. Static/cache/trial credentials remain keyed by their
				// credential digest below because those credentials have no signed subject.
				const principalKind = tierResult.data === 'owner' ? 'owner' : 'tenant';
				const jwtKeyHash = await deriveCanonicalOAuthPrincipal(issuer, claims.sub, principalKind);
				const legacyOwnerId = Array.from(await hashTokenRaw(token))
					.map((b) => b.toString(16).padStart(2, '0'))
					.join('')
					.slice(0, 16);
				// D2 contract-flag entitlement — carried as a boolean JWT claim by
				// bv-web-prod once the developer-claim carve-out lands. Absent today →
				// undefined (falsy); the gate stays inert until both the claim and
				// ENFORCE_CONTRACT_FLAG_GATE are in place.
				const contractFlag = claims.contractFlag === true;
				return {
					authenticated: true,
					tier: resolvedTier,
					keyHash: jwtKeyHash,
					legacyOwnerId,
					...(principalKind === 'tenant' ? { oauthTenantId: claims.sub } : {}),
					contractFlag,
				};
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

	// 0. Static internal-dev key short-circuit. The dev keys are hardcoded
	// "us only" secrets (load tests, ops scripts); they must not be subject to
	// KV-cache staleness or bv-web validate-key fallback — those paths can
	// quietly demote them to partner-tier and crash benchmarks on the 200/mo
	// quota. Comparison is constant-time XOR over raw SHA-256 digests.
	// Two independent slots (BV_INTERNAL_DEV_KEY + BV_INTERNAL_DEV_KEY_2) allow
	// adding a per-machine key without rotating the shared one out from under
	// other consumers. Both resolve to owner tier and remain OWNER_ALLOW_IPS-gated.
	if (
		(await matchesStaticDevKey(tokenRaw, env.BV_INTERNAL_DEV_KEY)) ||
		(await matchesStaticDevKey(tokenRaw, env.BV_INTERNAL_DEV_KEY_2))
	) {
		const resolvedTier = applyOwnerIpGate('owner', env.OWNER_ALLOW_IPS, clientIp);
		return { authenticated: true, tier: resolvedTier, keyHash, legacyOwnerId: keyHash.slice(0, 16), credentialHash: keyHash };
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
					// Trial cache entries may accelerate discovery but may never authorize:
					// every successful trial request must atomically consume one use.
					if (cacheResult.data.trialExpiresAt !== undefined) {
						await env.RATE_LIMIT.delete(`tier:${keyHash}`);
						if (cacheResult.data.trialExpiresAt < Date.now()) return { authenticated: false };
					} else {
						const resolvedTier = applyOwnerIpGate(cacheResult.data.tier, env.OWNER_ALLOW_IPS, clientIp);
						return { authenticated: true, tier: resolvedTier, keyHash, legacyOwnerId: keyHash.slice(0, 16), credentialHash: keyHash };
					}
				}
			}
		} catch {
			// Invalid cache entry, fall through
		}
	}

	// 2. Try trial key lookup
	if (env.RATE_LIMIT) {
		try {
			const trialResult = await resolveTrialKey(
				env.RATE_LIMIT,
				keyHash,
				parseEnvelopeKey(env.KV_ENVELOPE_KEY) ?? undefined,
				env.QUOTA_COORDINATOR,
			);
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
				// Deliberately do not positive-cache trials: a cache hit would bypass
				// atomic maxUses consumption. Negative entries remain short-lived.
				const resolvedTier = applyOwnerIpGate(trialResult.tier, env.OWNER_ALLOW_IPS, clientIp);
				return { authenticated: true, tier: resolvedTier, keyHash, legacyOwnerId: keyHash.slice(0, 16), credentialHash: keyHash };
			}
		} catch {
			// Trial lookup failed, fall through
		}
	}

	// 3. Try service binding to bv-web. Only uncached, non-trial credentials reach
	// this point. Give those resolutions a dedicated IP bucket before making the
	// service call so unique invalid bearer tokens cannot amplify into unbounded
	// BV_WEB requests. Prefixing the principal keeps this separate from ordinary
	// MCP control-plane quotas while reusing their distributed KV/DO machinery.
	let authResolutionRateLimited = false;
	let authResolutionRetryAfterMs: number | undefined;
	if (env.BV_WEB && env.BV_WEB_INTERNAL_KEY) {
		const resolutionRate = await checkControlPlaneRateLimit(
			`${AUTH_RESOLUTION_RATE_KEY_PREFIX}${clientIp ?? 'unknown'}`,
			env.RATE_LIMIT,
			env.QUOTA_COORDINATOR,
		);
		authResolutionRateLimited = !resolutionRate.allowed;
		authResolutionRetryAfterMs = resolutionRate.retryAfterMs;
	}

	if (env.BV_WEB && env.BV_WEB_INTERNAL_KEY && !authResolutionRateLimited) {
		try {
			const validationResponse = await fetchBvWebValidateKey(env.BV_WEB, env.BV_WEB_INTERNAL_KEY, keyHash);

			if (validationResponse.kind === 'ok') {
				const keyResult = ValidateKeyResponseSchema.safeParse(validationResponse.data);
				if (keyResult.success) {
					const data = keyResult.data;
					if (data.tier !== null) {
						// Cache the valid tier result (short-lived, 5 min)
						if (env.RATE_LIMIT) {
							await env.RATE_LIMIT.put(
								`tier:${keyHash}`,
								JSON.stringify({ tier: data.tier, revokedAt: null }),
								{ expirationTtl: TIER_KV_CACHE_TTL },
							);
						}
						const resolvedTier = applyOwnerIpGate(data.tier, env.OWNER_ALLOW_IPS, clientIp);
						return { authenticated: true, tier: resolvedTier, keyHash, legacyOwnerId: keyHash.slice(0, 16), credentialHash: keyHash };
					}
					// Null tier = definitive revocation or unknown key — cache negative result
					// to avoid repeated service binding calls within the TTL window.
					// This is a definitive "no entitlement" signal from bv-web.
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
			// Entitlement validation is an authorization boundary. Network failures,
			// timeouts, malformed bodies, and 5xx responses all fail closed. Serving a
			// stale positive result here would let a revoked bearer survive an outage.
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
			return { authenticated: true, tier: resolvedTier, keyHash, legacyOwnerId: keyHash.slice(0, 16), credentialHash: keyHash };
		}
	}

	return authResolutionRateLimited
		? { authenticated: false, rateLimited: true, retryAfterMs: authResolutionRetryAfterMs }
		: { authenticated: false };
}
