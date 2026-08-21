// SPDX-License-Identifier: BUSL-1.1

import { isValidOAuthSigningSecret } from '../lib/config';
import { SINGLETON_ROUTING, type ShardRouting } from '../lib/quota-coordinator';

export type OAuthAvailability = 'ready' | 'disabled' | 'misconfigured';

type OAuthEnv = {
	ENABLE_OAUTH?: string;
	OAUTH_SIGNING_SECRET?: string;
};

type RuntimeConfigEnv = OAuthEnv & {
	BV_CERTSTREAM_ADMIN_KEY?: string;
	BV_INTERNAL_DEV_KEY?: string;
	CERTSPOTTER_TOKEN?: string;
	QUOTA_SHARDING_ENABLED?: string;
	QUOTA_SHARD_SALT?: string;
};

/** Resolve the OAuth route gate without coupling route registration to env parsing. */
export function resolveOAuthAvailability(env: OAuthEnv): OAuthAvailability {
	if (env.ENABLE_OAUTH !== 'true') return 'disabled';
	if (!isValidOAuthSigningSecret(env.OAUTH_SIGNING_SECRET)) return 'misconfigured';
	return 'ready';
}

/** Prefer the dedicated token while preserving the legacy internal-key fallback. */
export function resolveCertstreamAuthToken(env: RuntimeConfigEnv): string | undefined {
	return env.BV_CERTSTREAM_ADMIN_KEY || env.BV_INTERNAL_DEV_KEY;
}

/**
 * SSLMate Cert Spotter API token, sent as `Authorization: Bearer` on CT queries.
 *
 * Absent → the CT source stays UNAUTHENTICATED and functional, on a per-IP,
 * per-hour quota that a batch sweep exhausts (measured 2026-08-21: HTTP 429
 * `rate_limited`, "For a higher rate limit, please authenticate with an API key").
 * Fail-soft by design — this must never become a hard dependency, because a
 * missing token degrades recall rather than breaking enumeration.
 *
 * ⚠️ A token raises RATE LIMITS, not the per-query timeout. The free "Small" tier
 * still cuts a query at 15s, so a large estate keeps returning HTTP 504
 * (`meta.com`, measured authenticated 2026-08-21) — that is #735's deterministic
 * timeout and only a paid tier's longer timeout addresses it.
 *
 * Named to match `cloudflare/certstream` in bv-web-prod, which already resolves
 * the same secret under this name; one secret must not acquire two spellings.
 */
export function resolveCertspotterToken(env: RuntimeConfigEnv): string | undefined {
	return env.CERTSPOTTER_TOKEN || undefined;
}

/** Build quota routing with the existing default-off behavior. */
export function resolveQuotaShardRouting(env: RuntimeConfigEnv): ShardRouting {
	if (env.QUOTA_SHARDING_ENABLED !== 'true') return SINGLETON_ROUTING;
	return { enabled: true, salt: env.QUOTA_SHARD_SALT ?? '' };
}
