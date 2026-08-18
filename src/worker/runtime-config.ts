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

/** Build quota routing with the existing default-off behavior. */
export function resolveQuotaShardRouting(env: RuntimeConfigEnv): ShardRouting {
	if (env.QUOTA_SHARDING_ENABLED !== 'true') return SINGLETON_ROUTING;
	return { enabled: true, salt: env.QUOTA_SHARD_SALT ?? '' };
}
