// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { resolveCertstreamAuthToken, resolveOAuthAvailability, resolveQuotaShardRouting } from '../src/worker/runtime-config';

describe('worker runtime configuration', () => {
	it('preserves OAuth disabled, misconfigured, and ready states', () => {
		expect(resolveOAuthAvailability({})).toBe('disabled');
		expect(resolveOAuthAvailability({ ENABLE_OAUTH: 'true' })).toBe('misconfigured');
		expect(resolveOAuthAvailability({ ENABLE_OAUTH: 'true', OAUTH_SIGNING_SECRET: 'a'.repeat(32) })).toBe('ready');
	});

	it('preserves default-off quota routing and certstream token precedence', () => {
		expect(resolveQuotaShardRouting({})).toMatchObject({ enabled: false });
		expect(resolveQuotaShardRouting({ QUOTA_SHARDING_ENABLED: 'true', QUOTA_SHARD_SALT: 'salt' })).toEqual({ enabled: true, salt: 'salt' });
		expect(resolveCertstreamAuthToken({ BV_CERTSTREAM_ADMIN_KEY: 'dedicated', BV_INTERNAL_DEV_KEY: 'fallback' })).toBe('dedicated');
	});
});
