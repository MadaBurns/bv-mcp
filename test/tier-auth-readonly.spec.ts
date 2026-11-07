// SPDX-License-Identifier: BUSL-1.1
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, expect, it, vi } from 'vitest';
import type { QuotaCoordinator } from '../src/lib/quota-coordinator';

const issuer = 'https://example.com';
const secret = 'a'.repeat(32);
const readonly = { readOnly: true };

describe('read-only authentication', () => {
	it('missing and unresolved opaque credentials never access cache, trial, or remote validation', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const get = vi.fn(() => {
			throw new Error('forbidden read');
		});
		const fetch = vi.fn(() => {
			throw new Error('forbidden remote');
		});
		const options = {
			RATE_LIMIT: { get } as unknown as KVNamespace,
			BV_WEB: { fetch } as unknown as Fetcher,
			BV_WEB_INTERNAL_KEY: 'internal',
		};
		expect(await resolveTier(null, options, undefined, issuer, readonly)).toEqual({ authenticated: false });
		expect(await resolveTier('unknown', options, undefined, issuer, readonly)).toEqual({ authenticated: false, storageUnavailable: true });
		expect(get).not.toHaveBeenCalled();
		expect(fetch).not.toHaveBeenCalled();
	});

	it('static owner authentication preserves allowlist downgrade and principal identity', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const options = { BV_API_KEY: 'static-owner', OWNER_ALLOW_IPS: '203.0.113.1' };
		const owner = await resolveTier('static-owner', options, '203.0.113.1', issuer, readonly);
		const downgraded = await resolveTier('static-owner', options, '203.0.113.2', issuer, readonly);
		expect(owner).toMatchObject({ authenticated: true, tier: 'owner', ownerIpGate: 'allowed' });
		expect(downgraded).toMatchObject({ authenticated: true, tier: 'partner', ownerIpGate: 'denied', keyHash: owner.keyHash });
	});

	it('JWT owner gates use strong read-only operations and fail closed on unreadable state', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const { signJwt, newJti } = await import('../src/oauth/jwt');
		const { OAUTH_JWT_TTL_SECONDS } = await import('../src/lib/config');
		const token = await signJwt(
			{ sub: 'owner', jti: newJti(), tier: 'owner' },
			{ secret, ttlSeconds: OAUTH_JWT_TTL_SECONDS, issuer, audience: `${issuer}/mcp` },
		);
		const payloads: Array<{ kind: string; readOnly?: boolean }> = [];
		const dispatch = vi.fn(async (p: { kind: string; readOnly?: boolean }) => {
			payloads.push(p);
			return p.kind === 'marker-has' ? { present: false } : { value: 1 };
		});
		const namespace = { getByName: () => ({ dispatch }) } as unknown as DurableObjectNamespace<QuotaCoordinator>;
		const get = vi.fn(async () => null);
		const options = {
			OAUTH_SIGNING_SECRET: secret,
			OAUTH_ISSUER: issuer,
			SESSION_STORE: { get } as unknown as KVNamespace,
			QUOTA_COORDINATOR: namespace,
			OWNER_ALLOW_IPS: '203.0.113.1',
		};
		expect(await resolveTier(token, options, '203.0.113.1', issuer, readonly)).toMatchObject({
			authenticated: true,
			tier: 'owner',
			ownerIpGate: 'allowed',
		});
		expect(payloads).toHaveLength(3);
		expect(payloads.every((p) => p.readOnly === true)).toBe(true);
		dispatch.mockRejectedValue(new Error('state unavailable'));
		expect(await resolveTier(token, options, '203.0.113.1', issuer, readonly)).toEqual({ authenticated: false, storageUnavailable: true });
		expect((await resolveTier('bad.jwt.value', options, '203.0.113.1', issuer, readonly)).authenticated).toBe(false);
	});

	it('known legacy revocation is denied without migrating a marker', async () => {
		const { isRevoked } = await import('../src/oauth/storage');
		const dispatch = vi.fn(async () => ({ present: false }));
		const namespace = { getByName: () => ({ dispatch }) } as unknown as DurableObjectNamespace<QuotaCoordinator>;
		expect(await isRevoked({ get: async () => 'revoked' } as unknown as KVNamespace, 'jti', namespace, true)).toBe(true);
		expect(dispatch).toHaveBeenCalledTimes(1);
		expect(dispatch.mock.calls[0]).toEqual([{ kind: 'marker-has', coordinationKey: expect.any(String), readOnly: true }]);
	});

	it('unmigrated EMA registry is unavailable without a migration attempt', async () => {
		const { getEmaTenant } = await import('../src/oauth/ema-tenants');
		const dispatch = vi.fn(async () => ({ status: 'ema_not_migrated' }));
		const coordinator = { getByName: () => ({ dispatch }) } as unknown as DurableObjectNamespace<QuotaCoordinator>;
		await expect(getEmaTenant({ coordinator, kv: {} as KVNamespace }, 'tenant', true)).rejects.toThrow();
		expect(dispatch).toHaveBeenCalledTimes(1);
	});

	it('strong peeks leave absent version and expired marker records unchanged', async () => {
		const { getVersionWithCoordinator, hasMarkerWithCoordinator, securityStateShardNameForKey } =
			await import('../src/lib/quota-coordinator');
		const key = `readonly-${crypto.randomUUID()}`;
		const stub = env.QUOTA_COORDINATOR.getByName(securityStateShardNameForKey(key));
		await runInDurableObject(stub, async (_instance, state) => {
			await state.storage.deleteAll();
			await state.storage.put(`quota:strong:marker:${key}`, { count: 1, expiresAt: 1 });
		});
		const before = await runInDurableObject(stub, async (_instance, state) => Array.from(await state.storage.list()));
		expect(await getVersionWithCoordinator(key, 7, env.QUOTA_COORDINATOR, true)).toEqual({ value: 7 });
		expect(await hasMarkerWithCoordinator(key, env.QUOTA_COORDINATOR, true)).toEqual({ present: false });
		expect(await runInDurableObject(stub, async (_instance, state) => Array.from(await state.storage.list()))).toEqual(before);
		// Positive control: the ordinary operation really seeds the absent version.
		expect(await getVersionWithCoordinator(key, 7, env.QUOTA_COORDINATOR)).toEqual({ value: 7 });
		expect(await runInDurableObject(stub, async (_instance, state) => state.storage.get(`strong:version:${key}`))).toEqual({ value: 7 });
	});

	it('malformed strong records are unavailable rather than absent and remain unchanged', async () => {
		const { getVersionWithCoordinator, hasMarkerWithCoordinator, securityStateShardNameForKey } =
			await import('../src/lib/quota-coordinator');
		const key = `readonly-malformed-${crypto.randomUUID()}`;
		const stub = env.QUOTA_COORDINATOR.getByName(securityStateShardNameForKey(key));
		await runInDurableObject(stub, async (_instance, state) => {
			await state.storage.put(`quota:strong:marker:${key}`, { invalid: true });
			await state.storage.put(`strong:version:${key}`, { value: 'bad' });
		});
		const before = await runInDurableObject(stub, async (_instance, state) => Array.from(await state.storage.list()));
		await expect(getVersionWithCoordinator(key, 1, env.QUOTA_COORDINATOR, true)).rejects.toThrow('Unreadable');
		await expect(hasMarkerWithCoordinator(key, env.QUOTA_COORDINATOR, true)).rejects.toThrow('Unreadable');
		expect(await runInDurableObject(stub, async (_instance, state) => Array.from(await state.storage.list()))).toEqual(before);
	});
});
