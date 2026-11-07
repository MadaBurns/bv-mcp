// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it, vi } from 'vitest';
import type { QuotaCoordinator } from '../src/lib/quota-coordinator';

describe('read-only strong-state mixed-version compatibility', () => {
	it('canonical JWT authentication becomes unavailable against an old coordinator', async () => {
		const { resolveTier } = await import('../src/lib/tier-auth');
		const { signJwt, newJti } = await import('../src/oauth/jwt');
		const { OAUTH_JWT_TTL_SECONDS } = await import('../src/lib/config');
		const calls: string[] = [];
		const coordinator = {
			getByName: () => ({
				dispatch: async (p: { kind: string }) => {
					calls.push(p.kind);
					throw new TypeError('Invalid payload: unknown kind');
				},
			}),
		} as unknown as DurableObjectNamespace<QuotaCoordinator>;
		const issuer = 'https://example.com';
		const secret = 'a'.repeat(32);
		const token = await signJwt(
			{ sub: 'owner', jti: newJti(), tier: 'owner' },
			{ secret, issuer, audience: `${issuer}/mcp`, ttlSeconds: OAUTH_JWT_TTL_SECONDS },
		);
		expect(
			await resolveTier(
				token,
				{
					OAUTH_SIGNING_SECRET: secret,
					OAUTH_ISSUER: issuer,
					SESSION_STORE: { get: async () => null } as unknown as KVNamespace,
					QUOTA_COORDINATOR: coordinator,
				},
				undefined,
				`${issuer}/mcp`,
				{ readOnly: true },
			),
		).toEqual({ authenticated: false, storageUnavailable: true });
		expect(calls).toEqual(['marker-peek']);
	});
	it('old RPC rejection becomes unavailable without retrying mutating legacy operations', async () => {
		const { isRevoked, getTokenVersion } = await import('../src/oauth/storage');
		const calls: string[] = [];
		const dispatch = vi.fn(async (p: { kind: string }) => {
			calls.push(p.kind);
			if (p.kind === 'marker-peek' || p.kind === 'version-peek') throw new TypeError('Invalid payload: unknown kind');
			throw new Error('Legacy operation must never be attempted');
		});
		const coordinator = { getByName: () => ({ dispatch }) } as unknown as DurableObjectNamespace<QuotaCoordinator>;
		const kv = { get: async () => null } as unknown as KVNamespace;
		await expect(isRevoked(kv, 'token', coordinator, true)).rejects.toThrow('unavailable');
		await expect(getTokenVersion(kv, 'subject', coordinator, true)).rejects.toThrow('unavailable');
		expect(calls).toEqual(['marker-peek', 'version-peek']);
	});

	it('old HTTP validation failure does not fall back to legacy operations', async () => {
		const { isRevoked, getTokenVersion } = await import('../src/oauth/storage');
		const kinds: string[] = [];
		const fetch = vi.fn(async (_url: string, init: RequestInit) => {
			const payload = JSON.parse(String(init.body)) as { kind: string };
			kinds.push(payload.kind);
			return new Response('Invalid payload: unknown kind', { status: 400 });
		});
		const coordinator = { getByName: () => ({ fetch }) } as unknown as DurableObjectNamespace<QuotaCoordinator>;
		const kv = { get: async () => null } as unknown as KVNamespace;
		await expect(isRevoked(kv, 'token', coordinator, true)).rejects.toThrow('unavailable');
		await expect(getTokenVersion(kv, 'subject', coordinator, true)).rejects.toThrow('unavailable');
		expect(kinds).toEqual(['marker-peek', 'version-peek']);
	});

	it('peek and legacy operations use identical frozen security shards and legacy flag is rejected', async () => {
		const { hasMarkerWithCoordinator, getVersionWithCoordinator, securityStateShardNameForKey, validateQuotaPayload } =
			await import('../src/lib/quota-coordinator');
		const names: string[] = [];
		const calls: string[] = [];
		const coordinator = {
			getByName: (name: string) => {
				names.push(name);
				return {
					dispatch: async (p: { kind: string }) => {
						calls.push(p.kind);
						return p.kind.startsWith('marker-') ? { present: false } : { value: 1 };
					},
				};
			},
		} as unknown as DurableObjectNamespace<QuotaCoordinator>;
		await hasMarkerWithCoordinator('same-key', coordinator, true);
		await hasMarkerWithCoordinator('same-key', coordinator);
		await getVersionWithCoordinator('same-key', 1, coordinator, true);
		await getVersionWithCoordinator('same-key', 1, coordinator);
		expect(names).toEqual(Array(4).fill(securityStateShardNameForKey('same-key')));
		expect(calls).toEqual(['marker-peek', 'marker-has', 'version-peek', 'version-get']);
		expect(validateQuotaPayload({ kind: 'marker-has', coordinationKey: 'same-key', readOnly: true }).valid).toBe(false);
		expect(validateQuotaPayload({ kind: 'evaluate', shardKey: 'same-key', checks: [], readOnly: true }).valid).toBe(false);
		expect(validateQuotaPayload({ kind: 'version-peek', coordinationKey: 'same-key', defaultValue: 0 }).valid).toBe(false);
	});
});
