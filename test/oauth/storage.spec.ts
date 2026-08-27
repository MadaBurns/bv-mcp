import { env } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { clearKvPrefix } from '../helpers/kv';
import { resetQuotaCoordinatorState } from '../../src/lib/quota-coordinator';

afterEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

describe('oauth/storage — client registration', () => {
	it('putClient + getClient round-trip', async () => {
		const { putClient, getClient } = await import('../../src/oauth/storage');
		const rec = { client_id: 'c1', client_id_issued_at: 1, redirect_uris: ['https://claude.ai/cb'] };
		await putClient(env.SESSION_STORE as unknown as KVNamespace, rec);
		const got = await getClient(env.SESSION_STORE as unknown as KVNamespace, 'c1');
		expect(got?.client_id).toBe('c1');
	});

	it('getClient returns null for unknown id', async () => {
		const { getClient } = await import('../../src/oauth/storage');
		const got = await getClient(env.SESSION_STORE as unknown as KVNamespace, 'missing');
		expect(got).toBeNull();
	});

	it('getClient returns null when stored value is corrupt JSON', async () => {
		const { getClient } = await import('../../src/oauth/storage');
		// Write bad data directly under the oauth:client: prefix
		await env.SESSION_STORE.put('oauth:client:corrupt', 'not-json');
		const got = await getClient(env.SESSION_STORE as unknown as KVNamespace, 'corrupt');
		expect(got).toBeNull();
	});

	it('getClient returns null when stored value fails schema validation', async () => {
		const { getClient } = await import('../../src/oauth/storage');
		await env.SESSION_STORE.put('oauth:client:bad-shape', JSON.stringify({ foo: 'bar' }));
		const got = await getClient(env.SESSION_STORE as unknown as KVNamespace, 'bad-shape');
		expect(got).toBeNull();
	});
});

describe('oauth/storage — authorization codes', () => {
	it('putCode + consumeCode round-trip (single use)', async () => {
		const { putCode, consumeCode } = await import('../../src/oauth/storage');
		await putCode(env.SESSION_STORE as unknown as KVNamespace, 'code1', {
			client_id: 'c1',
			redirect_uri: 'https://claude.ai/cb',
			code_challenge: 'x'.repeat(43),
			issued_at: Math.floor(Date.now() / 1000),
		});
		const first = await consumeCode(env.SESSION_STORE as unknown as KVNamespace, 'code1', undefined, env.QUOTA_COORDINATOR);
		expect(first?.client_id).toBe('c1');
		const second = await consumeCode(env.SESSION_STORE as unknown as KVNamespace, 'code1', undefined, env.QUOTA_COORDINATOR);
		expect(second).toBeNull();
	});

	it('allows exactly one concurrent code exchange', async () => {
		const { putCode, consumeCode } = await import('../../src/oauth/storage');
		await putCode(env.SESSION_STORE as unknown as KVNamespace, 'code-race', {
			client_id: 'c1',
			redirect_uri: 'https://claude.ai/cb',
			code_challenge: 'x'.repeat(43),
			issued_at: Math.floor(Date.now() / 1000),
		});
		const results = await Promise.all(
			Array.from({ length: 20 }, () =>
				consumeCode(env.SESSION_STORE as unknown as KVNamespace, 'code-race', undefined, env.QUOTA_COORDINATOR),
			),
		);
		expect(results.filter(Boolean)).toHaveLength(1);
	});
});

describe('oauth/storage — revocation', () => {
	it('revoke + isRevoked', async () => {
		const { revokeJti, isRevoked } = await import('../../src/oauth/storage');
		expect(await isRevoked(env.SESSION_STORE as unknown as KVNamespace, 'j1', env.QUOTA_COORDINATOR)).toBe(false);
		await revokeJti(env.SESSION_STORE as unknown as KVNamespace, 'j1', 60, env.QUOTA_COORDINATOR);
		expect(await isRevoked(env.SESSION_STORE as unknown as KVNamespace, 'j1', env.QUOTA_COORDINATOR)).toBe(true);
	});

	it('revokeJti clamps TTL to KV minimum of 60s when given smaller ttl', async () => {
		const { revokeJti, isRevoked } = await import('../../src/oauth/storage');
		// Should not throw — Math.max(60, 10) = 60 satisfies KV minimum
		await revokeJti(env.SESSION_STORE as unknown as KVNamespace, 'j-small-ttl', 10, env.QUOTA_COORDINATOR);
		expect(await isRevoked(env.SESSION_STORE as unknown as KVNamespace, 'j-small-ttl', env.QUOTA_COORDINATOR)).toBe(true);
	});
});

function kvReturning(value: string | null): KVNamespace {
	return {
		get: vi.fn().mockResolvedValue(value),
		put: vi.fn().mockResolvedValue(undefined),
		delete: vi.fn().mockResolvedValue(undefined),
	} as unknown as KVNamespace;
}

function coordinatorReturning(value: unknown): typeof env.QUOTA_COORDINATOR {
	return {
		getByName: vi.fn().mockReturnValue({ dispatch: vi.fn().mockResolvedValue(value) }),
	} as unknown as typeof env.QUOTA_COORDINATOR;
}

describe('oauth/storage — malformed coordinator responses fail closed', () => {
	it('rejects a malformed single-use-code claim response', async () => {
		const { consumeCode, StrongStateUnavailableError } = await import('../../src/oauth/storage');
		const kv = kvReturning(
			JSON.stringify({
				client_id: 'client',
				redirect_uri: 'https://claude.ai/cb',
				code_challenge: 'x'.repeat(43),
				issued_at: Math.floor(Date.now() / 1000),
			}),
		);

		await expect(
			consumeCode(kv, 'malformed-claim', undefined, coordinatorReturning({ claimed: 'yes' })),
		).rejects.toBeInstanceOf(StrongStateUnavailableError);
	});

	it('rejects malformed revocation marker write and read responses', async () => {
		const { isRevoked, revokeJti, StrongStateUnavailableError } = await import('../../src/oauth/storage');
		const kv = kvReturning(null);

		await expect(revokeJti(kv, 'jti', 60, coordinatorReturning({ present: 1 }))).rejects.toBeInstanceOf(
			StrongStateUnavailableError,
		);
		await expect(isRevoked(kv, 'jti', coordinatorReturning({}))).rejects.toBeInstanceOf(
			StrongStateUnavailableError,
		);
	});

	it('rejects malformed token and entitlement version responses', async () => {
		const {
			bumpTokenVersion,
			getMinimumEntitlementGeneration,
			getTokenVersion,
			raiseMinimumEntitlementGeneration,
			StrongStateUnavailableError,
		} = await import('../../src/oauth/storage');
		const kv = kvReturning(null);

		for (const operation of [
			() => getTokenVersion(kv, 'subject', coordinatorReturning({ value: 0 })),
			() => bumpTokenVersion(kv, 'subject', coordinatorReturning({ value: 1.5 })),
			() => getMinimumEntitlementGeneration(kv, 'subject', coordinatorReturning({ value: '2' })),
			() => raiseMinimumEntitlementGeneration(kv, 'subject', 2, coordinatorReturning({ value: 2, extra: true })),
		]) {
			await expect(operation()).rejects.toBeInstanceOf(StrongStateUnavailableError);
		}
	});

	it('rejects malformed idempotent version-bump replay responses', async () => {
		const { bumpTokenVersionIdempotently, StrongStateUnavailableError } = await import('../../src/oauth/storage');

		await expect(
			bumpTokenVersionIdempotently(
				kvReturning(null),
				'subject',
				'idempotency-key',
				'request-hash',
				Date.now() + 60_000,
				coordinatorReturning({ state: 'complete' }),
			),
		).rejects.toBeInstanceOf(StrongStateUnavailableError);
	});
});
