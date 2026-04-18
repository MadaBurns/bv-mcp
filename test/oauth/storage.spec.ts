import { env } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';

async function clearPrefix(prefix: string) {
	const list = await env.SESSION_STORE.list({ prefix });
	await Promise.all(list.keys.map((k) => env.SESSION_STORE.delete(k.name)));
}

afterEach(async () => {
	await clearPrefix('oauth:');
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
});

describe('oauth/storage — authorization codes', () => {
	it('putCode + consumeCode round-trip (single use)', async () => {
		const { putCode, consumeCode } = await import('../../src/oauth/storage');
		await putCode(env.SESSION_STORE as unknown as KVNamespace, 'code1', {
			client_id: 'c1',
			redirect_uri: 'https://claude.ai/cb',
			code_challenge: 'x'.repeat(43),
			issued_at: 1,
		});
		const first = await consumeCode(env.SESSION_STORE as unknown as KVNamespace, 'code1');
		expect(first?.client_id).toBe('c1');
		const second = await consumeCode(env.SESSION_STORE as unknown as KVNamespace, 'code1');
		expect(second).toBeNull();
	});
});

describe('oauth/storage — revocation', () => {
	it('revoke + isRevoked', async () => {
		const { revokeJti, isRevoked } = await import('../../src/oauth/storage');
		expect(await isRevoked(env.SESSION_STORE as unknown as KVNamespace, 'j1')).toBe(false);
		await revokeJti(env.SESSION_STORE as unknown as KVNamespace, 'j1', 60);
		expect(await isRevoked(env.SESSION_STORE as unknown as KVNamespace, 'j1')).toBe(true);
	});
});
