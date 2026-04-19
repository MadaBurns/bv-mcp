import { SELF, env } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';

async function clearPrefix(prefix: string) {
	const list = await env.SESSION_STORE.list({ prefix });
	await Promise.all(list.keys.map((k) => env.SESSION_STORE.delete(k.name)));
}

afterEach(async () => {
	await clearPrefix('oauth:');
});

describe('POST /oauth/register', () => {
	it('accepts a claude.ai redirect and returns 201 + client_id', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ client_name: 'Claude', redirect_uris: ['https://claude.ai/cb'] }),
		});
		expect(res.status).toBe(201);
		const body = (await res.json()) as Record<string, unknown>;
		expect(typeof body.client_id).toBe('string');
		expect(typeof body.client_id_issued_at).toBe('number');
		expect(body.token_endpoint_auth_method).toBe('none');
	});

	it('rejects redirect_uri outside allowlist', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: ['https://evil.example/cb'] }),
		});
		expect(res.status).toBe(400);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.error).toBe('invalid_redirect_uri');
	});

	it('rejects body missing redirect_uris', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ client_name: 'Claude' }),
		});
		expect(res.status).toBe(400);
		expect(((await res.json()) as Record<string, unknown>).error).toBe('invalid_client_metadata');
	});

	it('rejects body larger than 4 KB', async () => {
		const huge = 'x'.repeat(5000);
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ client_name: huge, redirect_uris: ['https://claude.ai/cb'] }),
		});
		expect(res.status).toBe(413);
	});

	it('rejects array where any redirect_uri is outside allowlist', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: ['https://claude.ai/cb', 'https://evil.example/cb'] }),
		});
		expect(res.status).toBe(400);
		const body = await res.json() as Record<string, unknown>;
		expect(body.error).toBe('invalid_redirect_uri');
	});

	it('rejects malformed JSON body with invalid_client_metadata', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: '{ not valid json',
		});
		expect(res.status).toBe(400);
		const body = await res.json() as Record<string, unknown>;
		expect(body.error).toBe('invalid_client_metadata');
	});
});
