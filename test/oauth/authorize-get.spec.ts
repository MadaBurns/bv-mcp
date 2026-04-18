import { SELF, env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

async function clearPrefix(prefix: string) {
	const list = await env.SESSION_STORE.list({ prefix });
	await Promise.all(list.keys.map((k) => env.SESSION_STORE.delete(k.name)));
}

async function registerClient(): Promise<string> {
	const res = await SELF.fetch('https://example.com/oauth/register', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ redirect_uris: ['https://claude.ai/cb'] }),
	});
	return ((await res.json()) as { client_id: string }).client_id;
}

beforeEach(async () => {
	await clearPrefix('oauth:');
});
afterEach(async () => {
	await clearPrefix('oauth:');
});

describe('GET /oauth/authorize', () => {
	it('renders consent HTML for valid params', async () => {
		const cid = await registerClient();
		const url = new URL('https://example.com/oauth/authorize');
		url.searchParams.set('client_id', cid);
		url.searchParams.set('redirect_uri', 'https://claude.ai/cb');
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 'stateval');
		url.searchParams.set('code_challenge', 'x'.repeat(43));
		url.searchParams.set('code_challenge_method', 'S256');
		const res = await SELF.fetch(url.toString());
		expect(res.status).toBe(200);
		expect(res.headers.get('content-type')).toMatch(/text\/html/);
		expect(res.headers.get('x-frame-options')).toBe('DENY');
		const html = await res.text();
		expect(html).toContain('name="api_key"');
		expect(html).toContain(cid);
	});

	it('rejects unknown client_id', async () => {
		const url = new URL('https://example.com/oauth/authorize');
		url.searchParams.set('client_id', 'missing');
		url.searchParams.set('redirect_uri', 'https://claude.ai/cb');
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 's');
		url.searchParams.set('code_challenge', 'x'.repeat(43));
		url.searchParams.set('code_challenge_method', 'S256');
		const res = await SELF.fetch(url.toString());
		expect(res.status).toBe(400);
	});

	it('rejects redirect_uri not registered to client', async () => {
		const cid = await registerClient();
		const url = new URL('https://example.com/oauth/authorize');
		url.searchParams.set('client_id', cid);
		url.searchParams.set('redirect_uri', 'https://claude.ai/different');
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 's');
		url.searchParams.set('code_challenge', 'x'.repeat(43));
		url.searchParams.set('code_challenge_method', 'S256');
		const res = await SELF.fetch(url.toString());
		expect(res.status).toBe(400);
	});

	it('rejects missing code_challenge', async () => {
		const cid = await registerClient();
		const url = new URL('https://example.com/oauth/authorize');
		url.searchParams.set('client_id', cid);
		url.searchParams.set('redirect_uri', 'https://claude.ai/cb');
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 's');
		const res = await SELF.fetch(url.toString());
		expect(res.status).toBe(400);
	});

	it('rejects code_challenge_method=plain', async () => {
		const cid = await registerClient();
		const url = new URL('https://example.com/oauth/authorize');
		url.searchParams.set('client_id', cid);
		url.searchParams.set('redirect_uri', 'https://claude.ai/cb');
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 's');
		url.searchParams.set('code_challenge', 'x'.repeat(43));
		url.searchParams.set('code_challenge_method', 'plain');
		const res = await SELF.fetch(url.toString());
		expect(res.status).toBe(400);
	});
});
