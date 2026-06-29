import { SELF, env } from 'cloudflare:test';
import { afterEach, describe, expect, it } from 'vitest';

// Regression: some MCP clients (notably Claude Desktop connectors, especially when given a
// pre-registered OAuth Client ID) skip authorization-server metadata discovery and request the
// OAuth endpoints at the server origin (/register, /authorize, /token) instead of the /oauth/-
// prefixed paths advertised in discovery. A production tail showed Claude Desktop hitting
// `GET /authorize` → 404, surfacing as "Couldn't connect" / "Couldn't register". The root-path
// aliases (src/index.ts) fix this by routing root paths to the same handlers as /oauth/*.

async function clearPrefix(prefix: string) {
	const list = await env.SESSION_STORE.list({ prefix });
	await Promise.all(list.keys.map((k) => env.SESSION_STORE.delete(k.name)));
}

afterEach(async () => {
	await clearPrefix('oauth:');
});

describe('root-path OAuth aliases', () => {
	it('POST /register behaves like /oauth/register (201 + client_id, not 404)', async () => {
		const res = await SELF.fetch('https://example.com/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ client_name: 'Claude Desktop', redirect_uris: ['https://claude.ai/cb'] }),
		});
		expect(res.status).toBe(201);
		const body = (await res.json()) as Record<string, unknown>;
		expect(typeof body.client_id).toBe('string');
		expect(body.token_endpoint_auth_method).toBe('none');
	});

	it('GET /authorize resolves a registered client (not 404)', async () => {
		// Register via the root alias, then authorize via the root alias.
		const reg = await SELF.fetch('https://example.com/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: ['https://claude.ai/cb'] }),
		});
		const cid = ((await reg.json()) as { client_id: string }).client_id;

		const url = new URL('https://example.com/authorize');
		url.searchParams.set('client_id', cid);
		url.searchParams.set('redirect_uri', 'https://claude.ai/cb');
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 'stateval');
		url.searchParams.set('code_challenge', 'x'.repeat(43));
		url.searchParams.set('code_challenge_method', 'S256');
		const res = await SELF.fetch(url.toString(), { redirect: 'manual' });
		// The customer-OAuth path (ENABLE_OWNER_OAUTH unset) 302-redirects to the consent URL;
		// the owner path renders 200 HTML. Either way it must NOT 404 — that's the bug.
		expect(res.status).not.toBe(404);
		expect([200, 302, 503]).toContain(res.status);
	});

	it('POST /token reaches the token handler (not 404)', async () => {
		const res = await SELF.fetch('https://example.com/token', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: '',
		});
		// Empty/invalid body → handler returns a 4xx OAuth error, NOT a 404 route miss.
		expect(res.status).not.toBe(404);
		expect(res.status).toBeGreaterThanOrEqual(400);
		expect(res.status).toBeLessThan(500);
	});

	it('GET /authorize with an unknown client_id is handled (not 404 route miss)', async () => {
		const url = new URL('https://example.com/authorize');
		url.searchParams.set('client_id', 'nonexistent-client');
		url.searchParams.set('redirect_uri', 'https://claude.ai/cb');
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 'stateval');
		url.searchParams.set('code_challenge', 'x'.repeat(43));
		url.searchParams.set('code_challenge_method', 'S256');
		const res = await SELF.fetch(url.toString(), { redirect: 'manual' });
		// Handler returns 400 "Unknown client_id"; the catch-all route miss would be 404.
		expect(res.status).toBe(400);
	});
});
