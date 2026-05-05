import { SELF, createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../../src/index';

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
		expect(res.headers.get('content-security-policy')).toContain("default-src 'self'");
		expect(res.headers.get('content-security-policy')).toContain("form-action 'self'");
		expect(res.headers.get('cache-control')).toBe('no-store');
		const html = await res.text();
		expect(html).toContain('name="api_key"');
		expect(html).toContain(cid);
		// _q must round-trip the full original query (Phase 6 relies on this).
		expect(html).toContain('name="_q"');
		expect(html).toContain(`client_id=${cid}`);
		expect(html).toContain('code_challenge=');
		expect(html).toContain('state=stateval');
	});

	it('does not render owner API key consent when owner OAuth is disabled', async () => {
		const cid = await registerClient();
		const url = new URL('https://example.com/oauth/authorize');
		url.searchParams.set('client_id', cid);
		url.searchParams.set('redirect_uri', 'https://claude.ai/cb');
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 'stateval');
		url.searchParams.set('code_challenge', 'x'.repeat(43));
		url.searchParams.set('code_challenge_method', 'S256');
		const ctx = createExecutionContext();
		const res = await worker.fetch(new Request(url.toString()), { ...env, ENABLE_OAUTH: 'true', ENABLE_OWNER_OAUTH: 'false' }, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(503);
		const body = await res.text();
		expect(body).not.toContain('Owner API key');
		expect(body).not.toContain('name="api_key"');
	});

	it('redirects to bv-web customer consent when owner OAuth is disabled and customer consent is configured', async () => {
		const cid = await registerClient();
		const url = new URL('https://example.com/oauth/authorize');
		url.searchParams.set('client_id', cid);
		url.searchParams.set('redirect_uri', 'https://claude.ai/cb');
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 'stateval');
		url.searchParams.set('scope', 'mcp');
		url.searchParams.set('code_challenge', 'x'.repeat(43));
		url.searchParams.set('code_challenge_method', 'S256');
		const ctx = createExecutionContext();
		const res = await worker.fetch(
			new Request(url.toString(), { redirect: 'manual' }),
			{
				...env,
				ENABLE_OAUTH: 'true',
				ENABLE_OWNER_OAUTH: 'false',
				BV_WEB_OAUTH_CONSENT_URL: 'https://www.blackveilsecurity.com/oauth/mcp/consent',
			},
			ctx,
		);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(302);
		const location = new URL(res.headers.get('location') ?? '');
		expect(location.origin + location.pathname).toBe('https://www.blackveilsecurity.com/oauth/mcp/consent');
		expect(location.searchParams.get('client_id')).toBe(cid);
		expect(location.searchParams.get('redirect_uri')).toBe('https://claude.ai/cb');
		expect(location.searchParams.get('state')).toBe('stateval');
		expect(location.searchParams.get('scope')).toBe('mcp');
		expect(location.searchParams.get('code_challenge')).toBe('x'.repeat(43));
		expect(location.searchParams.get('code_challenge_method')).toBe('S256');
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

	it('returns plain text (not HTML) for 400 errors — defense against XSS via error paths', async () => {
		const url = new URL('https://example.com/oauth/authorize');
		url.searchParams.set('client_id', 'missing');
		url.searchParams.set('redirect_uri', 'https://claude.ai/cb');
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 's');
		url.searchParams.set('code_challenge', 'x'.repeat(43));
		url.searchParams.set('code_challenge_method', 'S256');
		const res = await SELF.fetch(url.toString());
		expect(res.status).toBe(400);
		const ct = res.headers.get('content-type') ?? '';
		expect(ct).not.toMatch(/text\/html/);
		const body = await res.text();
		expect(body).not.toContain('<!doctype html>');
		expect(body).not.toContain('<html');
	});
});
