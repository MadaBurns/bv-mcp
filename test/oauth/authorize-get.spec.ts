import { SELF, createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../../src/index';
import { putClient } from '../../src/oauth/storage';
import { clearKvPrefix } from '../helpers/kv';

const CLAUDE_WEB_CIMD = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
const CLAUDE_CODE_CIMD = 'https://claude.ai/oauth/claude-code-client-metadata';
const CLAUDE_CODE_DOC = {
	client_id: CLAUDE_CODE_CIMD,
	client_name: 'Claude Code',
	redirect_uris: ['http://localhost/callback', 'http://127.0.0.1/callback'],
	token_endpoint_auth_method: 'none',
};

/** Serve `doc` at its own client_id URL; every other fetch goes to the real implementation. */
function stubCimdDocument(doc: { client_id: string } & Record<string, unknown>) {
	const realFetch = globalThis.fetch;
	const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (url !== doc.client_id) return realFetch(input, init);
		return new Response(JSON.stringify(doc), { status: 200, headers: { 'content-type': 'application/json' } });
	});
	vi.stubGlobal('fetch', mock);
	return mock;
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
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
});
afterEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
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
		// Missing consent configuration is intentional; bypass deployment-literal typing only at the Worker boundary.
		const noConsentEnv: Omit<typeof env, 'BV_WEB_OAUTH_CONSENT_URL'> & { BV_WEB_OAUTH_CONSENT_URL?: string } = {
			...env, ENABLE_OAUTH: 'true', ENABLE_OWNER_OAUTH: 'false', BV_WEB_OAUTH_CONSENT_URL: undefined,
		};
		const res = await worker.fetch(new Request(url.toString()), noConsentEnv as Parameters<typeof worker.fetch>[1], ctx);
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

	it('rejects a legacy stored client whose raw redirect text disguises an attacker hostname', async () => {
		const clientId = 'legacy-parser-confusion-client';
		const maliciousRedirect = 'https://evil.example?.anthropic.com/cb';
		await putClient(env.SESSION_STORE as unknown as KVNamespace, {
			client_id: clientId,
			client_id_issued_at: Math.floor(Date.now() / 1000),
			redirect_uris: [maliciousRedirect],
		});
		const url = new URL('https://example.com/oauth/authorize');
		url.searchParams.set('client_id', clientId);
		url.searchParams.set('redirect_uri', maliciousRedirect);
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 's');
		url.searchParams.set('code_challenge', 'x'.repeat(43));
		url.searchParams.set('code_challenge_method', 'S256');

		const res = await SELF.fetch(url.toString(), { redirect: 'manual' });

		expect(res.status).toBe(400);
		expect(res.headers.get('location')).toBeNull();
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

describe('GET /oauth/authorize — Client ID Metadata Document clients', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	function cimdAuthorizeRequest(clientId: string, redirectUri: string): Request {
		const url = new URL('https://example.com/oauth/authorize');
		url.searchParams.set('client_id', clientId);
		url.searchParams.set('redirect_uri', redirectUri);
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('state', 'stateval');
		url.searchParams.set('code_challenge', 'x'.repeat(43));
		url.searchParams.set('code_challenge_method', 'S256');
		return new Request(url.toString(), { redirect: 'manual' });
	}

	it('renders consent for the Claude web CIMD client, naming its client_id host instead of its self-asserted name', async () => {
		const fetchMock = stubCimdDocument({
			client_id: CLAUDE_WEB_CIMD,
			client_name: 'Totally Your Bank',
			redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
			token_endpoint_auth_method: 'none',
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(cimdAuthorizeRequest(CLAUDE_WEB_CIMD, 'https://claude.ai/api/mcp/auth_callback'), env, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(200);
		const html = await res.text();
		expect(html).toContain('<title>Authorize claude.ai</title>');
		expect(html).toContain('Client <code>claude.ai</code>');
		expect(html).not.toContain('Totally Your Bank');
		expect(fetchMock).toHaveBeenCalledWith(CLAUDE_WEB_CIMD, expect.objectContaining({ redirect: 'manual' }));
	});

	it('accepts the Claude Code CIMD client on an ephemeral loopback port', async () => {
		stubCimdDocument(CLAUDE_CODE_DOC);
		const ctx = createExecutionContext();
		const res = await worker.fetch(cimdAuthorizeRequest(CLAUDE_CODE_CIMD, 'http://localhost:53682/callback'), env, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(200);
		expect(await res.text()).toContain('Client <code>claude.ai</code>');
	});

	it('rejects a CIMD client whose document does not list the requested redirect_uri', async () => {
		stubCimdDocument(CLAUDE_CODE_DOC);
		const ctx = createExecutionContext();
		const res = await worker.fetch(cimdAuthorizeRequest(CLAUDE_CODE_CIMD, 'http://localhost:53682/elsewhere'), env, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(400);
		expect(res.headers.get('location')).toBeNull();
	});
});
