import { SELF, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../../src/index';

// Phase 9: prove the full OAuth 2.1 mobile connector loop works end-to-end:
// register → authorize (POST consent) → token → /mcp Bearer. The plan's pseudocode
// used SELF.fetch and `env.BV_API_KEY`, but BV_API_KEY is intentionally not in the
// miniflare base env (see test/index.spec.ts:171 unauthenticated path regression),
// so we follow the codebase pattern from bearer-jwt.spec / authorize-post.spec and
// use `worker.fetch` with a merged env override for the full-flow test.

const TEST_API_KEY = 'testkey';
const TEST_SIGNING_SECRET = 'a'.repeat(32);

type TestEnv = typeof env & { BV_API_KEY?: string; OAUTH_SIGNING_SECRET?: string; OAUTH_ISSUER?: string };

const customEnv = {
	...env,
	BV_API_KEY: TEST_API_KEY,
	OAUTH_SIGNING_SECRET: TEST_SIGNING_SECRET,
	OAUTH_ISSUER: 'https://example.com',
} as TestEnv;

async function clearPrefix(prefix: string) {
	const list = await env.SESSION_STORE.list({ prefix });
	await Promise.all(list.keys.map((k) => env.SESSION_STORE.delete(k.name)));
}

function base64url(buf: ArrayBuffer): string {
	const b = new Uint8Array(buf);
	let s = '';
	for (const x of b) s += String.fromCharCode(x);
	return btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
	const buf = new Uint8Array(32);
	crypto.getRandomValues(buf);
	const verifier = base64url(buf.buffer);
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	return { verifier, challenge: base64url(digest) };
}

beforeEach(async () => {
	await clearPrefix('oauth:');
});
afterEach(async () => {
	await clearPrefix('oauth:');
});

describe('OAuth end-to-end', () => {
	it('completes register → authorize → token → /mcp ping', async () => {
		// Step 1: Dynamic Client Registration — doesn't require any secret.
		const regReq = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: ['https://claude.ai/cb'], client_name: 'E2E' }),
		});
		const regCtx = createExecutionContext();
		const regRes = await worker.fetch(regReq, customEnv, regCtx);
		await waitOnExecutionContext(regCtx);
		expect(regRes.status).toBe(201);
		const cid = ((await regRes.json()) as { client_id: string }).client_id;

		// Step 2: Consent POST — needs BV_API_KEY and (via code-challenge persistence) KV.
		const { verifier, challenge } = await pkcePair();
		const q = new URLSearchParams({
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			response_type: 'code',
			state: 'S',
			code_challenge: challenge,
			code_challenge_method: 'S256',
		}).toString();
		const consentBody = new URLSearchParams({ api_key: TEST_API_KEY, _q: q });
		const consentReq = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: consentBody.toString(),
			redirect: 'manual',
		});
		const consentCtx = createExecutionContext();
		const consentRes = await worker.fetch(consentReq, customEnv, consentCtx);
		await waitOnExecutionContext(consentCtx);
		expect(consentRes.status).toBe(302);
		const code = new URL(consentRes.headers.get('location') ?? '').searchParams.get('code') ?? '';
		expect(code).toMatch(/^[A-Za-z0-9_-]{16,}$/);

		// Step 3: Token exchange — verifies PKCE and issues a signed JWT.
		const tokReq = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/token', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				client_id: cid,
				redirect_uri: 'https://claude.ai/cb',
				code_verifier: verifier,
			}).toString(),
		});
		const tokCtx = createExecutionContext();
		const tokRes = await worker.fetch(tokReq, customEnv, tokCtx);
		await waitOnExecutionContext(tokCtx);
		expect(tokRes.status).toBe(200);
		const token = ((await tokRes.json()) as { access_token: string }).access_token;
		expect(token.split('.')).toHaveLength(3);

		// Step 4: call /mcp with the Bearer JWT — proves auth middleware accepts OAuth-issued tokens.
		// MCP spec allows JSON-RPC errors at HTTP 200 with error body, so the assertion is
		// non-401 rather than equal to 200 — the goal is to prove auth passed, not to exercise a tool.
		const mcpReq = new Request<unknown, IncomingRequestCfProperties>('https://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${token}`,
				'User-Agent': 'e2e/1.0',
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
		});
		const mcpCtx = createExecutionContext();
		const mcpRes = await worker.fetch(mcpReq, customEnv, mcpCtx);
		await waitOnExecutionContext(mcpCtx);
		expect(mcpRes.status).not.toBe(401);
	});

	it('catch-all does not eat /oauth routes', async () => {
		// Regression guard: the Hono catch-all 404 handler must not intercept /oauth/*.
		// No env override needed — registration doesn't consult BV_API_KEY or the signing secret.
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: ['https://claude.ai/cb'] }),
		});
		expect(res.status).toBe(201);
	});

	it('unknown route still returns 404', async () => {
		const res = await SELF.fetch('https://example.com/nope');
		expect(res.status).toBe(404);
	});
});
