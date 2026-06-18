import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../../src/index';
import { verifyJwt } from '../../src/oauth/jwt';
import { OAUTH_KV_PREFIX } from '../../src/lib/config';

const TEST_INTERNAL_KEY = 'internal-key';
const TEST_SIGNING_SECRET = 'a'.repeat(32);

type TestEnv = typeof env & {
	BV_WEB_INTERNAL_KEY?: string;
	OAUTH_SIGNING_SECRET?: string;
};

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

async function registerClient(customEnv: TestEnv): Promise<string> {
	const request = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/register', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ redirect_uris: ['https://claude.ai/cb'] }),
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return ((await response.json()) as { client_id: string }).client_id;
}

function makeGrantBody(clientId: string, codeChallenge: string, overrides: Record<string, unknown> = {}) {
	return {
		clientId,
		redirectUri: 'https://claude.ai/cb',
		state: 'stateval',
		codeChallenge,
		codeChallengeMethod: 'S256',
		scope: 'mcp',
		entitlement: {
			subject: 'user_123',
			emailHash: 'a'.repeat(64),
			tier: 'developer',
			stripeCustomerId: 'cus_123',
			stripeSubscriptionId: 'sub_123',
			subscriptionStatus: 'active',
			scopes: ['mcp'],
			entitlementExpiresAt: 1893456000,
		},
		...overrides,
	};
}

async function postGrant(body: unknown, customEnv: TestEnv, headers: HeadersInit = {}): Promise<Response> {
	const request = new Request<unknown, IncomingRequestCfProperties>('https://example.com/internal/oauth/grants', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
			...headers,
		},
		body: JSON.stringify(body),
		redirect: 'manual',
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

beforeEach(async () => {
	await clearPrefix(OAUTH_KV_PREFIX);
});

afterEach(async () => {
	await clearPrefix(OAUTH_KV_PREFIX);
});

describe('POST /internal/oauth/grants', () => {
	it('creates a one-time developer authorization code and redirects through token exchange', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, OAUTH_SIGNING_SECRET: TEST_SIGNING_SECRET } as TestEnv;
		const { verifier, challenge } = await pkcePair();
		const clientId = await registerClient(customEnv);

		const grantResponse = await postGrant(makeGrantBody(clientId, challenge), customEnv);
		expect(grantResponse.status).toBe(200);
		expect(grantResponse.headers.get('cache-control')).toContain('no-store');

		const grant = (await grantResponse.json()) as { redirectTo: string; expiresIn: number };
		expect(grant.expiresIn).toBeGreaterThan(0);
		const redirectTo = new URL(grant.redirectTo);
		expect(redirectTo.origin + redirectTo.pathname).toBe('https://claude.ai/cb');
		expect(redirectTo.searchParams.get('state')).toBe('stateval');
		const code = redirectTo.searchParams.get('code');
		expect(code).toMatch(/^[A-Za-z0-9_-]{16,}$/);

		const tokenCtx = createExecutionContext();
		const tokenResponse = await worker.fetch(
			new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/token', {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					grant_type: 'authorization_code',
					code: code ?? '',
					client_id: clientId,
					redirect_uri: 'https://claude.ai/cb',
					code_verifier: verifier,
				}).toString(),
			}),
			customEnv,
			tokenCtx,
		);
		await waitOnExecutionContext(tokenCtx);
		expect(tokenResponse.status).toBe(200);
		const token = (await tokenResponse.json()) as { access_token: string };
		const claims = await verifyJwt(token.access_token, {
			secret: TEST_SIGNING_SECRET,
			issuer: 'https://example.com',
			audience: 'https://example.com/mcp',
		});
		expect(claims?.sub).toBe('user_123');
		expect(claims?.tier).toBe('developer');
	});

	it('rejects public internet requests before reading the grant body', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const response = await postGrant({}, customEnv, { 'cf-connecting-ip': '198.51.100.10' });
		expect(response.status).toBe(404);
	});

	it('requires the bv-web internal bearer secret', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const { challenge } = await pkcePair();
		const clientId = await registerClient(customEnv);
		const response = await postGrant(makeGrantBody(clientId, challenge), customEnv, { Authorization: 'Bearer wrong' });
		expect(response.status).toBe(401);
	});

	it('rejects redirect URI mismatch without creating a code', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const { challenge } = await pkcePair();
		const clientId = await registerClient(customEnv);
		const response = await postGrant(makeGrantBody(clientId, challenge, { redirectUri: 'https://evil.example/cb' }), customEnv);
		expect(response.status).toBe(400);
		const body = (await response.json()) as { error: string };
		expect(body.error).toBe('redirect_uri_not_registered');
	});

	it('rejects owner-tier entitlement escalation', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const { challenge } = await pkcePair();
		const clientId = await registerClient(customEnv);
		const response = await postGrant(
			makeGrantBody(clientId, challenge, {
				entitlement: {
					subject: 'user_123',
					tier: 'owner',
					stripeCustomerId: 'cus_123',
					stripeSubscriptionId: 'sub_123',
					subscriptionStatus: 'active',
					scopes: ['mcp'],
				},
			}),
			customEnv,
		);
		expect(response.status).toBe(400);
	});

	it('mints a code from an entitlement with no Stripe IDs (comp)', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, OAUTH_SIGNING_SECRET: TEST_SIGNING_SECRET } as TestEnv;
		const { challenge } = await pkcePair();
		const clientId = await registerClient(customEnv);

		const body = {
			clientId,
			redirectUri: 'https://claude.ai/cb',
			state: 'xyz',
			codeChallenge: challenge,
			codeChallengeMethod: 'S256',
			entitlement: {
				subject: 'tenant_abc',
				tier: 'developer',
				subscriptionStatus: 'active',
				scopes: ['mcp'],
			},
		};
		const res = await postGrant(body, customEnv);
		expect(res.status).toBe(200);
		const json = (await res.json()) as { redirectTo: string };
		expect(json.redirectTo).toContain('code=');
	});
});
