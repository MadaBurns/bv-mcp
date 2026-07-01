import { SELF, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../../src/index';
import { putCode } from '../../src/oauth/storage';
import { OAUTH_JWT_TTL_SECONDS } from '../../src/lib/config';

const TEST_API_KEY = 'testkey';
const TEST_SIGNING_SECRET = 'a'.repeat(32);

type TestEnv = typeof env & { BV_API_KEY?: string; OAUTH_SIGNING_SECRET?: string };
const authEnv = { ...env, BV_API_KEY: TEST_API_KEY, OAUTH_SIGNING_SECRET: TEST_SIGNING_SECRET } as TestEnv;

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

async function registerClient(): Promise<string> {
	// Register doesn't touch BV_API_KEY/OAUTH_SIGNING_SECRET — SELF.fetch is fine.
	const r = await SELF.fetch('https://example.com/oauth/register', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ redirect_uris: ['https://claude.ai/cb'] }),
	});
	return ((await r.json()) as { client_id: string }).client_id;
}

async function getAuthCode(cid: string, challenge: string, customEnv: TestEnv = authEnv): Promise<string> {
	const q = new URLSearchParams({
		client_id: cid,
		redirect_uri: 'https://claude.ai/cb',
		response_type: 'code',
		state: 's',
		code_challenge: challenge,
		code_challenge_method: 'S256',
	}).toString();
	const body = new URLSearchParams({ api_key: TEST_API_KEY, _q: q });
	const req = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/authorize', {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: body.toString(),
		redirect: 'manual',
	});
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return new URL(res.headers.get('location') ?? '').searchParams.get('code') ?? '';
}

async function postToken(body: URLSearchParams, customEnv: TestEnv = authEnv, headers: Record<string, string> = {}): Promise<Response> {
	const req = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/token', {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
		body: body.toString(),
	});
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

beforeEach(async () => {
	await clearPrefix('oauth:');
});
afterEach(async () => {
	await clearPrefix('oauth:');
});

describe('POST /oauth/token', () => {
	it('issues a JWT for a valid code + verifier', async () => {
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		const code = await getAuthCode(cid, challenge);
		expect(code).not.toBe('');
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			code_verifier: verifier,
		});
		const res = await postToken(body);
		expect(res.status).toBe(200);
		expect(res.headers.get('cache-control')).toContain('no-store');
		const tok = (await res.json()) as Record<string, unknown>;
		expect(tok.token_type).toBe('Bearer');
		expect(typeof tok.access_token).toBe('string');
		expect((tok.access_token as string).split('.')).toHaveLength(3);
		expect(tok.expires_in).toBeGreaterThan(0);
	});

	it('issues a developer-tier JWT when the authorization code carries Stripe entitlement metadata', async () => {
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		const code = 'paid-code-dev';
		await putCode(env.SESSION_STORE, code, {
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			code_challenge: challenge,
			issued_at: Math.floor(Date.now() / 1000),
			scope: 'mcp',
			subject: 'user_123',
			tier: 'developer',
			stripeCustomerId: 'cus_123',
			stripeSubscriptionId: 'sub_123',
			subscriptionStatus: 'active',
			entitlementExpiresAt: 1893456000,
		});
		const res = await postToken(
			new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				client_id: cid,
				redirect_uri: 'https://claude.ai/cb',
				code_verifier: verifier,
			}),
		);
		expect(res.status).toBe(200);
		const tok = (await res.json()) as { access_token: string };
		const [, payload] = tok.access_token.split('.');
		const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>;
		expect(claims.sub).toBe('user_123');
		expect(claims.tier).toBe('developer');
		expect(claims.client_id).toBe(cid);
		expect(claims.stripeCustomerId).toBeUndefined();
		expect(claims.stripeSubscriptionId).toBeUndefined();
	});

	it('clamps the JWT TTL to entitlementExpiresAt when it is sooner than the 90-day default', async () => {
		// FIND (A01 token-persistence): a paid entitlement that expires in ~1 hour must mint a
		// JWT whose lifetime is clamped to that window, not the flat 90-day default — otherwise a
		// lapsed subscription keeps resolving to the paid tier for up to 90 days.
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		const code = 'paid-code-soon-expiry';
		const now = Math.floor(Date.now() / 1000);
		const oneHour = 3600;
		await putCode(env.SESSION_STORE, code, {
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			code_challenge: challenge,
			issued_at: now,
			scope: 'mcp',
			subject: 'user_soon',
			tier: 'developer',
			stripeCustomerId: 'cus_soon',
			stripeSubscriptionId: 'sub_soon',
			subscriptionStatus: 'active',
			entitlementExpiresAt: now + oneHour,
		});
		const res = await postToken(
			new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				client_id: cid,
				redirect_uri: 'https://claude.ai/cb',
				code_verifier: verifier,
			}),
		);
		expect(res.status).toBe(200);
		const tok = (await res.json()) as { access_token: string; expires_in: number };
		const [, payload] = tok.access_token.split('.');
		const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as { iat: number; exp: number };
		// Lifetime asserted relative to the token's own iat — no wall-clock dependency.
		const lifetime = claims.exp - claims.iat;
		expect(lifetime).toBeLessThanOrEqual(oneHour);
		expect(lifetime).toBeGreaterThan(oneHour - 60); // ~1h, not 90 days
		expect(lifetime).toBeLessThan(OAUTH_JWT_TTL_SECONDS);
		expect(tok.expires_in).toBe(lifetime);
	});

	it('preserves the 90-day TTL when entitlementExpiresAt is far in the future', async () => {
		// A long-lived entitlement must still cap at the 90-day default (Math.min picks 90 days).
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		const code = 'paid-code-far-expiry';
		const now = Math.floor(Date.now() / 1000);
		await putCode(env.SESSION_STORE, code, {
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			code_challenge: challenge,
			issued_at: now,
			scope: 'mcp',
			subject: 'user_far',
			tier: 'developer',
			stripeCustomerId: 'cus_far',
			stripeSubscriptionId: 'sub_far',
			subscriptionStatus: 'active',
			entitlementExpiresAt: now + OAUTH_JWT_TTL_SECONDS * 10,
		});
		const res = await postToken(
			new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				client_id: cid,
				redirect_uri: 'https://claude.ai/cb',
				code_verifier: verifier,
			}),
		);
		expect(res.status).toBe(200);
		const tok = (await res.json()) as { access_token: string; expires_in: number };
		const [, payload] = tok.access_token.split('.');
		const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as { iat: number; exp: number };
		expect(claims.exp - claims.iat).toBe(OAUTH_JWT_TTL_SECONDS);
		expect(tok.expires_in).toBe(OAUTH_JWT_TTL_SECONDS);
	});

	it('preserves the 90-day TTL when entitlementExpiresAt is absent', async () => {
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		const code = await getAuthCode(cid, challenge);
		expect(code).not.toBe('');
		const res = await postToken(
			new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				client_id: cid,
				redirect_uri: 'https://claude.ai/cb',
				code_verifier: verifier,
			}),
		);
		expect(res.status).toBe(200);
		const tok = (await res.json()) as { access_token: string; expires_in: number };
		const [, payload] = tok.access_token.split('.');
		const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as { iat: number; exp: number };
		expect(claims.exp - claims.iat).toBe(OAUTH_JWT_TTL_SECONDS);
		expect(tok.expires_in).toBe(OAUTH_JWT_TTL_SECONDS);
	});

	it('rejects with invalid_grant when entitlementExpiresAt is already in the past', async () => {
		// A lapsed entitlement must never mint an (already-expired) token — reject the exchange.
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		const code = 'paid-code-lapsed';
		const now = Math.floor(Date.now() / 1000);
		await putCode(env.SESSION_STORE, code, {
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			code_challenge: challenge,
			issued_at: now,
			scope: 'mcp',
			subject: 'user_lapsed',
			tier: 'developer',
			stripeCustomerId: 'cus_lapsed',
			stripeSubscriptionId: 'sub_lapsed',
			subscriptionStatus: 'active',
			entitlementExpiresAt: now - 3600,
		});
		const res = await postToken(
			new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				client_id: cid,
				redirect_uri: 'https://claude.ai/cb',
				code_verifier: verifier,
			}),
		);
		expect(res.status).toBe(400);
		expect(((await res.json()) as Record<string, unknown>).error).toBe('invalid_grant');
	});

	it('rejects replay of the same code', async () => {
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		const code = await getAuthCode(cid, challenge);
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			code_verifier: verifier,
		});
		const first = await postToken(body);
		expect(first.status).toBe(200);
		const second = await postToken(body);
		expect(second.status).toBe(400);
		expect(((await second.json()) as Record<string, unknown>).error).toBe('invalid_grant');
	});

	it('rejects mismatched code_verifier', async () => {
		const { challenge } = await pkcePair();
		const cid = await registerClient();
		const code = await getAuthCode(cid, challenge);
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			code_verifier: 'v'.repeat(43),
		});
		const res = await postToken(body);
		expect(res.status).toBe(400);
		expect(((await res.json()) as Record<string, unknown>).error).toBe('invalid_grant');
	});

	it('rejects unsupported grant_type', async () => {
		const body = new URLSearchParams({
			grant_type: 'password',
			code: 'x',
			client_id: 'x',
			redirect_uri: 'https://claude.ai/cb',
			code_verifier: 'y'.repeat(43),
		});
		const res = await postToken(body);
		expect(res.status).toBe(400);
		expect(((await res.json()) as Record<string, unknown>).error).toBe('unsupported_grant_type');
	});

	it('returns 503 service_unavailable when OAUTH_SIGNING_SECRET is missing (v2.10.9 route-layer gate)', async () => {
		// Pre-v2.10.9 this was a 500 from the inner handler (`src/oauth/token.ts:154`).
		// v2.10.9 added a route-layer `oauthAvailability` gate that intercepts FIRST,
		// so the user-visible failure now surfaces as 503 service_unavailable. The
		// inner 500 path remains as defense in depth — exercised by direct handler
		// unit tests, not via worker.fetch.
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		const code = await getAuthCode(cid, challenge);
		const noSecretEnv = { ...env, BV_API_KEY: TEST_API_KEY, OAUTH_SIGNING_SECRET: undefined } as TestEnv;
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			code_verifier: verifier,
		});
		const res = await postToken(body, noSecretEnv);
		expect(res.status).toBe(503);
		expect(((await res.json()) as Record<string, unknown>).error).toBe('service_unavailable');
	});

	it('returns 503 service_unavailable when OAUTH_SIGNING_SECRET is shorter than 32 bytes', async () => {
		// HS256 requires ≥32 bytes for 256-bit security margin (RFC 7518 §3.2). A too-short
		// secret must be rejected identically to a missing one. Both states are 'misconfigured'
		// per `oauthAvailability` and surface the same wire shape.
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		const code = await getAuthCode(cid, challenge);
		const shortSecretEnv = { ...env, BV_API_KEY: TEST_API_KEY, OAUTH_SIGNING_SECRET: 'short' } as TestEnv;
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			code_verifier: verifier,
		});
		const res = await postToken(body, shortSecretEnv);
		expect(res.status).toBe(503);
		const payload = (await res.json()) as Record<string, unknown>;
		expect(payload.error).toBe('service_unavailable');
	});

	it('rejects with invalid_request when the request Host does not match the pinned OAUTH_ISSUER (fail closed)', async () => {
		// Hardening (security-audit item 9): when OAUTH_ISSUER is pinned, a token request arriving
		// on a different Host must NOT mint a JWT. resolveIssuerStrict rejects the Host mismatch
		// instead of silently normalizing to the pinned issuer, so a spoofed Host can never bake an
		// anomalous origin into a minted credential. Cloudflare's route binding already constrains
		// Host in prod — this is the fail-closed defense-in-depth layer behind it.
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		const code = await getAuthCode(cid, challenge);
		expect(code).not.toBe('');
		// postToken issues to https://example.com/oauth/token → Host ('example.com') ≠ pinned host.
		const pinnedEnv = { ...authEnv, OAUTH_ISSUER: 'https://dns-mcp.blackveilsecurity.com' } as TestEnv;
		const res = await postToken(
			new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				client_id: cid,
				redirect_uri: 'https://claude.ai/cb',
				code_verifier: verifier,
			}),
			pinnedEnv,
		);
		expect(res.status).toBe(400);
		expect(((await res.json()) as Record<string, unknown>).error).toBe('invalid_request');
	});

	it('mints normally when the request Host matches the pinned OAUTH_ISSUER (happy-path regression guard)', async () => {
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		const code = await getAuthCode(cid, challenge);
		expect(code).not.toBe('');
		// Pinned issuer host == request Host (example.com) → strict resolution succeeds, token mints.
		const pinnedEnv = { ...authEnv, OAUTH_ISSUER: 'https://example.com' } as TestEnv;
		const res = await postToken(
			new URLSearchParams({
				grant_type: 'authorization_code',
				code,
				client_id: cid,
				redirect_uri: 'https://claude.ai/cb',
				code_verifier: verifier,
			}),
			pinnedEnv,
		);
		expect(res.status).toBe(200);
		const tok = (await res.json()) as { access_token: string };
		const [, payload] = tok.access_token.split('.');
		const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>;
		expect(claims.iss).toBe('https://example.com');
		expect(claims.aud).toBe('https://example.com/mcp');
	});

	it('rate-limits token requests at 30/min per IP', async () => {
		// Mirrors the fixed-window limiter pattern in authorize.ts: 30 requests per IP per 60s.
		// The 31st call from the same IP must return 429 with invalid_request. We fire requests
		// with a bogus code so each one short-circuits at invalid_grant (cheap path) — the rate
		// limiter check runs BEFORE content-type / grant-type / Zod parsing, so the status
		// progression is deterministic regardless of downstream validation.
		const ip = '203.0.113.42';
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code: 'never-issued',
			client_id: 'no-such-client',
			redirect_uri: 'https://claude.ai/cb',
			code_verifier: 'v'.repeat(43),
		});

		async function postWithIp(): Promise<Response> {
			const req = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/token', {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': ip },
				body: body.toString(),
			});
			const ctx = createExecutionContext();
			const res = await worker.fetch(req, authEnv, ctx);
			await waitOnExecutionContext(ctx);
			return res;
		}

		for (let i = 0; i < 30; i++) {
			const res = await postWithIp();
			expect(res.status).not.toBe(429);
		}
		const limited = await postWithIp();
		expect(limited.status).toBe(429);
		const payload = (await limited.json()) as Record<string, unknown>;
		expect(payload.error).toBe('invalid_request');
		expect(payload.error_description).toBe('Too many token requests');
	});

	it('ignores x-forwarded-for and rate-limits the shared "unknown" bucket when cf-connecting-ip is absent', async () => {
		// Security: x-forwarded-for is attacker-controlled. Rotating it must NOT
		// reset the per-IP rate limit. Without cf-connecting-ip, all requests
		// share the 'unknown' bucket — so 30 hits from any spoofed XFF + a 31st
		// from a different spoofed XFF should still 429 (same bucket).
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code: 'never-issued',
			client_id: 'no-such-client',
			redirect_uri: 'https://claude.ai/cb',
			code_verifier: 'v'.repeat(43),
		});

		for (let i = 0; i < 30; i++) {
			const res = await postToken(body, authEnv, { 'x-forwarded-for': '198.51.100.20' });
			expect(res.status).not.toBe(429);
		}

		// Rotating XFF must NOT mint a fresh bucket — all 'unknown' IPs share one.
		const differentIp = await postToken(body, authEnv, { 'x-forwarded-for': '203.0.113.30' });
		expect(differentIp.status).toBe(429);
	});
});
