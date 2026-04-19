import { SELF, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../../src/index';

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

async function postToken(body: URLSearchParams, customEnv: TestEnv = authEnv): Promise<Response> {
	const req = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/token', {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
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

	it('returns 500 server_error when OAUTH_SIGNING_SECRET is missing', async () => {
		const { verifier, challenge } = await pkcePair();
		const cid = await registerClient();
		// Use authEnv (with secret) to mint the code, then call /oauth/token without the secret.
		const code = await getAuthCode(cid, challenge);
		const noSecretEnv = { ...env, BV_API_KEY: TEST_API_KEY } as TestEnv;
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			code_verifier: verifier,
		});
		const res = await postToken(body, noSecretEnv);
		expect(res.status).toBe(500);
		expect(((await res.json()) as Record<string, unknown>).error).toBe('server_error');
	});

	it('returns 500 server_error when OAUTH_SIGNING_SECRET is shorter than 32 bytes', async () => {
		// HS256 requires ≥32 bytes for 256-bit security margin (RFC 7518 §3.2). A too-short
		// secret must be rejected identically to a missing one — same error_description, no
		// leak of the distinction between "missing" and "too short".
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
		expect(res.status).toBe(500);
		const payload = (await res.json()) as Record<string, unknown>;
		expect(payload.error).toBe('server_error');
		expect(payload.error_description).toBe('OAUTH_SIGNING_SECRET not configured');
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
});
