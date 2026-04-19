import { SELF, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../../src/index';
import { OAUTH_KV_PREFIX } from '../../src/lib/config';

const TEST_API_KEY = 'testkey';

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

function buildForm(api_key: string, cid: string): URLSearchParams {
	const q = new URLSearchParams({
		client_id: cid,
		redirect_uri: 'https://claude.ai/cb',
		response_type: 'code',
		state: 'stateval',
		code_challenge: 'x'.repeat(43),
		code_challenge_method: 'S256',
	}).toString();
	return new URLSearchParams({ api_key, _q: q });
}

beforeEach(async () => {
	await clearPrefix('oauth:');
});
afterEach(async () => {
	await clearPrefix('oauth:');
});

describe('POST /oauth/authorize', () => {
	it('valid key → 302 redirect with code + state', async () => {
		const cid = await registerClient();
		const form = buildForm(TEST_API_KEY, cid);
		const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
		const request = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: form.toString(),
			redirect: 'manual',
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(request, authEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(302);
		const loc = new URL(res.headers.get('location') ?? '');
		expect(loc.origin + loc.pathname).toBe('https://claude.ai/cb');
		expect(loc.searchParams.get('code')).toMatch(/^[A-Za-z0-9_-]{16,}$/);
		expect(loc.searchParams.get('state')).toBe('stateval');
	});

	it('wrong key → 302 redirect with error=access_denied + state', async () => {
		const cid = await registerClient();
		const form = buildForm('wrongkey', cid);
		const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
		const request = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: form.toString(),
			redirect: 'manual',
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(request, authEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(302);
		const loc = new URL(res.headers.get('location') ?? '');
		expect(loc.origin + loc.pathname).toBe('https://claude.ai/cb');
		expect(loc.searchParams.get('error')).toBe('access_denied');
		expect(loc.searchParams.get('state')).toBe('stateval');
	});

	it('rate-limits consent POST after 5 wrong attempts', async () => {
		const cid = await registerClient();
		const form = buildForm('wrongkey', cid);
		for (let i = 0; i < 5; i++) {
			await SELF.fetch('https://example.com/oauth/authorize', {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '198.51.100.5' },
				body: form.toString(),
				redirect: 'manual',
			});
		}
		const res = await SELF.fetch('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '198.51.100.5' },
			body: form.toString(),
			redirect: 'manual',
		});
		expect(res.status).toBe(429);
	});

	it('rejects non-form content-type with 415', async () => {
		const cid = await registerClient();
		const form = buildForm('wrongkey', cid);
		const res = await SELF.fetch('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: form.toString(),
			redirect: 'manual',
		});
		expect(res.status).toBe(415);
	});

	it('rejects invalid _q query with 400', async () => {
		const form = new URLSearchParams({ api_key: 'x', _q: 'client_id=&redirect_uri=&response_type=code' });
		const res = await SELF.fetch('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: form.toString(),
			redirect: 'manual',
		});
		expect(res.status).toBe(400);
	});

	it('rejects unknown client_id in _q with 400', async () => {
		const q = new URLSearchParams({
			client_id: 'missing-client',
			redirect_uri: 'https://claude.ai/cb',
			response_type: 'code',
			state: 'stateval',
			code_challenge: 'x'.repeat(43),
			code_challenge_method: 'S256',
		}).toString();
		const form = new URLSearchParams({ api_key: 'x', _q: q });
		const res = await SELF.fetch('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: form.toString(),
			redirect: 'manual',
		});
		expect(res.status).toBe(400);
	});

	it('rate-limit window is fixed: expiresAt is stable across increments (not reset per write)', async () => {
		const cid = await registerClient();
		const form = buildForm('wrongkey', cid);
		const ip = '198.51.100.77';
		const rlKey = `${OAUTH_KV_PREFIX}consent-rl:${ip}`;

		// First failed attempt — establishes the window
		await SELF.fetch('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': ip },
			body: form.toString(),
			redirect: 'manual',
		});
		const firstRaw = await env.SESSION_STORE.get(rlKey);
		expect(firstRaw).not.toBeNull();
		const first = JSON.parse(firstRaw as string) as { count: number; expiresAt: number };
		expect(first.count).toBe(1);
		expect(typeof first.expiresAt).toBe('number');

		// Second failed attempt — must preserve the ORIGINAL expiresAt (fixed window).
		// Current buggy impl resets TTL on every put → expiresAt drifts forward.
		await SELF.fetch('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': ip },
			body: form.toString(),
			redirect: 'manual',
		});
		const secondRaw = await env.SESSION_STORE.get(rlKey);
		expect(secondRaw).not.toBeNull();
		const second = JSON.parse(secondRaw as string) as { count: number; expiresAt: number };
		expect(second.count).toBe(2);
		expect(second.expiresAt).toBe(first.expiresAt);
	});

	it('OWNER_ALLOW_IPS set + client IP in allowlist → 302 success with code', async () => {
		// Phase 6 amendment: the IP allowlist gate must run at the CONSENT step (before
		// BV_API_KEY is checked), not only at the Bearer-path tier resolver, because Phase 8
		// trusts the OAuth JWT as owner tier unconditionally. A client IP inside the allowlist
		// must still flow through and land on the success redirect.
		const cid = await registerClient();
		const form = buildForm(TEST_API_KEY, cid);
		const authEnv = { ...env, BV_API_KEY: TEST_API_KEY, OWNER_ALLOW_IPS: '10.0.0.1,10.0.0.2' } as Env;
		const request = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': '10.0.0.1' },
			body: form.toString(),
			redirect: 'manual',
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(request, authEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(302);
		const loc = new URL(res.headers.get('location') ?? '');
		expect(loc.searchParams.get('code')).toMatch(/^[A-Za-z0-9_-]{16,}$/);
		expect(loc.searchParams.get('error')).toBeNull();
	});

	it('OWNER_ALLOW_IPS set + client IP NOT in allowlist → access_denied, no code persisted', async () => {
		// Hard security test: correct BV_API_KEY from a disallowed IP must NOT mint a code.
		// The deny path must go through redirectWithError (so the client surfaces the standard
		// OAuth error), and no `oauth:code:*` entry may exist in KV afterwards.
		const cid = await registerClient();
		const form = buildForm(TEST_API_KEY, cid);
		const authEnv = { ...env, BV_API_KEY: TEST_API_KEY, OWNER_ALLOW_IPS: '10.0.0.1' } as Env;
		const request = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': '203.0.113.1' },
			body: form.toString(),
			redirect: 'manual',
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(request, authEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(302);
		const loc = new URL(res.headers.get('location') ?? '');
		expect(loc.origin + loc.pathname).toBe('https://claude.ai/cb');
		expect(loc.searchParams.get('error')).toBe('access_denied');
		expect(loc.searchParams.get('state')).toBe('stateval');
		expect(loc.searchParams.get('code')).toBeNull();

		// Verify no code record was persisted to KV — response-level check alone is not enough.
		const codeList = await env.SESSION_STORE.list({ prefix: `${OAUTH_KV_PREFIX}code:` });
		expect(codeList.keys.length).toBe(0);
	});

	it('OWNER_ALLOW_IPS unset → backward-compatible (no IP gating at consent)', async () => {
		// Self-hosted / dev default: no OWNER_ALLOW_IPS → any IP with the correct key passes.
		// Explicitly asserts we did not regress the existing success path when the env var is
		// absent. Uses a non-routable IP distinct from the other tests to avoid rate-limit
		// contamination across tests sharing the default cf-connecting-ip fallback.
		const cid = await registerClient();
		const form = buildForm(TEST_API_KEY, cid);
		const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
		const request = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'cf-connecting-ip': '192.0.2.55' },
			body: form.toString(),
			redirect: 'manual',
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(request, authEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(302);
		const loc = new URL(res.headers.get('location') ?? '');
		expect(loc.searchParams.get('code')).toMatch(/^[A-Za-z0-9_-]{16,}$/);
		expect(loc.searchParams.get('error')).toBeNull();
	});

	it('persists code record with submitted code_challenge at the KV layer', async () => {
		const cid = await registerClient();
		const challenge = 'a'.repeat(64);
		const q = new URLSearchParams({
			client_id: cid,
			redirect_uri: 'https://claude.ai/cb',
			response_type: 'code',
			state: 'stateval',
			code_challenge: challenge,
			code_challenge_method: 'S256',
		}).toString();
		const form = new URLSearchParams({ api_key: TEST_API_KEY, _q: q });
		const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
		const request = new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: form.toString(),
			redirect: 'manual',
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(request, authEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(302);
		const loc = new URL(res.headers.get('location') ?? '');
		const code = loc.searchParams.get('code');
		expect(code).toBeTruthy();

		const raw = await env.SESSION_STORE.get(`${OAUTH_KV_PREFIX}code:${code}`);
		expect(raw).not.toBeNull();
		const rec = JSON.parse(raw as string) as { code_challenge: string; client_id: string; redirect_uri: string };
		expect(rec.code_challenge).toBe(challenge);
		expect(rec.client_id).toBe(cid);
		expect(rec.redirect_uri).toBe('https://claude.ai/cb');
	});
});
