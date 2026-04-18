import { SELF, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../../src/index';

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
});
