// Auth-gate tests for /internal/trial-keys/*. Trial keys mint API credentials,
// so the network guard alone is insufficient defense-in-depth: callers must
// also present BV_WEB_INTERNAL_KEY, mirroring /oauth/grants. Success-path
// behavior (key creation, listing, etc.) is covered by lib-level tests in
// test/trial-keys.spec.ts — this file owns the auth contract only.

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src';

const TEST_INTERNAL_KEY = 'trial-test-internal-key';

type TestEnv = typeof env & { BV_WEB_INTERNAL_KEY?: string };

async function send(req: Request, customEnv: TestEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

describe('/internal/trial-keys auth gate', () => {
	it('returns 503 when BV_WEB_INTERNAL_KEY is not configured (POST /trial-keys)', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: undefined } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/trial-keys', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ label: 'test' }),
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(503);
	});

	it('returns 401 when Authorization header is missing (POST /trial-keys)', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/trial-keys', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ label: 'test' }),
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(401);
	});

	it('returns 401 when Authorization bearer is wrong (POST /trial-keys)', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/trial-keys', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: 'Bearer wrong' },
			body: JSON.stringify({ label: 'test' }),
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(401);
	});

	it('returns 401 on GET /trial-keys without bearer', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/trial-keys', {
			method: 'GET',
			headers: {},
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(401);
	});

	it('returns 401 on GET /trial-keys/:hash without bearer', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>(
			`http://example.com/internal/trial-keys/${'a'.repeat(64)}`,
			{ method: 'GET', headers: {} },
		);
		const res = await send(req, customEnv);
		expect(res.status).toBe(401);
	});

	it('returns 401 on DELETE /trial-keys/:hash without bearer', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>(
			`http://example.com/internal/trial-keys/${'a'.repeat(64)}`,
			{ method: 'DELETE', headers: {} },
		);
		const res = await send(req, customEnv);
		expect(res.status).toBe(401);
	});

	it('passes the auth gate when Authorization bearer matches (POST /trial-keys)', async () => {
		// Without a RATE_LIMIT binding the route then returns 500. We only assert that
		// auth did NOT short-circuit — i.e. the response is not 401/503.
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/trial-keys', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TEST_INTERNAL_KEY}` },
			body: JSON.stringify({ label: 'authorized-test' }),
		});
		const res = await send(req, customEnv);
		expect(res.status).not.toBe(401);
		expect(res.status).not.toBe(503);
	});
});
