// H1 regression (FIND-12): /internal/tools/* and /internal/analytics/* relied solely on
// the network guard (cf-connecting-ip absence) for access control. A misconfigured
// upstream that strips or forwards cf-connecting-ip could expose the entire
// internal surface — defense-in-depth eliminates the risk.
//
// Gate behavior is *secure-by-default* (FIND-12): bearer is required UNLESS
// REQUIRE_INTERNAL_AUTH=false is set as an explicit opt-out. Callers must present
// Authorization: Bearer ${BV_WEB_INTERNAL_KEY} on all /internal/tools/* and
// /internal/analytics/* routes.

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import worker from '../src';

const TEST_INTERNAL_KEY = 'tools-analytics-internal-key';

type TestEnv = typeof env & { BV_WEB_INTERNAL_KEY?: string; REQUIRE_INTERNAL_AUTH?: string };

async function send(req: Request, customEnv: TestEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

describe('internal tools+analytics auth gate', () => {
	const routes: Array<{ name: string; method: string; url: string; body?: string; ct?: string }> = [
		{ name: 'POST /internal/tools/call', method: 'POST', url: 'http://example.com/internal/tools/call', body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }), ct: 'application/json' },
		{ name: 'POST /internal/tools/batch', method: 'POST', url: 'http://example.com/internal/tools/batch', body: JSON.stringify({ tool: 'check_spf', domains: ['example.com'] }), ct: 'application/json' },
		{ name: 'GET /internal/analytics/tier-summary', method: 'GET', url: 'http://example.com/internal/analytics/tier-summary' },
		{ name: 'GET /internal/analytics/key-usage', method: 'GET', url: 'http://example.com/internal/analytics/key-usage' },
		{ name: 'GET /internal/analytics/digest', method: 'GET', url: 'http://example.com/internal/analytics/digest' },
	];

	for (const r of routes) {
		it(`${r.name}: gate active by default (REQUIRE_INTERNAL_AUTH unset), bearer missing → 401`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, REQUIRE_INTERNAL_AUTH: undefined } as TestEnv;
			const headers: Record<string, string> = {};
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, { method: r.method, headers, ...(r.body ? { body: r.body } : {}) });
			const res = await send(req, customEnv);
			expect(res.status).toBe(401);
		});

		it(`${r.name}: key missing and REQUIRE_INTERNAL_AUTH unset → 503 (misconfig fail-closed)`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: undefined, REQUIRE_INTERNAL_AUTH: undefined } as TestEnv;
			const headers: Record<string, string> = {};
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, { method: r.method, headers, ...(r.body ? { body: r.body } : {}) });
			const res = await send(req, customEnv);
			expect(res.status).toBe(503);
		});

		it(`${r.name}: bearer missing → 401`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
			const headers: Record<string, string> = {};
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, { method: r.method, headers, ...(r.body ? { body: r.body } : {}) });
			const res = await send(req, customEnv);
			expect(res.status).toBe(401);
		});

		it(`${r.name}: bearer wrong → 401`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
			const headers: Record<string, string> = { Authorization: 'Bearer wrong' };
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, { method: r.method, headers, ...(r.body ? { body: r.body } : {}) });
			const res = await send(req, customEnv);
			expect(res.status).toBe(401);
		});

		it(`${r.name}: opt-out (REQUIRE_INTERNAL_AUTH=false) without bearer → passes through`, async () => {
			// When the operator explicitly opts out, bearer should not be required.
			// This covers the controlled migration window where bv-web isn't yet
			// sending an Authorization header.
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, REQUIRE_INTERNAL_AUTH: 'false' } as TestEnv;
			const headers: Record<string, string> = {};
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, { method: r.method, headers, ...(r.body ? { body: r.body } : {}) });
			const res = await send(req, customEnv);
			expect(res.status).not.toBe(401);
			expect(res.status).not.toBe(503);
		});
	}

	it('valid bearer → passes through to handler (POST /internal/tools/call)', async () => {
		const { mockTxtRecords } = await import('./helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TEST_INTERNAL_KEY}` },
			body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
		});
		const res = await send(req, customEnv);
		expect(res.status).not.toBe(401);
		expect(res.status).not.toBe(503);
	});

	it('does NOT gate /internal/oauth/grants behind the new gate (existing route preserves its own check)', async () => {
		// /oauth/grants already has its own BV_WEB_INTERNAL_KEY gate — confirming the new
		// middleware doesn't double-block or change its existing 401/400 contract.
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/grants', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TEST_INTERNAL_KEY}` },
			body: JSON.stringify({}),
		});
		const res = await send(req, customEnv);
		// 400 from invalid_grant_request is fine — confirms auth passed
		expect([400, 200]).toContain(res.status);
	});
});
