// H1 regression: /internal/tools/* and /internal/analytics/* relied solely on
// the network guard (cf-connecting-ip absence) for access control. A misconfigured
// upstream that strips or forwards cf-connecting-ip could expose the entire
// internal surface — defense-in-depth eliminates the risk.
//
// Gate behavior is *opt-in*: activates only when REQUIRE_INTERNAL_AUTH === 'true'
// AND BV_WEB_INTERNAL_KEY is set. Default off so existing bv-web → bv-mcp service
// bindings (which today don't send an Authorization header on /tools/call) keep
// working after deploy. Operators flip the flag once bv-web is updated to attach
// the bearer.

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
		it(`${r.name}: gate disabled by default (REQUIRE_INTERNAL_AUTH unset) — passes through`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, REQUIRE_INTERNAL_AUTH: undefined } as TestEnv;
			const headers: Record<string, string> = {};
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, { method: r.method, headers, ...(r.body ? { body: r.body } : {}) });
			const res = await send(req, customEnv);
			expect(res.status).not.toBe(401);
			expect(res.status).not.toBe(503);
		});

		it(`${r.name}: opted-in but missing key → 503 (misconfig fail-closed)`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: undefined, REQUIRE_INTERNAL_AUTH: 'true' } as TestEnv;
			const headers: Record<string, string> = {};
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, { method: r.method, headers, ...(r.body ? { body: r.body } : {}) });
			const res = await send(req, customEnv);
			expect(res.status).toBe(503);
		});

		it(`${r.name}: opted-in, bearer missing → 401`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, REQUIRE_INTERNAL_AUTH: 'true' } as TestEnv;
			const headers: Record<string, string> = {};
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, { method: r.method, headers, ...(r.body ? { body: r.body } : {}) });
			const res = await send(req, customEnv);
			expect(res.status).toBe(401);
		});

		it(`${r.name}: opted-in, bearer wrong → 401`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, REQUIRE_INTERNAL_AUTH: 'true' } as TestEnv;
			const headers: Record<string, string> = { Authorization: 'Bearer wrong' };
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, { method: r.method, headers, ...(r.body ? { body: r.body } : {}) });
			const res = await send(req, customEnv);
			expect(res.status).toBe(401);
		});
	}

	it('opted-in + valid bearer → passes through to handler (POST /internal/tools/call)', async () => {
		const { mockTxtRecords } = await import('./helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, REQUIRE_INTERNAL_AUTH: 'true' } as TestEnv;
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
