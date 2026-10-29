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

const TEST_INTERNAL_KEY = 'tools-analytics-internal-key-32-bytes';
const TEST_OAUTH_MINT_KEY = 'oauth-mint-internal-key-32-bytes-minimum';

type TestEnv = typeof env & { BV_WEB_INTERNAL_KEY?: string; BV_MCP_OAUTH_MINT_KEY?: string; REQUIRE_INTERNAL_AUTH?: string };

async function send(req: Request, customEnv: TestEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

describe('internal tools+analytics auth gate', () => {
	const routes: Array<{ name: string; method: string; url: string; body?: string; ct?: string }> = [
		{
			name: 'POST /internal/tools/call',
			method: 'POST',
			url: 'http://example.com/internal/tools/call',
			body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
			ct: 'application/json',
		},
		{
			name: 'POST /internal/tools/batch',
			method: 'POST',
			url: 'http://example.com/internal/tools/batch',
			body: JSON.stringify({ tool: 'check_spf', domains: ['example.com'] }),
			ct: 'application/json',
		},
		{ name: 'GET /internal/analytics/tier-summary', method: 'GET', url: 'http://example.com/internal/analytics/tier-summary' },
		{ name: 'GET /internal/analytics/key-usage', method: 'GET', url: 'http://example.com/internal/analytics/key-usage' },
		{ name: 'GET /internal/analytics/digest', method: 'GET', url: 'http://example.com/internal/analytics/digest' },
	];

	for (const r of routes) {
		it(`${r.name}: gate active by default (REQUIRE_INTERNAL_AUTH unset), bearer missing → 401`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, REQUIRE_INTERNAL_AUTH: undefined } as TestEnv;
			const headers: Record<string, string> = {};
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, {
				method: r.method,
				headers,
				...(r.body ? { body: r.body } : {}),
			});
			const res = await send(req, customEnv);
			expect(res.status).toBe(401);
		});

		it(`${r.name}: key missing and REQUIRE_INTERNAL_AUTH unset → 503 (misconfig fail-closed)`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: undefined, REQUIRE_INTERNAL_AUTH: undefined } as TestEnv;
			const headers: Record<string, string> = {};
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, {
				method: r.method,
				headers,
				...(r.body ? { body: r.body } : {}),
			});
			const res = await send(req, customEnv);
			expect(res.status).toBe(503);
		});

		it(`${r.name}: bearer missing → 401`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
			const headers: Record<string, string> = {};
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, {
				method: r.method,
				headers,
				...(r.body ? { body: r.body } : {}),
			});
			const res = await send(req, customEnv);
			expect(res.status).toBe(401);
		});

		it(`${r.name}: bearer wrong → 401`, async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY } as TestEnv;
			const headers: Record<string, string> = { Authorization: 'Bearer wrong' };
			if (r.ct) headers['Content-Type'] = r.ct;
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, {
				method: r.method,
				headers,
				...(r.body ? { body: r.body } : {}),
			});
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
			const req = new Request<unknown, IncomingRequestCfProperties>(r.url, {
				method: r.method,
				headers,
				...(r.body ? { body: r.body } : {}),
			});
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
		// /oauth/grants already has its own dedicated OAuth grant-key gate — confirming the new
		// middleware doesn't double-block or change its existing 401/400 contract.
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			BV_MCP_OAUTH_MINT_KEY: TEST_OAUTH_MINT_KEY,
		} as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/grants', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TEST_OAUTH_MINT_KEY}` },
			body: JSON.stringify({}),
		});
		const res = await send(req, customEnv);
		// 400 from invalid_grant_request is fine — confirms auth passed
		expect([400, 200]).toContain(res.status);
	});

	// SQ-471: a defined-but-invalid OPTIONAL capability (TOOL_DELEGATION / WATCH_CLEANUP) must
	// disable only itself. It used to 503 every caller of /internal/tools/*, including the valid
	// BV_WEB_INTERNAL_KEY path. The gate's primary credential keeps its fail-closed 503.
	describe('defined-but-invalid optional capabilities disable only themselves', () => {
		const OPTIONAL_KEYS = ['BV_MCP_TOOL_DELEGATION_KEY', 'BV_MCP_WATCH_CLEANUP_KEY'] as const;
		const toolCall = (token: string, extra: Record<string, string> = {}, path = '/internal/tools/call') =>
			new Request<unknown, IncomingRequestCfProperties>(`http://example.com${path}`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...extra },
				body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
			});

		for (const keyName of OPTIONAL_KEYS) {
			it(`${keyName}='' with a valid web key → web call is 200`, async () => {
				const { mockTxtRecords } = await import('./helpers/dns-mock');
				mockTxtRecords(['v=spf1 -all']);
				const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, [keyName]: '' } as TestEnv;
				const res = await send(toolCall(TEST_INTERNAL_KEY), customEnv);
				expect(res.status).toBe(200);
			});

			it(`${keyName}='' is never accepted as a bearer (empty token → 401)`, async () => {
				const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, [keyName]: '' } as TestEnv;
				expect((await send(toolCall(''), customEnv)).status).toBe(401);
			});

			it(`${keyName} under 32 bytes with a valid web key → web call is 200, the weak key is not accepted`, async () => {
				const { mockTxtRecords } = await import('./helpers/dns-mock');
				mockTxtRecords(['v=spf1 -all']);
				const weak = 'too-short-capability';
				const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, [keyName]: weak } as TestEnv;
				expect((await send(toolCall(TEST_INTERNAL_KEY), customEnv)).status).toBe(200);
				expect((await send(toolCall(weak), customEnv)).status).toBe(401);
			});

			it(`${keyName} aliased to the web key → capability disabled, web key still works`, async () => {
				// The entry point (src/index.ts) 503s a global alias before routing, so exercise the
				// route gate directly: it must hold on its own, not only behind that check.
				const { mockTxtRecords } = await import('./helpers/dns-mock');
				mockTxtRecords(['v=spf1 -all']);
				const { internalRoutes } = await import('../src/internal');
				const customEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY, [keyName]: TEST_INTERNAL_KEY } as TestEnv;
				const ctx = createExecutionContext();
				const ok = await internalRoutes.fetch(toolCall(TEST_INTERNAL_KEY, {}, '/tools/call'), customEnv, ctx);
				await waitOnExecutionContext(ctx);
				expect(ok.status).toBe(200);
				// The aliased value authenticates as the web principal only: tenant context is refused,
				// so it did not inherit the delegation/cleanup principal.
				const ctx2 = createExecutionContext();
				const tenant = await internalRoutes.fetch(
					toolCall(TEST_INTERNAL_KEY, { 'X-Tenant': 'victim_tenant', 'X-Auth-Tier': 'enterprise' }, '/tools/call'),
					customEnv,
					ctx2,
				);
				await waitOnExecutionContext(ctx2);
				expect(tenant.status).toBe(403);
			});
		}

		it('a valid optional capability still authenticates when the other one is invalid', async () => {
			const { mockTxtRecords } = await import('./helpers/dns-mock');
			mockTxtRecords(['v=spf1 -all']);
			const cleanup = 'watch-cleanup-capability-key-32-bytes-minimum';
			const customEnv = {
				...env,
				BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
				BV_MCP_TOOL_DELEGATION_KEY: '',
				BV_MCP_WATCH_CLEANUP_KEY: cleanup,
			} as TestEnv;
			const res = await send(toolCall(cleanup), customEnv);
			// Authenticated as the watch-cleanup principal, whose exact tool allowlist excludes scans.
			expect(res.status).not.toBe(401);
			expect(res.status).not.toBe(503);
		});

		it('the primary credential keeps its fail-closed 503 when no valid key remains', async () => {
			const customEnv = { ...env, BV_WEB_INTERNAL_KEY: undefined, BV_MCP_TOOL_DELEGATION_KEY: '' } as TestEnv;
			expect((await send(toolCall('anything'), customEnv)).status).toBe(503);
		});
	});
});
