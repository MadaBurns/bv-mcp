// SPDX-License-Identifier: BUSL-1.1
//
// Decision table for GET /internal/analytics/tier-summary and /internal/analytics/key-usage.
// Both sit behind webOnlyGate (BV_WEB_INTERNAL_KEY bearer) and call the Analytics Engine SQL API
// through global fetch, which is the only boundary mocked here.
//
//   input                                  -> status  body
//   no bearer                              -> 401     (never reaches Analytics Engine)
//   bearer, CF_ACCOUNT_ID/TOKEN missing     -> 500     { error: 'Analytics not configured (...)' }
//   bearer, configured, AE ok               -> 200     rows keyed per route
//   bearer, configured, AE rejects (Error)  -> 502     { error: 'Analytics query failed', detail: <=100 chars }
//   bearer, configured, AE throws non-Error -> 502     { error: 'Analytics query failed', detail: 'unknown' }

import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => vi.restoreAllMocks());

const WEB_KEY = 'web-internal-capability-test-key-32-bytes';
const AUTH = { authorization: `Bearer ${WEB_KEY}` };
const CONFIGURED = { BV_WEB_INTERNAL_KEY: WEB_KEY, CF_ACCOUNT_ID: 'acct-1', CF_ANALYTICS_TOKEN: 'ae-token' };
const NOT_CONFIGURED_ERROR = 'Analytics not configured (CF_ACCOUNT_ID + CF_ANALYTICS_TOKEN required)';

function aeResponse(data: unknown[]): Response {
	return new Response(JSON.stringify({ data }), { status: 200, headers: { 'content-type': 'application/json' } });
}

function stubAe(respond: () => Promise<Response>) {
	return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => respond());
}

describe.each([{ route: '/analytics/tier-summary' }, { route: '/analytics/key-usage' }])('GET /internal$route handler', ({ route }) => {
	it('401s without the web bearer and never reaches Analytics Engine', async () => {
		const { internalRoutes } = await import('../src/internal');
		const fetchSpy = stubAe(async () => aeResponse([]));
		const res = await internalRoutes.request(route, {}, CONFIGURED);
		expect(res.status).toBe(401);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('500s when CF_ACCOUNT_ID / CF_ANALYTICS_TOKEN are not configured', async () => {
		const { internalRoutes } = await import('../src/internal');
		const fetchSpy = stubAe(async () => aeResponse([]));
		const res = await internalRoutes.request(route, { headers: AUTH }, { BV_WEB_INTERNAL_KEY: WEB_KEY });
		expect(res.status).toBe(500);
		expect(await res.json()).toEqual({ error: NOT_CONFIGURED_ERROR });
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('502s with a truncated Error message when Analytics Engine rejects the query', async () => {
		const { internalRoutes } = await import('../src/internal');
		stubAe(async () => new Response('x'.repeat(500), { status: 422 }));
		const res = await internalRoutes.request(route, { headers: AUTH }, CONFIGURED);
		expect(res.status).toBe(502);
		const body = (await res.json()) as { error: string; detail: string };
		expect(body.error).toBe('Analytics query failed');
		expect(body.detail.startsWith('Analytics Engine query failed: 422')).toBe(true);
		expect(body.detail.length).toBeLessThanOrEqual(100);
	});

	it('502s with detail "unknown" when the failure is not an Error instance', async () => {
		const { internalRoutes } = await import('../src/internal');
		stubAe(async () => {
			throw 'boom';
		});
		const res = await internalRoutes.request(route, { headers: AUTH }, CONFIGURED);
		expect(res.status).toBe(502);
		expect(await res.json()).toEqual({ error: 'Analytics query failed', detail: 'unknown' });
	});
});

describe('GET /internal/analytics/tier-summary', () => {
	it('answers all eight panels with the default 7-day window and tier "all"', async () => {
		const { internalRoutes } = await import('../src/internal');
		const rows = [{ k: 'a', n: 3 }];
		const fetchSpy = stubAe(async () => aeResponse(rows));
		const res = await internalRoutes.request('/analytics/tier-summary', { headers: AUTH }, CONFIGURED);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({
			days: '7',
			tier: 'all',
			usage: rows,
			latency: rows,
			errors: rows,
			cache: rows,
			rateLimits: rows,
			sessions: rows,
			trend: rows,
			topTools: rows,
		});
		expect(fetchSpy).toHaveBeenCalledTimes(8);
	});

	it('echoes the tier filter, clamps ?days, and derives the top-tools hours window as days * 24', async () => {
		const { internalRoutes } = await import('../src/internal');
		const { queryTierTopTools, queryTierToolUsage } = await import('../src/lib/analytics-queries');
		const fetchSpy = stubAe(async () => aeResponse([]));
		const res = await internalRoutes.request('/analytics/tier-summary?days=500&tier=developer', { headers: AUTH }, CONFIGURED);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { days: string; tier: string };
		expect(body.days).toBe('90');
		expect(body.tier).toBe('developer');
		const sqls = fetchSpy.mock.calls.map(([, init]) => (init as RequestInit).body);
		expect(sqls).toContain(queryTierToolUsage('90', 'developer', 'bv_dns_security_mcp'));
		expect(sqls).toContain(queryTierTopTools('2160', 'bv_dns_security_mcp'));
	});
});

describe('GET /internal/analytics/key-usage', () => {
	it('returns the usage rows with the default 7-day window and key "all"', async () => {
		const { internalRoutes } = await import('../src/internal');
		const rows = [{ k: 'a', n: 3 }];
		const fetchSpy = stubAe(async () => aeResponse(rows));
		const res = await internalRoutes.request('/analytics/key-usage', { headers: AUTH }, CONFIGURED);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ days: '7', keyHash: 'all', usage: rows });
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});

	it('echoes the key_hash prefix and binds it into the query', async () => {
		const { internalRoutes } = await import('../src/internal');
		const { queryKeyUsage } = await import('../src/lib/analytics-queries');
		const fetchSpy = stubAe(async () => aeResponse([]));
		const res = await internalRoutes.request('/analytics/key-usage?days=3&key_hash=abcd1234', { headers: AUTH }, CONFIGURED);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ days: '3', keyHash: 'abcd1234', usage: [] });
		const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
		expect(init.body).toBe(queryKeyUsage('3', 'abcd1234', 'bv_dns_security_mcp'));
	});
});
