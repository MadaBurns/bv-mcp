// SPDX-License-Identifier: BUSL-1.1
//
// Handler-body coverage for GET /internal/analytics/digest and /internal/analytics/geo.
// Both sit behind webOnlyGate (BV_WEB_INTERNAL_KEY bearer) and call the Analytics Engine
// SQL API through global fetch, which is the only boundary mocked here.

import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => vi.restoreAllMocks());

const WEB_KEY = 'web-internal-capability-test-key-32-bytes';
const AUTH = { authorization: `Bearer ${WEB_KEY}` };
const CONFIGURED = { BV_WEB_INTERNAL_KEY: WEB_KEY, CF_ACCOUNT_ID: 'acct-1', CF_ANALYTICS_TOKEN: 'ae-token' };

function aeResponse(data: unknown[]): Response {
	return new Response(JSON.stringify({ data }), { status: 200, headers: { 'content-type': 'application/json' } });
}

function stubAe(respond: () => Promise<Response>) {
	return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => respond());
}

describe.each([
	{ route: '/analytics/digest', bodyKey: 'tiers', failure: 'Analytics query failed' },
	{ route: '/analytics/geo', bodyKey: 'geo', failure: 'Geo query failed' },
])('GET /internal$route handler', ({ route, bodyKey, failure }) => {
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
		expect(await res.json()).toEqual({ error: 'Analytics not configured (CF_ACCOUNT_ID + CF_ANALYTICS_TOKEN required)' });
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('returns the Analytics Engine rows with the default 7-day window', async () => {
		const { internalRoutes } = await import('../src/internal');
		const rows = [{ k: 'a', n: 3 }];
		const fetchSpy = stubAe(async () => aeResponse(rows));
		const res = await internalRoutes.request(route, { headers: AUTH }, CONFIGURED);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ days: '7', [bodyKey]: rows });
		const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('https://api.cloudflare.com/client/v4/accounts/acct-1/analytics_engine/sql');
		expect((init.headers as Record<string, string>).Authorization).toBe('Bearer ae-token');
		expect(typeof init.body).toBe('string');
	});

	it('clamps ?days to 1..90 and falls back to 7 on a non-numeric value', async () => {
		const { internalRoutes } = await import('../src/internal');
		stubAe(async () => aeResponse([]));
		const daysFor = async (qs: string) => ((await (await internalRoutes.request(`${route}${qs}`, { headers: AUTH }, CONFIGURED)).json()) as { days: string }).days;
		expect(await daysFor('?days=500')).toBe('90');
		expect(await daysFor('?days=0')).toBe('1');
		expect(await daysFor('?days=3')).toBe('3');
		expect(await daysFor('?days=abc')).toBe('7');
	});

	it('502s with a truncated Error message when Analytics Engine rejects the query', async () => {
		const { internalRoutes } = await import('../src/internal');
		stubAe(async () => new Response('x'.repeat(500), { status: 422 }));
		const res = await internalRoutes.request(route, { headers: AUTH }, CONFIGURED);
		expect(res.status).toBe(502);
		const body = (await res.json()) as { error: string; detail: string };
		expect(body.error).toBe(failure);
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
		expect(await res.json()).toEqual({ error: failure, detail: 'unknown' });
	});
});

describe('GET /internal/analytics/digest hours window', () => {
	it('derives the AE query hours from the clamped days (days * 24)', async () => {
		const { internalRoutes } = await import('../src/internal');
		const { queryTierDigest } = await import('../src/lib/analytics-queries');
		const fetchSpy = stubAe(async () => aeResponse([]));
		await internalRoutes.request('/analytics/digest?days=2', { headers: AUTH }, CONFIGURED);
		const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
		expect(init.body).toBe(queryTierDigest('48', 'bv_dns_security_mcp'));
	});
});
