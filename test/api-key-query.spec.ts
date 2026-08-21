// SPDX-License-Identifier: BUSL-1.1

/**
 * FIND-01: REJECT_QUERY_API_KEY kill-switch tests.
 *
 * When `REJECT_QUERY_API_KEY='true'`, the `?api_key=` query-parameter
 * fallback must be silently nulled so the request proceeds as free tier
 * rather than being authenticated or rejected as a bad token.
 */

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import worker from '../src';
import { resetQuotaCoordinatorState } from '../src/lib/quota-coordinator';
import { resetAllRateLimits, resetAllRateLimitsKv } from '../src/lib/rate-limiter';
import { resetLegacySseState } from '../src/lib/legacy-sse';
import { resetSessions } from '../src/lib/session';

const TEST_API_KEY = 'test-api-key';

describe('REJECT_QUERY_API_KEY kill-switch', () => {
	beforeEach(async () => {
		resetAllRateLimits();
		resetSessions();
		resetLegacySseState();
		await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
		await resetAllRateLimitsKv(env.RATE_LIMIT);
	});

	it('when flag is set, an invalid ?api_key= is ignored and request proceeds as free tier (200)', async () => {
		// Without the flag, a wrong key causes a 401.
		// With the flag, the query token is nulled → token is null → no auth gate → 200 (free tier).
		const killSwitchEnv = { ...env, BV_API_KEY: TEST_API_KEY, REJECT_QUERY_API_KEY: 'true' } as Env;
		const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp?api_key=wrong-key', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, killSwitchEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
	});

	it('when flag is set, a valid ?api_key= is NOT honored — no Deprecation header (token was ignored, not merely unauthenticated)', async () => {
		// Without the flag, valid api_key in query → authenticated → Deprecation header set + 200.
		// With the flag, query token is nulled → treated as unauthenticated free tier → no Deprecation header.
		const killSwitchEnv = { ...env, BV_API_KEY: TEST_API_KEY, REJECT_QUERY_API_KEY: 'true' } as Env;
		const request = new Request<unknown, IncomingRequestCfProperties>(`http://example.com/mcp?api_key=${TEST_API_KEY}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, killSwitchEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
		expect(response.headers.get('Deprecation')).toBeNull();
	});

	it('when flag is NOT set, a valid ?api_key= still authenticates (existing behavior preserved)', async () => {
		const authEnv = { ...env, BV_API_KEY: TEST_API_KEY } as Env;
		const request = new Request<unknown, IncomingRequestCfProperties>(`http://example.com/mcp?api_key=${TEST_API_KEY}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, authEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
		expect(response.headers.get('mcp-session-id')).toBeTruthy();
		// The Deprecation header must be set — this is the expected deprecation signal.
		expect(response.headers.get('Deprecation')).toBe('true');
	});

	it('when flag is set, Authorization: Bearer still authenticates normally', async () => {
		const killSwitchEnv = { ...env, BV_API_KEY: TEST_API_KEY, REJECT_QUERY_API_KEY: 'true' } as Env;
		const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_API_KEY}`,
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, killSwitchEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
		expect(response.headers.get('mcp-session-id')).toBeTruthy();
		// No Deprecation header because no query token was used.
		expect(response.headers.get('Deprecation')).toBeNull();
	});
});

/**
 * #747: `X-API-Key` header auth. Precedence is Bearer → X-API-Key → `?api_key=`.
 */
describe('X-API-Key header auth', () => {
	beforeEach(async () => {
		resetAllRateLimits();
		resetSessions();
		resetLegacySseState();
		await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
		await resetAllRateLimitsKv(env.RATE_LIMIT);
	});

	const initRequest = (headers: Record<string, string>, url = 'http://example.com/mcp') =>
		new Request<unknown, IncomingRequestCfProperties>(url, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', ...headers },
			body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }),
		});

	const run = async (request: Request<unknown, IncomingRequestCfProperties>, overrides: Partial<Env> = {}) => {
		const testEnv = { ...env, BV_API_KEY: TEST_API_KEY, ...overrides } as Env;
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);
		return response;
	};

	it('authenticates with a valid X-API-Key header alone (no Deprecation header)', async () => {
		// REQUIRE_AUTH forces a 401 for an unauthenticated caller, so a 200 here
		// proves the header actually authenticated rather than falling through to free tier.
		const response = await run(initRequest({ 'X-API-Key': TEST_API_KEY }), { REQUIRE_AUTH: 'true' } as Partial<Env>);
		expect(response.status).toBe(200);
		expect(response.headers.get('mcp-session-id')).toBeTruthy();
		expect(response.headers.get('Deprecation')).toBeNull();
	});

	it('rejects a bad X-API-Key exactly like a bad Bearer token (401)', async () => {
		const headerResponse = await run(initRequest({ 'X-API-Key': 'wrong-key' }));
		const bearerResponse = await run(initRequest({ Authorization: 'Bearer wrong-key' }));
		expect(headerResponse.status).toBe(401);
		expect(bearerResponse.status).toBe(401);
		expect(await headerResponse.json()).toEqual(await bearerResponse.json());
	});

	it('Bearer wins when both are present with different values (valid Bearer + bad header → 200)', async () => {
		const response = await run(initRequest({ Authorization: `Bearer ${TEST_API_KEY}`, 'X-API-Key': 'wrong-key' }));
		expect(response.status).toBe(200);
		expect(response.headers.get('mcp-session-id')).toBeTruthy();
	});

	it('Bearer wins when both are present with different values (bad Bearer + valid header → 401)', async () => {
		const response = await run(initRequest({ Authorization: 'Bearer wrong-key', 'X-API-Key': TEST_API_KEY }));
		expect(response.status).toBe(401);
	});

	it('header wins over ?api_key= (valid header + bad query → 200, no Deprecation header)', async () => {
		const response = await run(initRequest({ 'X-API-Key': TEST_API_KEY }, 'http://example.com/mcp?api_key=wrong-key'));
		expect(response.status).toBe(200);
		expect(response.headers.get('Deprecation')).toBeNull();
	});

	it('header wins over ?api_key= (bad header + valid query → 401)', async () => {
		const response = await run(initRequest({ 'X-API-Key': 'wrong-key' }, `http://example.com/mcp?api_key=${TEST_API_KEY}`));
		expect(response.status).toBe(401);
	});

	it('an empty/whitespace X-API-Key is ignored — request proceeds as free tier', async () => {
		const response = await run(initRequest({ 'X-API-Key': '   ' }));
		expect(response.status).toBe(200);
	});

	it('is not disabled by REJECT_QUERY_API_KEY (that kill-switch covers the query param only)', async () => {
		const response = await run(initRequest({ 'X-API-Key': TEST_API_KEY }), {
			REJECT_QUERY_API_KEY: 'true',
			REQUIRE_AUTH: 'true',
		} as Partial<Env>);
		expect(response.status).toBe(200);
		expect(response.headers.get('mcp-session-id')).toBeTruthy();
	});
});
