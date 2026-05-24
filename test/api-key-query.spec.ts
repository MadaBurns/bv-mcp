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
