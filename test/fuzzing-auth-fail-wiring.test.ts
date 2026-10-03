// T10 item 2 regression: `classifyError` only returns `auth_fail` for `httpStatus === 401`, but
// `recordFuzzEvent` (src/mcp/execute.ts) never passed `httpStatus`, so the `auth_fail` kind and its
// threshold were dead — a 401 response never incremented any fuzz counter.
//
// The public 401 gate (`buildAuthRequiredResponse`) is currently SHADOWED by the internal-only gate
// for every real auth-required tool (see identity-secops-auth-gate.spec.ts), so this test forces the
// policy verdict to `auth_required` to exercise the live code path end to end: executeMcpRequest →
// emitRequestAnalytics → recordFuzzEvent → KV counter.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { env } from 'cloudflare:test';
import { resetAllRateLimits, resetGlobalDailyLimit, resetConcurrencyLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';
import type { ExecuteMcpRequestOptions } from '../src/mcp/execute';
import type { JsonRpcRequest } from '../src/lib/json-rpc';

const IP_HASH = 'i_t10authfail';

async function clearFuzz() {
	const list = await env.RATE_LIMIT.list({ prefix: 'fuzz:' });
	await Promise.all(list.keys.map((k) => env.RATE_LIMIT.delete(k.name)));
}

beforeEach(async () => {
	resetAllRateLimits();
	resetGlobalDailyLimit();
	resetConcurrencyLimits();
	resetSessions();
	await clearFuzz();
});

afterEach(async () => {
	vi.doUnmock('../src/lib/config');
	vi.resetModules();
	await clearFuzz();
});

describe('fuzzing auth_fail wiring — 401 responses reach the fuzz counter', () => {
	it('an anonymous 401 from the auth-required gate increments the auth_fail counter for the caller ipHash', async () => {
		vi.resetModules();
		vi.doMock('../src/lib/config', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/config')>();
			return {
				...actual,
				// Same verdict at both call sites: the internal-only check passes through (block !== 'internal_only'),
				// the later auth-required check fires — i.e. the gate that returns HTTP 401.
				evaluateToolPolicy: () => ({ allowed: false, block: 'auth_required' as const }),
			};
		});

		const pending: Promise<unknown>[] = [];
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const options: ExecuteMcpRequestOptions = {
			body: {
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'query_signins', arguments: { ms_tenant_id: 'tenant-abc' } },
			} as JsonRpcRequest,
			allowStreaming: false,
			batchMode: false,
			batchSize: 1,
			responseTransport: 'json',
			startTime: Date.now(),
			ip: '203.0.113.77',
			ipHash: IP_HASH,
			isAuthenticated: false,
			validateSession: false,
			serverVersion: '2.3.0',
			rateLimitKv: env.RATE_LIMIT,
			waitUntil: (p) => {
				pending.push(p);
			},
		};

		const result = await executeMcpRequest(options);
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(401);
		await Promise.all(pending);

		const list = await env.RATE_LIMIT.list({ prefix: `fuzz:p:${IP_HASH}:e:` });
		expect(list.keys.map((k) => k.name.split(':').pop())).toEqual(['auth_fail']);
	});
});
