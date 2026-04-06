import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import worker from '../src';
import type { Env } from '../src/types/env';
import { resetSessions } from '../src/lib/session';

describe('Security Hardening - REQUIRE_AUTH', () => {
	beforeEach(async () => {
		resetSessions();
	});

	it('allows unauthenticated requests when REQUIRE_AUTH is not set', async () => {
		const request = new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
	});

	it('rejects unauthenticated requests when REQUIRE_AUTH is "true"', async () => {
		const authEnv = { ...env, REQUIRE_AUTH: 'true' } as Env;
		const request = new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, authEnv, ctx);
		await waitOnExecutionContext(ctx);
		
		// Should be 401 Unauthorized
		expect(response.status).toBe(401);
		const body = await response.json() as Record<string, unknown>;
		expect(body.error.code).toBe(-32001); // unauthorized
	});

	it('allows authenticated requests when REQUIRE_AUTH is "true"', async () => {
		const TEST_API_KEY = 'test-api-key';
		const authEnv = { ...env, REQUIRE_AUTH: 'true', BV_API_KEY: TEST_API_KEY } as Env;
		const request = new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 
				'Content-Type': 'application/json',
				'Authorization': `Bearer ${TEST_API_KEY}`
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, authEnv, ctx);
		await waitOnExecutionContext(ctx);
		
		expect(response.status).toBe(200);
	});
});
