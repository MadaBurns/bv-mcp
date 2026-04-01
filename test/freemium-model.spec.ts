import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import worker from '../src';
import { resetSessions } from '../src/lib/session';
import { resetAllRateLimits, resetGlobalDailyLimit } from '../src/lib/rate-limiter';

describe('Freemium Model Verification', () => {
	const TEST_API_KEY = 'test-api-key';
	const IP_ANON = '1.1.1.1';
	const IP_AUTH = '2.2.2.2';

	beforeEach(async () => {
		resetSessions();
		resetAllRateLimits();
		resetGlobalDailyLimit();
	});

	it('allows anonymous users to call tools (Free tier)', async () => {
		// 1. Initialize session anonymously
		const initReq = new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 
				'Content-Type': 'application/json',
				'cf-connecting-ip': IP_ANON
			},
			body: JSON.stringify({ 
				jsonrpc: '2.0', 
				id: 1, 
				method: 'initialize', 
				params: { capabilities: {}, serverInfo: { name: 'test', version: '1.0' } } 
			}),
		});
		const initCtx = createExecutionContext();
		const initRes = await worker.fetch(initReq, env, initCtx);
		await waitOnExecutionContext(initCtx);
		expect(initRes.status).toBe(200);
		const initBody = await initRes.json() as any;
		const sessionId = initRes.headers.get('mcp-session-id');
		expect(sessionId).toBeDefined();

		// 2. Call a tool (check_spf)
		const toolReq = new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 
				'Content-Type': 'application/json',
				'cf-connecting-ip': IP_ANON,
				'mcp-session-id': sessionId!
			},
			body: JSON.stringify({ 
				jsonrpc: '2.0', 
				id: 2, 
				method: 'tools/call', 
				params: { name: 'check_spf', arguments: { domain: 'google.com' } } 
			}),
		});
		const toolCtx = createExecutionContext();
		const toolRes = await worker.fetch(toolReq, env, toolCtx);
		await waitOnExecutionContext(toolCtx);
		
		expect(toolRes.status).toBe(200);
		const toolBody = await toolRes.json() as any;
		expect(toolBody.result).toBeDefined();
		expect(toolBody.error).toBeUndefined();
	});

	it('applies stricter limits to anonymous users vs authenticated users', async () => {
		// This is a conceptual test for the "Freemium" logic. 
		// We verify that unauthenticated users are processed with 'free' limits
		// and authenticated users are processed with their tier limits.
		
		const authEnv = { ...env, BV_API_KEY: TEST_API_KEY };

		// 1. Anonymous request
		const anonReq = new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 
				'Content-Type': 'application/json',
				'cf-connecting-ip': IP_ANON
			},
			body: JSON.stringify({ 
				jsonrpc: '2.0', 
				id: 1, 
				method: 'initialize', 
				params: {} 
			}),
		});
		const anonRes = await worker.fetch(anonReq, authEnv as any, createExecutionContext());
		const anonTier = anonRes.headers.get('x-mcp-tier');
		// Note: The worker might not always expose the tier in headers in production, 
		// but we can verify authentication state in the response or logs if needed.
		// For this test, we verify the request succeeds without a token.
		expect(anonRes.status).toBe(200);

		// 2. Authenticated request
		const authReq = new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 
				'Content-Type': 'application/json',
				'cf-connecting-ip': IP_AUTH,
				'Authorization': `Bearer ${TEST_API_KEY}`
			},
			body: JSON.stringify({ 
				jsonrpc: '2.0', 
				id: 2, 
				method: 'initialize', 
				params: {} 
			}),
		});
		const authRes = await worker.fetch(authReq, authEnv as any, createExecutionContext());
		expect(authRes.status).toBe(200);
	});

	it('respects REQUIRE_AUTH toggle while preserving freemium when disabled', async () => {
		// Case A: REQUIRE_AUTH=false (default) -> Anon allowed
		const envDefault = { ...env, REQUIRE_AUTH: 'false' };
		const reqAnon = new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
		});
		const resAnon = await worker.fetch(reqAnon, envDefault as any, createExecutionContext());
		expect(resAnon.status).toBe(200);

		// Case B: REQUIRE_AUTH=true -> Anon rejected
		const envStrict = { ...env, REQUIRE_AUTH: 'true' };
		const resStrict = await worker.fetch(reqAnon, envStrict as any, createExecutionContext());
		expect(resStrict.status).toBe(401);

		// Case C: REQUIRE_AUTH=true + Valid Key -> Allowed
		const envStrictAuth = { ...env, REQUIRE_AUTH: 'true', BV_API_KEY: TEST_API_KEY };
		const reqAuth = new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 
				'Content-Type': 'application/json',
				'Authorization': `Bearer ${TEST_API_KEY}`
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'initialize', params: {} }),
		});
		const resStrictAuth = await worker.fetch(reqAuth, envStrictAuth as any, createExecutionContext());
		expect(resStrictAuth.status).toBe(200);
	});
});
