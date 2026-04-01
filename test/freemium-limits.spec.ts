import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import worker from '../src';
import { resetSessions } from '../src/lib/session';
import { resetAllRateLimits, resetGlobalDailyLimit } from '../src/lib/rate-limiter';

describe('Freemium Model - Limits and Tiers', () => {
	const TEST_API_KEY = 'test-api-key';
	const IP_ANON = '1.1.1.1';
	const IP_AUTH = '2.2.2.2';

	beforeEach(async () => {
		resetSessions();
		resetAllRateLimits();
		resetGlobalDailyLimit();
	});

	it('applies Free tier limits to unauthenticated users', async () => {
		// We can't easily hit 75 requests in a unit test without mocking KV.
		// So we'll verify the headers that reflect the quota.
		
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
				params: {} 
			}),
		});
		const initRes = await worker.fetch(initReq, env, createExecutionContext());
		const sessionId = initRes.headers.get('mcp-session-id');

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
				params: { name: 'scan_domain', arguments: { domain: 'google.com' } } 
			}),
		});
		const toolRes = await worker.fetch(toolReq, env, createExecutionContext());
		
		// Unauthenticated tools/call should return quota headers for the IP
		expect(toolRes.headers.get('x-quota-tier')).toBe('free');
		expect(toolRes.headers.get('x-quota-limit')).toBe('75'); // From FREE_TOOL_DAILY_LIMITS.scan_domain
		expect(parseInt(toolRes.headers.get('x-quota-remaining')!)).toBeLessThan(75);
	});

	it('applies higher tier limits to authenticated users', async () => {
		// Mock BV_API_KEY as an 'owner' or 'partner' would require more setup,
		// but by default BV_API_KEY maps to 'owner' (Infinity) or 'partner' (100k).
		const authEnv = { ...env, BV_API_KEY: TEST_API_KEY };

		const initReq = new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 
				'Content-Type': 'application/json',
				'Authorization': `Bearer ${TEST_API_KEY}`
			},
			body: JSON.stringify({ 
				jsonrpc: '2.0', 
				id: 1, 
				method: 'initialize', 
				params: {} 
			}),
		});
		const initRes = await worker.fetch(initReq, authEnv as any, createExecutionContext());
		const sessionId = initRes.headers.get('mcp-session-id');

		const toolReq = new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { 
				'Content-Type': 'application/json',
				'Authorization': `Bearer ${TEST_API_KEY}`,
				'mcp-session-id': sessionId!
			},
			body: JSON.stringify({ 
				jsonrpc: '2.0', 
				id: 2, 
				method: 'tools/call', 
				params: { name: 'scan_domain', arguments: { domain: 'google.com' } } 
			}),
		});
		const toolRes = await worker.fetch(toolReq, authEnv as any, createExecutionContext());
		
		// Authenticated tier (default BV_API_KEY is 'owner' in this test setup)
		expect(toolRes.headers.get('x-quota-tier')).toBe('owner');
		expect(toolRes.headers.get('x-quota-limit')).toBe('Infinity');
	});
});
