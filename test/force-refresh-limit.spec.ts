// SPDX-License-Identifier: BUSL-1.1

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetAllRateLimits, resetGlobalDailyLimit, resetConcurrencyLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';
import type { ExecuteMcpRequestOptions } from '../src/mcp/execute';
import type { JsonRpcRequest } from '../src/lib/json-rpc';

/** Build a minimal valid ExecuteMcpRequestOptions for testing */
function baseOptions(overrides: Partial<ExecuteMcpRequestOptions> = {}): ExecuteMcpRequestOptions {
	return {
		body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} } as JsonRpcRequest,
		allowStreaming: false,
		batchMode: false,
		batchSize: 1,
		responseTransport: 'json',
		startTime: Date.now(),
		ip: '203.0.113.99',
		isAuthenticated: false,
		validateSession: false,
		serverVersion: '3.0.0',
		...overrides,
	};
}

beforeEach(() => {
	resetAllRateLimits();
	resetGlobalDailyLimit();
	resetConcurrencyLimits();
	resetSessions();
});

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

// ---------------------------------------------------------------------------
// Constant sanity check
// ---------------------------------------------------------------------------

describe('force_refresh sub-limit — constant', () => {
	it('exposes a FORCE_REFRESH_DAILY_LIMIT smaller than the per-tool free limit', async () => {
		const { FORCE_REFRESH_DAILY_LIMIT, FREE_TOOL_DAILY_LIMITS } = await import('../src/lib/config');
		expect(FORCE_REFRESH_DAILY_LIMIT).toBeLessThan(FREE_TOOL_DAILY_LIMITS.scan_domain);
		expect(FORCE_REFRESH_DAILY_LIMIT).toBeGreaterThan(0);
	});
});

// ---------------------------------------------------------------------------
// Behavioral enforcement via executeMcpRequest
// ---------------------------------------------------------------------------

describe('force_refresh sub-limit — enforcement in execute path', () => {
	it('returns rate-limited error (-32029) for free-tier caller with force_refresh: true when daily cap is exhausted', async () => {
		// The spy returns denied specifically for the synthetic '__force_refresh__' key,
		// but allows the normal per-tool scan_domain call.
		const checkToolSpy = vi.fn().mockImplementation(
			async (_principalId: string, toolName: string, _limit: number) => {
				if (toolName === '__force_refresh__') {
					return { allowed: false, retryAfterMs: 50_000, remaining: 0, limit: 5 };
				}
				// Normal per-tool quota — allow
				return { allowed: true, remaining: 24, limit: 25 };
			},
		);

		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkRateLimit: vi.fn().mockResolvedValue({ allowed: true, minuteRemaining: 49, hourRemaining: 299 }),
				checkToolDailyRateLimit: checkToolSpy,
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 1,
					method: 'tools/call',
					params: { name: 'scan_domain', arguments: { domain: 'example.com', force_refresh: true } },
				} as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(429);

		const payload = result.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32029);
		expect(payload.error.message).toContain('Rate limit exceeded');

		// Verify the synthetic key was checked
		const forceRefreshCalls = checkToolSpy.mock.calls.filter(([, toolName]) => toolName === '__force_refresh__');
		expect(forceRefreshCalls.length).toBeGreaterThanOrEqual(1);
		// The principalId must be the client IP
		expect(forceRefreshCalls[0][0]).toBe('203.0.113.99');

		// Quota headers should reflect the force_refresh limit
		expect(result.headers['x-quota-limit']).toBe('5');
		expect(result.headers['x-quota-remaining']).toBe('0');
		expect(result.headers['x-quota-tier']).toBe('free');
		expect(result.headers['retry-after']).toBe('50');
	});

	it('does NOT enforce the force_refresh sub-limit when force_refresh is absent', async () => {
		const checkToolSpy = vi.fn().mockResolvedValue({ allowed: true, remaining: 24, limit: 25 });

		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkRateLimit: vi.fn().mockResolvedValue({ allowed: true, minuteRemaining: 49, hourRemaining: 299 }),
				checkToolDailyRateLimit: checkToolSpy,
			};
		});
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 2, result: {} },
				headers: {},
				newSessionId: undefined,
				logTool: 'scan_domain',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 2,
					method: 'tools/call',
					params: { name: 'scan_domain', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		// The '__force_refresh__' synthetic key must NOT have been checked
		const forceRefreshCalls = checkToolSpy.mock.calls.filter(([, toolName]) => toolName === '__force_refresh__');
		expect(forceRefreshCalls.length).toBe(0);
	});

	it('does NOT enforce the force_refresh sub-limit for authenticated callers', async () => {
		const checkToolSpy = vi.fn().mockResolvedValue({ allowed: true, remaining: 999, limit: 1000 });

		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkToolDailyRateLimit: checkToolSpy,
				acquireConcurrencySlot: vi.fn().mockReturnValue({ allowed: true, active: 1, limit: 10 }),
				releaseConcurrencySlot: vi.fn(),
			};
		});
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 3, result: {} },
				headers: {},
				newSessionId: undefined,
				logTool: 'scan_domain',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 3,
					method: 'tools/call',
					params: { name: 'scan_domain', arguments: { domain: 'example.com', force_refresh: true } },
				} as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'developer', keyHash: 'devhash456' },
			}),
		);

		// Authenticated callers are not in the free-tier block, so __force_refresh__ is never checked
		const forceRefreshCalls = checkToolSpy.mock.calls.filter(([, toolName]) => toolName === '__force_refresh__');
		expect(forceRefreshCalls.length).toBe(0);

		// The call itself should not be rate-limited
		if (result.kind === 'response') {
			expect(result.httpStatus).not.toBe(429);
		}
	});
});
