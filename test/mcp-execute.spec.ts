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
		ip: '203.0.113.1',
		isAuthenticated: false,
		validateSession: false,
		serverVersion: '2.3.0',
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
// JSON-RPC validation
// ---------------------------------------------------------------------------

describe('executeMcpRequest — JSON-RPC validation', () => {
	it('rejects a request with invalid jsonrpc version field', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '1.0', id: 1, method: 'tools/list', params: {} } as JsonRpcRequest,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(400);
		expect((result.payload as { error: { code: number } }).error.code).toBe(-32600);
	});

	it('rejects a request with an invalid id type (array)', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: [] as unknown as string, method: 'tools/list', params: {} } as JsonRpcRequest,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(400);
		expect((result.payload as { error: { code: number; message: string } }).error.message).toContain('id');
		expect(result.useErrorEnvelope).toBe(true);
	});

	it('rejects a request missing the method field', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 1 } as unknown as JsonRpcRequest,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(400);
		expect(result.useErrorEnvelope).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// Batch-mode initialize restriction
// ---------------------------------------------------------------------------

describe('executeMcpRequest — batch initialize restriction', () => {
	it('rejects initialize when batched with other messages', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} } as JsonRpcRequest,
				batchMode: true,
				batchSize: 2,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(400);
		const payload = result.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32600);
		expect(payload.error.message).toContain('initialize cannot be batched');
		expect(result.useErrorEnvelope).toBe(true);
	});

	it('allows initialize when it is the sole batch item (batchSize=1)', async () => {
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: true }),
			createSession: vi.fn().mockResolvedValue('aabbcc'),
			reviveSession: vi.fn().mockResolvedValue(false),
		}));
		vi.doMock('../src/lib/audit', () => ({
			auditSessionCreated: vi.fn(),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} } as JsonRpcRequest,
				batchMode: true,
				batchSize: 1,
			}),
		);

		// Should not be a 400 batch error — may succeed or fail for session reasons, but not batch restriction
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		// Must not have the batch error message
		const payload = result.payload as { error?: { message: string }; result?: unknown };
		if (payload.error) {
			expect(payload.error.message).not.toContain('initialize cannot be batched');
		}
	});
});

// ---------------------------------------------------------------------------
// Global daily rate limit (unauthenticated tools/call)
// ---------------------------------------------------------------------------

describe('executeMcpRequest — global daily rate limit', () => {
	it('returns rate-limited response when global daily cap is exhausted', async () => {
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({
					allowed: false,
					retryAfterMs: 86_400_000,
					remaining: 0,
					limit: 500_000,
				}),
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'check_spf', arguments: { domain: 'example.com' } } } as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(200);
		const payload = result.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32029);
		expect(payload.error.message).toContain('Service capacity reached');
		expect(result.useErrorEnvelope).toBe(true);
	});

	it('sets retry-after header when global cap is exhausted', async () => {
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({
					allowed: false,
					retryAfterMs: 3600_000,
					remaining: 0,
					limit: 500_000,
				}),
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'check_spf', arguments: { domain: 'example.com' } } } as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.headers['retry-after']).toBe('3600');
	});

	it('does NOT check global daily limit for authenticated users', async () => {
		const checkGlobalSpy = vi.fn().mockResolvedValue({ allowed: false, remaining: 0, limit: 500_000 });

		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: checkGlobalSpy,
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 999, limit: 10_000 }),
			};
		});
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 1, result: {} },
				headers: {},
				newSessionId: undefined,
				logTool: 'check_spf',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'check_spf', arguments: { domain: 'example.com' } } } as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'developer', keyHash: 'abc123' },
			}),
		);

		expect(checkGlobalSpy).not.toHaveBeenCalled();
		// Should not be rate-limited by global daily limit
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect((result.payload as { error?: unknown }).error).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Per-IP rate limiting (unauthenticated tools/call)
// ---------------------------------------------------------------------------

describe('executeMcpRequest — per-IP rate limiting', () => {
	it('returns rate-limited response when per-IP minute limit is exceeded', async () => {
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkRateLimit: vi.fn().mockResolvedValue({
					allowed: false,
					minuteRemaining: 0,
					hourRemaining: 50,
					retryAfterMs: 15_000,
				}),
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'check_spf', arguments: { domain: 'example.com' } } } as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(200);
		const payload = result.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32029);
		expect(payload.error.message).toContain('Rate limit exceeded');
		expect(result.headers['retry-after']).toBe('15');
		expect(result.useErrorEnvelope).toBe(true);
	});

	it('includes x-ratelimit headers on allowed requests', async () => {
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkRateLimit: vi.fn().mockResolvedValue({
					allowed: true,
					minuteRemaining: 42,
					hourRemaining: 200,
				}),
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 199, limit: 200 }),
			};
		});
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 3, result: {} },
				headers: {},
				newSessionId: undefined,
				logTool: 'check_spf',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'check_spf', arguments: { domain: 'example.com' } } } as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.headers['x-ratelimit-limit']).toBe('50');
		expect(result.headers['x-ratelimit-remaining']).toBe('42');
		expect(result.headers['x-ratelimit-reset']).toBeDefined();
	});
});

// ---------------------------------------------------------------------------
// Per-tool daily limits (free tier)
// ---------------------------------------------------------------------------

describe('executeMcpRequest — per-tool daily limits (free tier)', () => {
	it('returns rate-limited response when per-tool daily quota is exhausted', async () => {
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkRateLimit: vi.fn().mockResolvedValue({ allowed: true, minuteRemaining: 49, hourRemaining: 299 }),
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({
					allowed: false,
					retryAfterMs: 50_000,
					remaining: 0,
					limit: 20,
				}),
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 4,
					method: 'tools/call',
					params: { name: 'check_lookalikes', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(200);
		const payload = result.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32029);
		expect(payload.error.message).toContain('check_lookalikes');
		expect(payload.error.message).toContain('20');
		// x-quota headers should be present
		expect(result.headers['x-quota-limit']).toBe('20');
		expect(result.headers['x-quota-remaining']).toBe('0');
		expect(result.headers['x-quota-tier']).toBe('free');
	});

	it('skips per-tool quota check for tools not in FREE_TOOL_DAILY_LIMITS', async () => {
		const checkToolSpy = vi.fn().mockResolvedValue({ allowed: true, remaining: 99, limit: 100 });

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
				payload: { jsonrpc: '2.0', id: 5, result: {} },
				headers: {},
				newSessionId: undefined,
				logTool: 'tools/list',
				logCategory: 'list',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		// Use a tool name not in FREE_TOOL_DAILY_LIMITS — e.g. 'nonexistent_tool'
		await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 5,
					method: 'tools/call',
					params: { name: 'nonexistent_tool', arguments: {} },
				} as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		// checkToolDailyRateLimit should NOT have been called since the tool has no free limit entry
		expect(checkToolSpy).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// Authenticated tier-based daily limits
// ---------------------------------------------------------------------------

describe('executeMcpRequest — authenticated tier daily limits', () => {
	it('returns rate-limited response when tier daily quota is exhausted', async () => {
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({
					allowed: false,
					retryAfterMs: 7_200_000,
					remaining: 0,
					limit: 500,
				}),
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 6,
					method: 'tools/call',
					params: { name: 'scan_domain', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'developer', keyHash: 'devhash123' },
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(200);
		const payload = result.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32029);
		expect(payload.error.message).toContain('developer');
		expect(payload.error.message).toContain('500');
		expect(result.headers['x-quota-tier']).toBe('developer');
		expect(result.headers['retry-after']).toBe('7200');
	});

	it('uses keyHash as principalId for authenticated tier limits', async () => {
		const checkToolSpy = vi.fn().mockResolvedValue({ allowed: true, remaining: 9_999, limit: 10_000 });

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
				payload: { jsonrpc: '2.0', id: 7, result: {} },
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
					id: 7,
					method: 'tools/call',
					params: { name: 'scan_domain', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'enterprise', keyHash: 'myhashxyz' },
			}),
		);

		// First arg to checkToolDailyRateLimit should be keyHash, not IP
		expect(checkToolSpy).toHaveBeenCalledWith(
			'myhashxyz',
			'scan_domain',
			expect.any(Number),
			undefined,
			undefined,
		);
	});
});

// ---------------------------------------------------------------------------
// Session validation
// ---------------------------------------------------------------------------

describe('executeMcpRequest — session validation', () => {
	it('returns 400 when session is required but missing', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 8, method: 'tools/list', params: {} } as JsonRpcRequest,
				validateSession: true,
				sessionId: undefined,
				sessionErrorMessage: 'Bad Request: missing session. Send an initialize request first to create a session.',
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(400);
		const payload = result.payload as { error: { code: number; message: string } };
		expect(payload.error.message).toContain('Bad Request: missing session');
		expect(result.useErrorEnvelope).toBe(true);
	});

	it('returns 404 when session ID is provided but session is expired', async () => {
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: true }),
			createSession: vi.fn(),
			// reviveSession returns false — session ID is malformed or tombstoned
			reviveSession: vi.fn().mockResolvedValue(false),
			validateSession: vi.fn().mockResolvedValue(false),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		// Use a valid-format 64-hex-char session ID so revive is attempted but fails
		const fakeSessionId = 'a'.repeat(64);
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 9, method: 'tools/list', params: {} } as JsonRpcRequest,
				validateSession: true,
				sessionId: fakeSessionId,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(404);
		expect(result.useErrorEnvelope).toBe(true);
	});

	it('skips session validation for initialize method', async () => {
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: true }),
			createSession: vi.fn().mockResolvedValue('newsession'),
			reviveSession: vi.fn().mockResolvedValue(false),
		}));
		vi.doMock('../src/lib/audit', () => ({
			auditSessionCreated: vi.fn(),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 10, method: 'initialize', params: {} } as JsonRpcRequest,
				validateSession: true,
				sessionId: undefined, // missing session, but initialize is exempt
			}),
		);

		// Should not fail with 400 (session validation is skipped for initialize)
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		// Should not be the missing-session 400
		expect(result.httpStatus).not.toBe(400);
	});

	it('skips session validation for notifications/* methods', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: undefined, method: 'notifications/cancelled', params: {} } as unknown as JsonRpcRequest,
				validateSession: true,
				sessionId: undefined,
			}),
		);

		// Notifications (no id) return kind='notification' without hitting session validation
		expect(result.kind).toBe('notification');
	});
});

// ---------------------------------------------------------------------------
// Session revival (expired session recovery)
// ---------------------------------------------------------------------------

describe('executeMcpRequest — session revival', () => {
	it('continues request after successfully reviving an expired session', async () => {
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: true }),
			createSession: vi.fn(),
			reviveSession: vi.fn().mockResolvedValue(true),
			validateSession: vi.fn().mockResolvedValue(false),
		}));
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 11, result: { tools: [] } },
				headers: {},
				newSessionId: undefined,
				logTool: 'tools/list',
				logCategory: 'list',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const validSessionId = 'b'.repeat(64);
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 11, method: 'tools/list', params: {} } as JsonRpcRequest,
				validateSession: true,
				sessionId: validSessionId,
				isAuthenticated: false,
			}),
		);

		// Should continue and succeed (not return 404)
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(200);
		const payload = result.payload as { result?: unknown; error?: unknown };
		expect(payload.error).toBeUndefined();
	});

	it('returns 404 when revival fails (tombstoned or malformed session)', async () => {
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: true }),
			createSession: vi.fn(),
			reviveSession: vi.fn().mockResolvedValue(false),
			validateSession: vi.fn().mockResolvedValue(false),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const validSessionId = 'c'.repeat(64);
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 12, method: 'tools/list', params: {} } as JsonRpcRequest,
				validateSession: true,
				sessionId: validSessionId,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(404);
	});

	it('still returns 404 for malformed session IDs (< 64 hex chars)', async () => {
		// reviveSession returns false for malformed IDs (isValidSessionIdFormat rejects them).
		const reviveSpy = vi.fn().mockResolvedValue(false);

		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: true }),
			createSession: vi.fn(),
			reviveSession: reviveSpy,
			validateSession: vi.fn().mockResolvedValue(false),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		// Malformed — too short, won't pass isValidSessionIdFormat
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 13, method: 'tools/list', params: {} } as JsonRpcRequest,
				validateSession: true,
				sessionId: 'tooshort',
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		// Should fail with 404 — session not found / invalid
		expect(result.httpStatus).toBe(404);
		// reviveSession is called but returns false because isValidSessionIdFormat rejects 'tooshort'
		if (reviveSpy.mock.calls.length > 0) {
			// If called, it should have returned false (no actual revival)
			expect(reviveSpy).toHaveReturnedWith(Promise.resolve(false));
		}
	});
});

// ---------------------------------------------------------------------------
// Notification handling
// ---------------------------------------------------------------------------

describe('executeMcpRequest — notification handling', () => {
	it('returns kind=notification for requests without an id (pure notifications)', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: undefined, method: 'notifications/progress', params: {} } as unknown as JsonRpcRequest,
				validateSession: false,
			}),
		);

		expect(result.kind).toBe('notification');
	});

	it('returns kind=notification for id=null notifications', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: null, method: 'notifications/cancelled', params: {} } as unknown as JsonRpcRequest,
				validateSession: false,
			}),
		);

		expect(result.kind).toBe('notification');
	});

	it('does NOT return kind=notification for initialize even without an id', async () => {
		// initialize with no id is weird, but the code specifically checks: isNotification && method !== 'initialize'
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: true }),
			createSession: vi.fn().mockResolvedValue('sess123'),
			reviveSession: vi.fn().mockResolvedValue(false),
		}));
		vi.doMock('../src/lib/audit', () => ({
			auditSessionCreated: vi.fn(),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: undefined, method: 'initialize', params: {} } as unknown as JsonRpcRequest,
				validateSession: false,
			}),
		);

		// initialize proceeds even without an id — never returns kind='notification'
		expect(result.kind).toBe('response');
	});
});

// ---------------------------------------------------------------------------
// Concurrency limiting
// ---------------------------------------------------------------------------

describe('executeMcpRequest — concurrency limiting', () => {
	it('returns rate-limited response when concurrency limit is exceeded (free tier)', async () => {
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkRateLimit: vi.fn().mockResolvedValue({ allowed: true, minuteRemaining: 49, hourRemaining: 299 }),
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 74, limit: 75 }),
				acquireConcurrencySlot: vi.fn().mockReturnValue({
					allowed: false,
					retryAfterMs: 1000,
					active: 3,
					limit: 3,
				}),
				releaseConcurrencySlot: vi.fn(),
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 14,
					method: 'tools/call',
					params: { name: 'scan_domain', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(200);
		const payload = result.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32029);
		expect(payload.error.message).toContain('free');
		expect(payload.error.message).toContain('3');
		expect(result.headers['retry-after']).toBe('1');
	});

	it('releases concurrency slot in finally block even when dispatch throws', async () => {
		const releaseSpy = vi.fn();

		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkRateLimit: vi.fn().mockResolvedValue({ allowed: true, minuteRemaining: 49, hourRemaining: 299 }),
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 74, limit: 75 }),
				acquireConcurrencySlot: vi.fn().mockReturnValue({ allowed: true, active: 1, limit: 3 }),
				releaseConcurrencySlot: releaseSpy,
			};
		});
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockRejectedValue(new Error('Unexpected dispatch failure')),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 15,
					method: 'tools/call',
					params: { name: 'scan_domain', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		// Should return an internal error, not propagate the throw
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(500);
		// The concurrency slot must have been released in the finally block
		expect(releaseSpy).toHaveBeenCalled();
	});

	it('does not track concurrency slots for owner tier (Infinity limit)', async () => {
		const acquireSpy = vi.fn().mockReturnValue({ allowed: true, active: 1, limit: Infinity });
		const releaseSpy = vi.fn();

		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: Infinity, limit: Infinity }),
				acquireConcurrencySlot: acquireSpy,
				releaseConcurrencySlot: releaseSpy,
			};
		});
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 16, result: {} },
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
					id: 16,
					method: 'tools/call',
					params: { name: 'scan_domain', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'owner', keyHash: 'ownerkey' },
			}),
		);

		// Owner tier has Infinity limit — acquireConcurrencySlot is NOT called
		expect(acquireSpy).not.toHaveBeenCalled();
		// releaseConcurrencySlot is also NOT called (no principalId tracked)
		expect(releaseSpy).not.toHaveBeenCalled();
	});
});

// ---------------------------------------------------------------------------
// Dispatch result handling
// ---------------------------------------------------------------------------

describe('executeMcpRequest — dispatch result propagation', () => {
	it('returns early-error result from dispatch with correct status', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'early-error',
				payload: { jsonrpc: '2.0', id: 17, error: { code: -32029, message: 'Rate limit exceeded. Session creation rate limited' } },
				headers: { 'retry-after': '30' },
				status: 200,
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 17, method: 'initialize', params: {} } as JsonRpcRequest,
				validateSession: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(200);
		expect(result.useErrorEnvelope).toBe(true);
		const payload = result.payload as { error: { code: number } };
		expect(payload.error.code).toBe(-32029);
	});

	it('includes new session ID in response headers from dispatch result', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 18, result: { capabilities: {} } },
				headers: {},
				newSessionId: 'd'.repeat(64),
				logTool: 'initialize',
				logCategory: 'session',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 18, method: 'initialize', params: {} } as JsonRpcRequest,
				validateSession: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.headers['mcp-session-id']).toBe('d'.repeat(64));
	});

	it('returns http 200 and no useErrorEnvelope for successful dispatch', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 19, result: { tools: [] } },
				headers: {},
				newSessionId: undefined,
				logTool: 'tools/list',
				logCategory: 'list',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 19, method: 'tools/list', params: {} } as JsonRpcRequest,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(200);
		expect(result.useErrorEnvelope).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Error handling / catch block
// ---------------------------------------------------------------------------

describe('executeMcpRequest — error handling', () => {
	it('returns 500 with sanitized error message when dispatch throws unexpectedly', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockRejectedValue(new Error('Internal database exploded')),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 20, method: 'tools/list', params: {} } as JsonRpcRequest,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(500);
		expect(result.useErrorEnvelope).toBe(true);
		const payload = result.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32603);
		// Unsafe internal details should be scrubbed
		expect(payload.error.message).not.toContain('database exploded');
		expect(payload.error.message).toBe('Internal server error');
	});

	it('passes through safe "Rate limit exceeded" error messages', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockRejectedValue(new Error('Rate limit exceeded. Please retry.')),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 21, method: 'tools/list', params: {} } as JsonRpcRequest,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		const payload = result.payload as { error: { message: string } };
		expect(payload.error.message).toContain('Rate limit exceeded');
	});

	it('passes through safe "Invalid" error messages', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockRejectedValue(new Error('Invalid domain: too short')),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 22, method: 'tools/list', params: {} } as JsonRpcRequest,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		const payload = result.payload as { error: { message: string } };
		expect(payload.error.message).toContain('Invalid domain');
	});
});

// ---------------------------------------------------------------------------
// Analytics emission
// ---------------------------------------------------------------------------

describe('executeMcpRequest — analytics', () => {
	it('emits analytics for a successful request', async () => {
		const emitRequestEventSpy = vi.fn();

		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 23, result: {} },
				headers: {},
				newSessionId: undefined,
				logTool: 'tools/list',
				logCategory: 'list',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 23, method: 'tools/list', params: {} } as JsonRpcRequest,
				analytics: {
					emitRequestEvent: emitRequestEventSpy,
					emitToolCallEvent: vi.fn(),
					emitRateLimitEvent: vi.fn(),
					emitSessionEvent: vi.fn(),
				},
			}),
		);

		expect(emitRequestEventSpy).toHaveBeenCalledOnce();
		expect(emitRequestEventSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				method: 'tools/list',
				status: 'ok',
				hasJsonRpcError: false,
			}),
		);
	});

	it('emits analytics with status=error for rate-limited requests', async () => {
		const emitRequestEventSpy = vi.fn();

		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: false, retryAfterMs: 1000, remaining: 0, limit: 500_000 }),
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 24,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
				analytics: {
					emitRequestEvent: emitRequestEventSpy,
					emitToolCallEvent: vi.fn(),
					emitRateLimitEvent: vi.fn(),
					emitSessionEvent: vi.fn(),
				},
			}),
		);

		expect(emitRequestEventSpy).toHaveBeenCalledOnce();
		expect(emitRequestEventSpy).toHaveBeenCalledWith(
			expect.objectContaining({
				status: 'error',
				hasJsonRpcError: true,
			}),
		);
	});

	it('emits a rate limit event when global daily cap is exhausted', async () => {
		const emitRateLimitEventSpy = vi.fn();

		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: false, retryAfterMs: 1000, remaining: 0, limit: 500_000 }),
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 25,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
				analytics: {
					emitRequestEvent: vi.fn(),
					emitToolCallEvent: vi.fn(),
					emitRateLimitEvent: emitRateLimitEventSpy,
					emitSessionEvent: vi.fn(),
				},
			}),
		);

		expect(emitRateLimitEventSpy).toHaveBeenCalledOnce();
		expect(emitRateLimitEventSpy).toHaveBeenCalledWith(
			expect.objectContaining({ limitType: 'daily_global' }),
		);
	});
});

// ---------------------------------------------------------------------------
// Control-plane rate limiting (non-tools/call methods)
// ---------------------------------------------------------------------------

describe('executeMcpRequest — control-plane rate limiting', () => {
	it('applies control-plane rate limit to non-standard methods for unauthenticated users', async () => {
		vi.doMock('../src/mcp/route-gates', () => ({
			buildControlPlaneRateLimitResponse: vi.fn().mockResolvedValue(
				Response.json(
					{ jsonrpc: '2.0', id: 26, error: { code: -32029, message: 'Rate limit exceeded. Retry after 2s' } },
					{
						status: 200,
						headers: { 'retry-after': '2', 'x-ratelimit-limit': '60', 'x-ratelimit-remaining': '0' },
					},
				),
			),
			validateSessionRequest: vi.fn().mockResolvedValue(undefined),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 26, method: 'unknown/method', params: {} } as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(200);
		expect(result.useErrorEnvelope).toBe(true);
		const payload = result.payload as { error: { code: number } };
		expect(payload.error.code).toBe(-32029);
	});
});

// ---------------------------------------------------------------------------
// eventId propagation
// ---------------------------------------------------------------------------

describe('executeMcpRequest — eventId propagation', () => {
	it('carries string id as eventId in the response', async () => {
		// Explicitly reset control-plane mock from prior test to avoid bleed-through
		vi.doMock('../src/mcp/route-gates', () => ({
			buildControlPlaneRateLimitResponse: vi.fn().mockResolvedValue(undefined),
			validateSessionRequest: vi.fn().mockResolvedValue(undefined),
		}));
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 'req-abc', result: {} },
				headers: {},
				newSessionId: undefined,
				logTool: 'tools/list',
				logCategory: 'list',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 'req-abc', method: 'tools/list', params: {} } as JsonRpcRequest,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.eventId).toBe('req-abc');
	});

	it('carries numeric id as string eventId in the response', async () => {
		vi.doMock('../src/mcp/route-gates', () => ({
			buildControlPlaneRateLimitResponse: vi.fn().mockResolvedValue(undefined),
			validateSessionRequest: vi.fn().mockResolvedValue(undefined),
		}));
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 42, result: {} },
				headers: {},
				newSessionId: undefined,
				logTool: 'tools/list',
				logCategory: 'list',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 42, method: 'tools/list', params: {} } as JsonRpcRequest,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.eventId).toBe('42');
	});
});
