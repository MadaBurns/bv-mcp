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
				body: {
					jsonrpc: '2.0',
					id: 1,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(429);
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
				body: {
					jsonrpc: '2.0',
					id: 1,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
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
				body: {
					jsonrpc: '2.0',
					id: 1,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
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
				// R8: batched per-IP evaluation — scoped-rate denies (minute limit exceeded).
				checkIpScopedQuotaBatch: vi.fn().mockResolvedValue({
					rate: { allowed: false, minuteRemaining: 0, hourRemaining: 50, retryAfterMs: 15_000 },
				}),
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 2,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
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
		expect(result.headers['retry-after']).toBe('15');
		expect(result.useErrorEnvelope).toBe(true);
	});

	it('includes x-ratelimit headers on allowed requests', async () => {
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				// R8: the unauthenticated path now folds scoped-rate + tool-daily into one batched call.
				checkIpScopedQuotaBatch: vi.fn().mockResolvedValue({
					rate: { allowed: true, minuteRemaining: 42, hourRemaining: 200 },
					toolDaily: { allowed: true, remaining: 199, limit: 200 },
				}),
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
				body: {
					jsonrpc: '2.0',
					id: 3,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
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
				// R8: batched per-IP evaluation — scoped-rate allows, tool-daily denies.
				checkIpScopedQuotaBatch: vi.fn().mockResolvedValue({
					rate: { allowed: true, minuteRemaining: 49, hourRemaining: 299 },
					toolDaily: { allowed: false, retryAfterMs: 50_000, remaining: 0, limit: 5 },
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
					params: { name: 'check_mx_reputation', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(429);
		const payload = result.payload as {
			error: { code: number; message: string; data?: { upgrade?: { channel: string; url: string; tier_required: string } } };
		};
		expect(payload.error.code).toBe(-32029);
		expect(payload.error.message).toContain('check_mx_reputation');
		expect(payload.error.message).toContain('5');
		expect(result.headers['x-quota-limit']).toBe('5');
		expect(result.headers['x-quota-remaining']).toBe('0');
		expect(result.headers['x-quota-tier']).toBe('free');
		// A free-tier volume ceiling is a conversion moment → additive self-serve upgrade
		// affordance (prose unchanged), always self_serve channel per isVolume429.
		expect(payload.error.data?.upgrade).toMatchObject({
			channel: 'self_serve',
			url: 'https://blackveilsecurity.com/contact?service=mcp-enterprise',
			tier_required: 'developer',
		});
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

	// ADAM non-negotiable #9: gated/paid-only tools must NOT fold a tool-daily check
	// into the batch — the prior serial path 403'd before ever incrementing tool-daily.
	// The batch must receive `undefined` as the toolDailyLimit for a gated tool so no
	// per-tool-daily counter is touched on the gated (401 + challenge / 403) path.
	it('excludes tool-daily from the batch for a gated paid-only tool (no tool-daily increment on the gated response)', async () => {
		const batchSpy = vi.fn().mockResolvedValue({ rate: { allowed: true, minuteRemaining: 49, hourRemaining: 299 } });
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkIpScopedQuotaBatch: batchSpy,
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 42,
					method: 'tools/call',
					// discover_subdomains is in GATED_PAID_ONLY_TOOLS → gated for unauthenticated.
					params: { name: 'discover_subdomains', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
				unauthChallenge: 'Bearer resource_metadata="https://dns-mcp.example.test/.well-known/oauth-protected-resource", scope="mcp"',
			}),
		);

		// UPGRADE_REQUIRED body as the serial path returned, now HTTP 401 + WWW-Authenticate because a challenge was supplied.
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(401);
		expect(result.headers['www-authenticate']).toContain(
			'resource_metadata="https://dns-mcp.example.test/.well-known/oauth-protected-resource"',
		);
		expect((result.payload as { error: { code: number } }).error.code).toBe(-32003);

		// The batch was invoked, and its 3rd positional arg (toolDailyLimit) is undefined
		// for the gated tool — so no per-tool-daily counter was ever touched.
		expect(batchSpy).toHaveBeenCalledTimes(1);
		const [ipArg, toolArg, toolDailyArg] = batchSpy.mock.calls[0];
		expect(ipArg).toBe('203.0.113.1');
		expect(toolArg).toBe('discover_subdomains');
		expect(toolDailyArg).toBeUndefined();
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
		expect(result.httpStatus).toBe(429);
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
		expect(checkToolSpy).toHaveBeenCalledWith('myhashxyz', 'scan_domain', expect.any(Number), undefined, undefined);
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
			validateSession: vi.fn().mockResolvedValue(false),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		// A valid shape does not prove the server issued this ID.
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

	it('requires the assigned session for notifications/* methods', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: undefined, method: 'notifications/cancelled', params: {} } as unknown as JsonRpcRequest,
				validateSession: true,
				sessionId: undefined,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(400);
		expect(result.payload).toMatchObject({
			jsonrpc: '2.0',
			id: null,
			error: { code: -32600 },
		});
	});
});

// ---------------------------------------------------------------------------
// Unknown or expired session rejection
// ---------------------------------------------------------------------------

describe('executeMcpRequest — unknown session rejection', () => {
	it('never recreates a caller-supplied valid-shaped session ID', async () => {
		vi.doMock('../src/lib/session', () => ({
			createSession: vi.fn(),
			validateSession: vi.fn().mockResolvedValue(false),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const validSessionId = 'b'.repeat(64);
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					method: 'notifications/cancelled',
					params: { requestId: 11 },
				} as unknown as JsonRpcRequest,
				validateSession: true,
				sessionId: validSessionId,
				isAuthenticated: true,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(404);
	});

	it('returns 404 for a malformed session without attempting recovery', async () => {
		vi.doMock('../src/lib/session', () => ({
			createSession: vi.fn(),
			validateSession: vi.fn().mockResolvedValue(false),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 12, method: 'tools/list', params: {} } as JsonRpcRequest,
				validateSession: true,
				sessionId: 'tooshort',
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(404);
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

	it('treats a non-notification method with explicit id=null as a real request (JSON-RPC 2.0 spec)', async () => {
		// Per JSON-RPC 2.0, a notification is a request WITHOUT an `id` member.
		// `id: null` is a valid (if discouraged) id that REQUIRES a response.
		// A spec-conformant client sending `tools/call` with `id: null` must NOT get a 202/notification ack.
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: null, result: { content: [] } },
				headers: {},
				newSessionId: undefined,
				logTool: 'tools/call',
				logCategory: 'call',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: null,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				validateSession: false,
			}),
		);

		// Must be a response, not a notification ack.
		expect(result.kind).toBe('response');
	});

	it('does NOT return kind=notification for initialize even without an id', async () => {
		// initialize with no id is weird, but the code specifically checks: isNotification && method !== 'initialize'
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: true }),
			createSession: vi.fn().mockResolvedValue('sess123'),
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
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 4, limit: 5 }),
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
		expect(result.httpStatus).toBe(429);
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
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 4, limit: 5 }),
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
				status: 429,
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
		expect(result.httpStatus).toBe(429);
		expect(result.useErrorEnvelope).toBe(true);
		const payload = result.payload as { error: { code: number } };
		expect(payload.error.code).toBe(-32029);
	});

	it('records the JSON-RPC error code in analytics on the JSON dispatch path', async () => {
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 9, error: { code: -32602, message: 'Invalid params' } },
				headers: {},
				newSessionId: undefined,
				logTool: 'scan_domain',
				logCategory: 'tool',
				logResult: 'error',
				logDetails: {},
			}),
		}));

		const emitRequestEvent = vi.fn();
		const analytics = {
			enabled: true,
			emitRequestEvent,
			emitToolEvent: vi.fn(),
			emitRateLimitEvent: vi.fn(),
			emitSessionEvent: vi.fn(),
		};

		const { executeMcpRequest } = await import('../src/mcp/execute');
		await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'scan_domain', arguments: {} } } as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'owner', keyHash: 'ownerkey' },
				analytics: analytics as unknown as ExecuteMcpRequestOptions['analytics'],
			}),
		);

		expect(emitRequestEvent).toHaveBeenCalledTimes(1);
		expect(emitRequestEvent.mock.calls[0][0]).toMatchObject({
			status: 'error',
			hasJsonRpcError: true,
			jsonRpcErrorCode: -32602,
		});
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
					enabled: true,
					emitToolEvent: vi.fn(),
					emitDegradationEvent: vi.fn(),
					emitUngradedNotCachedEvent: vi.fn(),
					emitDohPrimarySummary: vi.fn(),
					emitQuotaShardEvent: vi.fn(),
					emitQueueBatchEvent: vi.fn(),
					emitTailAggregate: vi.fn(),
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
					enabled: true,
					emitToolEvent: vi.fn(),
					emitDegradationEvent: vi.fn(),
					emitUngradedNotCachedEvent: vi.fn(),
					emitDohPrimarySummary: vi.fn(),
					emitQuotaShardEvent: vi.fn(),
					emitQueueBatchEvent: vi.fn(),
					emitTailAggregate: vi.fn(),
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
					enabled: true,
					emitToolEvent: vi.fn(),
					emitDegradationEvent: vi.fn(),
					emitUngradedNotCachedEvent: vi.fn(),
					emitDohPrimarySummary: vi.fn(),
					emitQuotaShardEvent: vi.fn(),
					emitQueueBatchEvent: vi.fn(),
					emitTailAggregate: vi.fn(),
					emitRateLimitEvent: emitRateLimitEventSpy,
					emitSessionEvent: vi.fn(),
				},
			}),
		);

		expect(emitRateLimitEventSpy).toHaveBeenCalledOnce();
		expect(emitRateLimitEventSpy).toHaveBeenCalledWith(expect.objectContaining({ limitType: 'daily_global' }));
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
						status: 429,
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
		expect(result.httpStatus).toBe(429);
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

// ---------------------------------------------------------------------------
// Unknown resource URI / prompt name are client errors, not 500 + -32603
// ---------------------------------------------------------------------------

describe('executeMcpRequest — unknown resource / prompt', () => {
	// Earlier suites vi.doMock the dispatcher and route gates; these cases need the real ones.
	beforeEach(() => {
		vi.doUnmock('../src/mcp/dispatch');
		vi.doUnmock('../src/mcp/route-gates');
	});

	it('resources/read with an unknown URI returns -32002 "Resource not found: <uri>" over HTTP 400', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 5, method: 'resources/read', params: { uri: 'dns-security://guides/nope' } } as JsonRpcRequest,
			}),
		);
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(400);
		const payload = result.payload as { id: number; error: { code: number; message: string } };
		expect(payload.id).toBe(5);
		expect(payload.error.code).toBe(-32002);
		expect(payload.error.message).toBe('Resource not found: dns-security://guides/nope');
	});

	it('prompts/get with an unknown name returns -32602 "Invalid prompt name: <name>" over HTTP 400', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: { jsonrpc: '2.0', id: 6, method: 'prompts/get', params: { name: 'no-such-prompt' } } as JsonRpcRequest,
			}),
		);
		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(400);
		const payload = result.payload as { id: number; error: { code: number; message: string } };
		expect(payload.id).toBe(6);
		expect(payload.error.code).toBe(-32602);
		expect(payload.error.message).toBe('Invalid prompt name: no-such-prompt');
	});
});

// ---------------------------------------------------------------------------
// Authenticated per-key daily total across all tools (SQ-494)
// ---------------------------------------------------------------------------

type RateLimitEmitter = NonNullable<ExecuteMcpRequestOptions['analytics']>['emitRateLimitEvent'];

describe('executeMcpRequest — authenticated per-key daily total across tools', () => {
	/** Lowered developer total so a cross-tool run reaches it in a few calls; every other tier keeps its shipped value. */
	const DEV_TOTAL = 3;
	const developerKey = { authenticated: true, tier: 'developer', keyHash: 'dev-total-key' } as const;

	// vi.doMock registrations outlive resetModules: earlier blocks leave a stubbed
	// rate-limiter behind, and these cases need the real (in-memory) counters.
	beforeEach(() => {
		vi.doUnmock('../src/lib/rate-limiter');
		vi.doUnmock('../src/lib/config');
		vi.doUnmock('../src/mcp/dispatch');
		vi.doUnmock('../src/lib/session');
	});

	function mockDeveloperTotal(perToolLimits: Record<string, number> = {}, otherTotals: Record<string, number> = {}): void {
		vi.doMock('../src/lib/config', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/config')>();
			return {
				...actual,
				TIER_AGGREGATE_DAILY_LIMITS: { ...actual.TIER_AGGREGATE_DAILY_LIMITS, ...otherTotals, developer: DEV_TOTAL },
				tierToolDailyLimit: (tier: Parameters<typeof actual.tierToolDailyLimit>[0], tool: string) =>
					perToolLimits[tool] ?? actual.tierToolDailyLimit(tier, tool),
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
	}

	function toolCall(name: string, overrides: Partial<ExecuteMcpRequestOptions> = {}): ExecuteMcpRequestOptions {
		return baseOptions({
			body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: { domain: 'example.com' } } } as JsonRpcRequest,
			...overrides,
		});
	}

	function asDeveloper(overrides: Partial<ExecuteMcpRequestOptions> = {}): Partial<ExecuteMcpRequestOptions> {
		return { isAuthenticated: true, tierAuthResult: developerKey, ...overrides };
	}

	function analyticsWith(emitRateLimitEvent: RateLimitEmitter): ExecuteMcpRequestOptions['analytics'] {
		return {
			enabled: true,
			emitRequestEvent: vi.fn(),
			emitToolEvent: vi.fn(),
			emitDegradationEvent: vi.fn(),
			emitUngradedNotCachedEvent: vi.fn(),
			emitDohPrimarySummary: vi.fn(),
			emitQuotaShardEvent: vi.fn(),
			emitQueueBatchEvent: vi.fn(),
			emitTailAggregate: vi.fn(),
			emitRateLimitEvent,
			emitSessionEvent: vi.fn(),
		};
	}

	async function statusOf(result: Promise<import('../src/mcp/execute').ProcessedRequestResult>) {
		const settled = await result;
		if (settled.kind !== 'response') throw new Error('expected response');
		return settled;
	}

	it('rejects the first call past the total even though every per-tool counter is under its cap', async () => {
		mockDeveloperTotal();
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const { AGGREGATE_QUOTA_COUNTER } = await import('../src/lib/config');

		for (const tool of ['scan_domain', 'check_spf', 'check_dmarc']) {
			const allowed = await statusOf(executeMcpRequest(toolCall(tool, asDeveloper())));
			expect(allowed.httpStatus).toBe(200);
			// Allowed calls keep reporting the per-tool counter, exactly as before the total existed.
			expect(allowed.headers['x-quota-limit']).toBe('500');
			expect(allowed.headers['x-quota-remaining']).toBe('499');
		}

		const emitRateLimitEvent = vi.fn<RateLimitEmitter>();
		const denied = await statusOf(executeMcpRequest(toolCall('check_mx', asDeveloper({ analytics: analyticsWith(emitRateLimitEvent) }))));
		expect(denied.httpStatus).toBe(429);
		const payload = denied.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32029);
		expect(payload.error.message).toBe(`Rate limit exceeded. developer tier is limited to ${DEV_TOTAL} requests per day across all tools.`);
		expect(denied.headers['x-quota-limit']).toBe(String(DEV_TOTAL));
		expect(denied.headers['x-quota-remaining']).toBe('0');
		expect(denied.headers['x-quota-tier']).toBe('developer');
		expect(Number(denied.headers['retry-after'])).toBeGreaterThan(0);
		expect(emitRateLimitEvent).toHaveBeenCalledWith(
			expect.objectContaining({ limitType: 'daily_tool', toolName: AGGREGATE_QUOTA_COUNTER, limit: DEV_TOTAL, authTier: 'developer' }),
		);
	});

	it('a per-tool denial does not consume the total, and the per-tool message is unchanged', async () => {
		mockDeveloperTotal({ check_spf: 1 });
		const { executeMcpRequest } = await import('../src/mcp/execute');

		expect((await statusOf(executeMcpRequest(toolCall('check_spf', asDeveloper())))).httpStatus).toBe(200);
		const perTool = await statusOf(executeMcpRequest(toolCall('check_spf', asDeveloper())));
		expect(perTool.httpStatus).toBe(429);
		expect((perTool.payload as { error: { message: string } }).error.message).toBe(
			'Rate limit exceeded. developer tier is limited to 1 requests per day.',
		);

		// Two more calls fit only if the per-tool denial above left the total at 1 of 3.
		expect((await statusOf(executeMcpRequest(toolCall('check_dmarc', asDeveloper())))).httpStatus).toBe(200);
		expect((await statusOf(executeMcpRequest(toolCall('check_mx', asDeveloper())))).httpStatus).toBe(200);
		const overTotal = await statusOf(executeMcpRequest(toolCall('check_ns', asDeveloper())));
		expect(overTotal.httpStatus).toBe(429);
		expect((overTotal.payload as { error: { message: string } }).error.message).toContain('across all tools');
	});

	it('keys the total on the same principal as the per-tool counter', async () => {
		const checkToolSpy = vi.fn().mockResolvedValue({ allowed: true, remaining: 9_999, limit: 10_000 });
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return { ...actual, checkToolDailyRateLimit: checkToolSpy };
		});
		mockDeveloperTotal();
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const { AGGREGATE_QUOTA_COUNTER, TIER_AGGREGATE_DAILY_LIMITS } = await import('../src/lib/config');

		await executeMcpRequest(
			toolCall('scan_domain', { isAuthenticated: true, tierAuthResult: { authenticated: true, tier: 'enterprise', keyHash: 'ent-key' } }),
		);

		expect(checkToolSpy).toHaveBeenNthCalledWith(1, 'ent-key', 'scan_domain', 10_000, undefined, undefined);
		expect(checkToolSpy).toHaveBeenNthCalledWith(
			2,
			'ent-key',
			AGGREGATE_QUOTA_COUNTER,
			TIER_AGGREGATE_DAILY_LIMITS.enterprise,
			undefined,
			undefined,
		);
	});

	it('omits retry-after when the denying counter gives no retry hint', async () => {
		const checkToolSpy = vi
			.fn()
			.mockResolvedValueOnce({ allowed: true, remaining: 499, limit: 500 })
			.mockResolvedValueOnce({ allowed: false, remaining: 0, limit: DEV_TOTAL });
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return { ...actual, checkToolDailyRateLimit: checkToolSpy };
		});
		mockDeveloperTotal();
		const { executeMcpRequest } = await import('../src/mcp/execute');

		const denied = await statusOf(executeMcpRequest(toolCall('check_spf', asDeveloper())));
		expect(denied.httpStatus).toBe(429);
		expect(denied.headers['x-quota-limit']).toBe(String(DEV_TOTAL));
		expect(denied.headers).not.toHaveProperty('retry-after');
	});

	it('exposes the remaining total on allowed calls without changing the per-tool headers', async () => {
		mockDeveloperTotal();
		const { executeMcpRequest } = await import('../src/mcp/execute');

		const first = await statusOf(executeMcpRequest(toolCall('check_spf', asDeveloper())));
		expect(first.httpStatus).toBe(200);
		expect(first.headers['x-quota-limit']).toBe('500');
		expect(first.headers['x-quota-remaining']).toBe('499');
		expect(first.headers['x-quota-total-remaining']).toBe(String(DEV_TOTAL - 1));

		const second = await statusOf(executeMcpRequest(toolCall('check_spf', asDeveloper())));
		expect(second.headers['x-quota-total-remaining']).toBe(String(DEV_TOTAL - 2));
	});

	it('does not send x-quota-total-remaining for an uncapped tier', async () => {
		mockDeveloperTotal();
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const owner = { isAuthenticated: true, tierAuthResult: { authenticated: true, tier: 'owner', keyHash: 'owner-hdr-key' } as const };

		const result = await statusOf(executeMcpRequest(toolCall('check_spf', owner)));
		expect(result.httpStatus).toBe(200);
		expect(result.headers).not.toHaveProperty('x-quota-total-remaining');
	});

	it('a client-supplied tool name equal to the aggregate counter is unknown and consumes nothing', async () => {
		mockDeveloperTotal();
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const { AGGREGATE_QUOTA_COUNTER } = await import('../src/lib/config');

		// Raw, upper-cased and padded spellings all normalise onto the counter name.
		for (const spelling of [AGGREGATE_QUOTA_COUNTER, AGGREGATE_QUOTA_COUNTER.toUpperCase(), ` ${AGGREGATE_QUOTA_COUNTER} `]) {
			const reserved = await statusOf(executeMcpRequest(toolCall(spelling, asDeveloper())));
			expect(reserved.httpStatus).toBe(200);
			const result = (reserved.payload as { result: { isError: boolean; content: Array<{ text: string }> } }).result;
			expect(result.isError).toBe(true);
			expect(result.content[0].text).toContain(`Unknown tool: ${AGGREGATE_QUOTA_COUNTER}`);
		}

		// The whole total is still available: had a reserved call counted (twice each), fewer fit.
		for (const tool of ['check_spf', 'check_dmarc', 'check_mx']) {
			expect((await statusOf(executeMcpRequest(toolCall(tool, asDeveloper())))).httpStatus).toBe(200);
		}
		const overTotal = await statusOf(executeMcpRequest(toolCall('check_ns', asDeveloper())));
		expect(overTotal.httpStatus).toBe(429);
		expect((overTotal.payload as { error: { message: string } }).error.message).toContain('across all tools');
	});

	it('a call rejected by the concurrency limit does not consume the total', async () => {
		const state = { reject: true };
		const release = vi.fn();
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				acquireConcurrencySlot: vi.fn(() =>
					state.reject ? { allowed: false, retryAfterMs: 1000, active: 10, limit: 10 } : { allowed: true, active: 1, limit: 10 },
				),
				releaseConcurrencySlot: release,
			};
		});
		mockDeveloperTotal();
		const { executeMcpRequest } = await import('../src/mcp/execute');

		// More rejected calls than the total allows: if they consumed it, nothing would fit below.
		for (let i = 0; i < DEV_TOTAL + 2; i++) {
			const rejected = await statusOf(executeMcpRequest(toolCall('check_spf', asDeveloper())));
			expect(rejected.httpStatus).toBe(429);
			expect((rejected.payload as { error: { message: string } }).error.message).toContain('concurrent requests');
		}

		state.reject = false;
		for (const tool of ['check_dmarc', 'check_mx', 'check_ns']) {
			expect((await statusOf(executeMcpRequest(toolCall(tool, asDeveloper())))).httpStatus).toBe(200);
		}
		const overTotal = await statusOf(executeMcpRequest(toolCall('check_ptr', asDeveloper())));
		expect(overTotal.httpStatus).toBe(429);
		expect((overTotal.payload as { error: { message: string } }).error.message).toContain('across all tools');
		// Three completed calls release in the finally block; the total denial hands back its slot too.
		expect(release).toHaveBeenCalledTimes(4);
	});

	it('a call rejected by session validation does not consume the total', async () => {
		const state = { valid: false };
		vi.doMock('../src/lib/session', () => ({
			checkSessionCreateRateLimit: vi.fn().mockResolvedValue({ allowed: true }),
			createSession: vi.fn(),
			validateSession: vi.fn(async () => state.valid),
		}));
		mockDeveloperTotal();
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const withSession = asDeveloper({ validateSession: true, sessionId: 'b'.repeat(64) });

		for (let i = 0; i < DEV_TOTAL + 2; i++) {
			expect((await statusOf(executeMcpRequest(toolCall('check_spf', withSession)))).httpStatus).toBe(404);
		}

		state.valid = true;
		for (const tool of ['check_dmarc', 'check_mx', 'check_ns']) {
			expect((await statusOf(executeMcpRequest(toolCall(tool, withSession)))).httpStatus).toBe(200);
		}
		expect((await statusOf(executeMcpRequest(toolCall('check_ptr', withSession)))).httpStatus).toBe(429);
	});

	it('owner keys are not capped by the total', async () => {
		mockDeveloperTotal();
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const owner = { isAuthenticated: true, tierAuthResult: { authenticated: true, tier: 'owner', keyHash: 'owner-total-key' } as const };

		for (let i = 0; i < DEV_TOTAL + 2; i++) {
			const result = await statusOf(executeMcpRequest(toolCall('check_spf', owner)));
			expect(result.httpStatus).toBe(200);
			expect(result.headers['x-quota-tier']).toBe('owner');
		}
	});

	it('unauthenticated callers are not capped by any tier total', async () => {
		// Every tier's total lowered, so applying ANY of them to an anonymous caller would deny here.
		mockDeveloperTotal({}, { free: DEV_TOTAL, agent: DEV_TOTAL, enterprise: DEV_TOTAL, partner: DEV_TOTAL, owner: DEV_TOTAL });
		const { executeMcpRequest } = await import('../src/mcp/execute');

		for (let i = 0; i < DEV_TOTAL + 2; i++) {
			const result = await statusOf(executeMcpRequest(toolCall('check_spf')));
			expect(result.httpStatus).toBe(200);
			expect(result.headers['x-quota-tier']).toBe('free');
		}
	});
});
