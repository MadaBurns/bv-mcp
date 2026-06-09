// SPDX-License-Identifier: BUSL-1.1

/**
 * Integration tests for the free-tier distinct-domain daily cap.
 *
 * An unauthenticated IP is allowed to scan at most FREE_DISTINCT_DOMAIN_DAILY_LIMIT
 * distinct domains per day. Re-scanning an already-seen domain does not consume
 * additional budget.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetAllRateLimits, resetGlobalDailyLimit, resetConcurrencyLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';
import type { ExecuteMcpRequestOptions } from '../src/mcp/execute';
import type { JsonRpcRequest } from '../src/lib/json-rpc';
import { FREE_DISTINCT_DOMAIN_DAILY_LIMIT } from '../src/lib/config';

/** In-memory KV mock that persists state across calls (load-bearing for counter accumulation). */
function makeKv(): KVNamespace {
	const store = new Map<string, string>();
	return {
		async get(key: string): Promise<string | null> {
			return store.get(key) ?? null;
		},
		async put(key: string, value: string): Promise<void> {
			store.set(key, value);
		},
		async delete(key: string): Promise<void> {
			store.delete(key);
		},
		async list(): Promise<KVNamespaceListResult<unknown, string>> {
			return { keys: [], list_complete: true, cacheStatus: null } as unknown as KVNamespaceListResult<unknown, string>;
		},
		async getWithMetadata(): Promise<unknown> {
			return { value: null, metadata: null };
		},
	} as unknown as KVNamespace;
}

/** Build a minimal valid ExecuteMcpRequestOptions for testing */
function baseOptions(overrides: Partial<ExecuteMcpRequestOptions> = {}): ExecuteMcpRequestOptions {
	return {
		body: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} } as JsonRpcRequest,
		allowStreaming: false,
		batchMode: false,
		batchSize: 1,
		responseTransport: 'json',
		startTime: Date.now(),
		ip: '203.0.113.42',
		isAuthenticated: false,
		validateSession: false,
		serverVersion: '3.17.0',
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
// Distinct-domain daily cap (unauthenticated)
// ---------------------------------------------------------------------------

describe('executeMcpRequest — free-tier distinct-domain daily cap', () => {
	it('denies the (limit+1)-th distinct domain for an unauthenticated IP', async () => {
		// Mock the preceding rate limiters to always pass so we don't accidentally
		// trip a different 429 before reaching the distinct-domain check.
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkIpDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 999, limit: 1_000 }),
				checkRateLimit: vi.fn().mockResolvedValue({ allowed: true, minuteRemaining: 49, hourRemaining: 299 }),
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499, limit: 500 }),
				// Leave checkDistinctDomainDailyLimit as the REAL implementation so
				// it exercises the actual KV counter logic.
			};
		});
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'ok' }] } },
				headers: {},
				newSessionId: undefined,
				logTool: 'check_spf',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');

		// Shared KV so the distinct-domain counter accumulates across calls.
		const sharedKv = makeKv();

		const opts = baseOptions({
			isAuthenticated: false,
			rateLimitKv: sharedKv,
		});

		// Scan exactly FREE_DISTINCT_DOMAIN_DAILY_LIMIT distinct domains — all should be allowed.
		for (let i = 0; i < FREE_DISTINCT_DOMAIN_DAILY_LIMIT; i++) {
			const domain = `d${i}.example.com`;
			const result = await executeMcpRequest({
				...opts,
				body: {
					jsonrpc: '2.0',
					id: i + 1,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain } },
				} as JsonRpcRequest,
			});
			expect(result.kind).toBe('response');
			if (result.kind !== 'response') throw new Error('expected response');
			expect(result.httpStatus).not.toBe(429);
		}

		// One more NEW domain — must be denied.
		const overflowResult = await executeMcpRequest({
			...opts,
			body: {
				jsonrpc: '2.0',
				id: FREE_DISTINCT_DOMAIN_DAILY_LIMIT + 1,
				method: 'tools/call',
				params: { name: 'check_spf', arguments: { domain: `overflow-domain.example.com` } },
			} as JsonRpcRequest,
		});

		expect(overflowResult.kind).toBe('response');
		if (overflowResult.kind !== 'response') throw new Error('expected response');
		expect(overflowResult.httpStatus).toBe(429);
		const payload = overflowResult.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32029);
		expect(payload.error.message).toMatch(/distinct domains/i);
		expect(overflowResult.useErrorEnvelope).toBe(true);
	});

	it('re-scanning an already-seen domain stays allowed at cap', async () => {
		// Same mock setup as above.
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkIpDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 999, limit: 1_000 }),
				checkRateLimit: vi.fn().mockResolvedValue({ allowed: true, minuteRemaining: 49, hourRemaining: 299 }),
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499, limit: 500 }),
			};
		});
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 1, result: { content: [{ type: 'text', text: 'ok' }] } },
				headers: {},
				newSessionId: undefined,
				logTool: 'check_spf',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));

		const { executeMcpRequest } = await import('../src/mcp/execute');

		const sharedKv = makeKv();
		const opts = baseOptions({
			isAuthenticated: false,
			rateLimitKv: sharedKv,
		});

		// Fill the cap with FREE_DISTINCT_DOMAIN_DAILY_LIMIT distinct domains.
		for (let i = 0; i < FREE_DISTINCT_DOMAIN_DAILY_LIMIT; i++) {
			const domain = `d${i}.example.com`;
			await executeMcpRequest({
				...opts,
				body: {
					jsonrpc: '2.0',
					id: i + 1,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain } },
				} as JsonRpcRequest,
			});
		}

		// Re-scan d0 (already seen) — must NOT be denied.
		const rescanResult = await executeMcpRequest({
			...opts,
			body: {
				jsonrpc: '2.0',
				id: FREE_DISTINCT_DOMAIN_DAILY_LIMIT + 1,
				method: 'tools/call',
				params: { name: 'check_spf', arguments: { domain: 'd0.example.com' } },
			} as JsonRpcRequest,
		});

		expect(rescanResult.kind).toBe('response');
		if (rescanResult.kind !== 'response') throw new Error('expected response');
		expect(rescanResult.httpStatus).not.toBe(429);
	});
});
