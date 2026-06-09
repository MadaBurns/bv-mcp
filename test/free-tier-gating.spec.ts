// SPDX-License-Identifier: BUSL-1.1

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
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
	// vi.restoreAllMocks and vi.resetModules intentionally omitted here because
	// we use dynamic imports inside each test for isolation (matching the existing
	// mcp-execute.spec.ts pattern), but we don't mock modules across tests.
});

// ---------------------------------------------------------------------------
// Paid-gated tool enforcement (HTTP 403)
// ---------------------------------------------------------------------------

describe('executeMcpRequest — paid-gated tool enforcement', () => {
	it('returns HTTP 403 with UPGRADE_REQUIRED code for unauthenticated caller hitting discover_subdomains', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 100,
					method: 'tools/call',
					params: { name: 'discover_subdomains', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(403);
		const payload = result.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32003);
		expect(payload.error.message).toMatch(/paid plan/i);
		expect(result.useErrorEnvelope).toBe(true);
	});

	it('returns HTTP 403 for authenticated free-tier caller hitting simulate_attack_paths', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 101,
					method: 'tools/call',
					params: { name: 'simulate_attack_paths', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'free', keyHash: 'k_test' },
				authTier: 'free',
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(403);
		const payload = result.payload as { error: { code: number; message: string } };
		expect(payload.error.code).toBe(-32003);
	});

	it('returns HTTP 403 for authenticated agent-tier caller hitting batch_scan', async () => {
		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 102,
					method: 'tools/call',
					params: { name: 'batch_scan', arguments: { domains: ['example.com'] } },
				} as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'agent', keyHash: 'k_agent' },
				authTier: 'agent',
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).toBe(403);
	});

	it('does NOT return HTTP 403 for authenticated developer-tier caller hitting discover_subdomains', async () => {
		// developer tier is allowed; mock dispatch to succeed
		const { vi } = await import('vitest');
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 103, result: { content: [] } },
				headers: {},
				newSessionId: undefined,
				logTool: 'discover_subdomains',
				logCategory: 'tool',
				logResult: 'ok',
				logDetails: {},
			}),
		}));
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499, limit: 500 }),
				acquireConcurrencySlot: vi.fn().mockReturnValue({ allowed: true, active: 1, limit: 10 }),
				releaseConcurrencySlot: vi.fn(),
			};
		});

		const { executeMcpRequest } = await import('../src/mcp/execute');
		const result = await executeMcpRequest(
			baseOptions({
				body: {
					jsonrpc: '2.0',
					id: 103,
					method: 'tools/call',
					params: { name: 'discover_subdomains', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: true,
				tierAuthResult: { authenticated: true, tier: 'developer', keyHash: 'k_dev' },
				authTier: 'developer',
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).not.toBe(403);
		const payload403 = result.payload as { error?: { code: number } } | undefined;
		expect(payload403?.error?.code).not.toBe(-32003);
	});

	it('does NOT return HTTP 403 for unauthenticated caller hitting non-gated check_spf', async () => {
		// check_spf is a regular tool; the call will go through normal quota checks
		// and eventually hit dispatch. Mock dispatch to succeed.
		const { vi } = await import('vitest');
		vi.doMock('../src/lib/rate-limiter', async (importOriginal) => {
			const actual = await importOriginal<typeof import('../src/lib/rate-limiter')>();
			return {
				...actual,
				checkGlobalDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 499_999, limit: 500_000 }),
				checkIpDailyLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 99, limit: 100 }),
				checkRateLimit: vi.fn().mockResolvedValue({ allowed: true, minuteRemaining: 49, hourRemaining: 299 }),
				checkToolDailyRateLimit: vi.fn().mockResolvedValue({ allowed: true, remaining: 199, limit: 200 }),
				acquireConcurrencySlot: vi.fn().mockReturnValue({ allowed: true, active: 1, limit: 3 }),
				releaseConcurrencySlot: vi.fn(),
			};
		});
		vi.doMock('../src/mcp/dispatch', () => ({
			dispatchMcpMethod: vi.fn().mockResolvedValue({
				kind: 'success',
				payload: { jsonrpc: '2.0', id: 104, result: { content: [] } },
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
					id: 104,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				isAuthenticated: false,
			}),
		);

		expect(result.kind).toBe('response');
		if (result.kind !== 'response') throw new Error('expected response');
		expect(result.httpStatus).not.toBe(403);
		const payloadSpf = result.payload as { error?: { code: number } } | undefined;
		expect(payloadSpf?.error?.code).not.toBe(-32003);
	});
});
