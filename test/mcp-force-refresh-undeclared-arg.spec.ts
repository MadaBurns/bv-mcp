// SPDX-License-Identifier: BUSL-1.1

/**
 * The free-tier force_refresh quota gate (FIND-06) reads RAW tools/call arguments
 * before validation. Every tool schema is strict, so on a tool that does NOT declare
 * force_refresh the key is an unknown argument and the call is rejected: such a call
 * must not consume a force-refresh quota unit. A tool that declares it stays metered.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetAllRateLimits, resetGlobalDailyLimit, resetConcurrencyLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';
import type { ExecuteMcpRequestOptions } from '../src/mcp/execute';
import type { JsonRpcRequest } from '../src/lib/json-rpc';

function toolsCall(name: string, args: Record<string, unknown>): ExecuteMcpRequestOptions {
	return {
		body: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } } as JsonRpcRequest,
		allowStreaming: false,
		batchMode: false,
		batchSize: 1,
		responseTransport: 'json',
		startTime: Date.now(),
		ip: '203.0.113.77',
		isAuthenticated: false,
		validateSession: false,
		serverVersion: '3.0.0',
	};
}

async function executeWithQuotaSpy(name: string, args: Record<string, unknown>) {
	const checkToolSpy = vi.fn().mockResolvedValue({ allowed: true, remaining: 4, limit: 5 });
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
	const result = await executeMcpRequest(toolsCall(name, args));
	const forceRefreshUnits = checkToolSpy.mock.calls.filter(([, toolName]) => toolName === '__force_refresh__').length;
	return { result, forceRefreshUnits };
}

function resultText(result: unknown): string {
	return JSON.stringify(result);
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

describe('force_refresh quota gate vs strict schemas', () => {
	it('a call rejected for an undeclared force_refresh consumes no force-refresh unit', async () => {
		// explain_finding does not cache, so its schema does not declare force_refresh.
		const { result, forceRefreshUnits } = await executeWithQuotaSpy('explain_finding', {
			checkType: 'SPF',
			status: 'fail',
			force_refresh: true,
		});
		expect(forceRefreshUnits).toBe(0);
		expect(resultText(result)).toContain('Invalid request: unknown argument(s): force_refresh');
	});

	it('a tool that declares force_refresh is still metered (positive control)', async () => {
		const { mockTxtRecords } = await import('./helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const { result, forceRefreshUnits } = await executeWithQuotaSpy('check_spf', { domain: 'example.com', force_refresh: true });
		expect(resultText(result)).not.toContain('unknown argument');
		expect(forceRefreshUnits).toBe(1);
	});
});
