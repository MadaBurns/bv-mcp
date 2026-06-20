// SPDX-License-Identifier: BUSL-1.1

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resetAllRateLimits, resetGlobalDailyLimit, resetConcurrencyLimits } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';
import { logEvent } from '../src/lib/log';
import type { ExecuteMcpRequestOptions } from '../src/mcp/execute';
import type { JsonRpcRequest } from '../src/lib/json-rpc';

/** Build a minimal valid ExecuteMcpRequestOptions for testing. */
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

/** Parse every console.log JSON line emitted during the test. */
function capturedLogEvents(spy: ReturnType<typeof vi.spyOn>): Array<Record<string, unknown>> {
	const events: Array<Record<string, unknown>> = [];
	for (const call of spy.mock.calls) {
		try {
			events.push(JSON.parse(String(call[0])) as Record<string, unknown>);
		} catch {
			// non-JSON console.log line — ignore
		}
	}
	return events;
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

describe('F2 — request correlation id', () => {
	it('round-trips through a LogEvent into the serialized log line', () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		logEvent({ timestamp: new Date().toISOString(), correlationId: 'corr-abc', category: 'test', result: 'ok' });
		const events = capturedLogEvents(consoleSpy);
		expect(events).toHaveLength(1);
		expect(events[0].correlationId).toBe('corr-abc');
	});

	it('stamps the threaded correlation id onto the dispatch log line for a request', async () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		const { executeMcpRequest } = await import('../src/mcp/execute');

		await executeMcpRequest(baseOptions({ correlationId: 'corr-fixed-1', userAgent: 'vitest' }));

		const events = capturedLogEvents(consoleSpy);
		const stamped = events.filter((e) => e.correlationId === 'corr-fixed-1');
		// At least the dispatch log line must carry the id.
		expect(stamped.length).toBeGreaterThanOrEqual(1);
		// Every log line emitted with a correlationId for this request must carry
		// THIS request's id — none should be missing/another id.
		const withCorr = events.filter((e) => typeof e.correlationId === 'string');
		for (const e of withCorr) {
			expect(e.correlationId).toBe('corr-fixed-1');
		}
	});

	it('keeps correlation ids distinct across two separate requests', async () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		const { executeMcpRequest } = await import('../src/mcp/execute');

		await executeMcpRequest(baseOptions({ correlationId: 'corr-A' }));
		await executeMcpRequest(baseOptions({ correlationId: 'corr-B' }));

		const events = capturedLogEvents(consoleSpy);
		const ids = new Set(events.filter((e) => typeof e.correlationId === 'string').map((e) => e.correlationId));
		expect(ids.has('corr-A')).toBe(true);
		expect(ids.has('corr-B')).toBe(true);
	});
});
