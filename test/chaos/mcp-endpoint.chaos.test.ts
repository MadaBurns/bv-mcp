// SPDX-License-Identifier: BUSL-1.1
//
// Chaos: /mcp Streamable-HTTP endpoint resilience.
//
// Hypotheses under test:
//
//  H1 — Telemetry-failure isolation. The Analytics Engine binding is best-
//       effort: every emit path runs through `safeWrite()` (lib/analytics.ts).
//       If the dataset throws on every `writeDataPoint`, the endpoint MUST
//       still serve a valid JSON-RPC response. A 500 here would mean a
//       degraded telemetry path is taking down request handling.
//
//  H2 — JSON-RPC batch isolation. A single malformed entry in a batch must
//       produce its own error response without poisoning sibling entries.
//       The batch path in `index.ts` returns 200 with a per-entry payload
//       array; a regression here would surface as a 400 short-circuit.

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../../src/index';
import { resetSessions } from '../../src/lib/session';
import { resetAllRateLimits } from '../../src/lib/rate-limiter';
import { resetQuotaCoordinatorState } from '../../src/lib/quota-coordinator';

type TestEnv = typeof env & { MCP_ANALYTICS?: unknown };

const ORIGINAL_ANALYTICS = (env as TestEnv).MCP_ANALYTICS;

beforeEach(async () => {
	resetAllRateLimits();
	resetQuotaCoordinatorState();
	resetSessions();
	(env as TestEnv).MCP_ANALYTICS = ORIGINAL_ANALYTICS;
});

afterEach(() => {
	(env as TestEnv).MCP_ANALYTICS = ORIGINAL_ANALYTICS;
});

function postMcp(body: unknown): Request<unknown, IncomingRequestCfProperties> {
	return new Request<unknown, IncomingRequestCfProperties>('http://example.com/mcp', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
		body: JSON.stringify(body),
	});
}

describe('chaos: /mcp endpoint resilience', () => {
	it('H1: analytics dataset throwing on every writeDataPoint does not break initialize', async () => {
		let writeAttempts = 0;
		(env as TestEnv).MCP_ANALYTICS = {
			writeDataPoint(): void {
				writeAttempts += 1;
				throw new Error('analytics dataset down');
			},
		};

		const ctx = createExecutionContext();
		const res = await worker.fetch(
			postMcp({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
			env,
			ctx,
		);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(200);
		expect(res.headers.get('mcp-session-id')).toMatch(/^[a-f0-9]{64}$/);
		const body = (await res.json()) as { jsonrpc: string; id: number; result?: unknown; error?: unknown };
		expect(body.jsonrpc).toBe('2.0');
		expect(body.id).toBe(1);
		expect(body.result).toBeDefined();
		expect(body.error).toBeUndefined();
		// Proves the throwing emit path was actually exercised (request + session emits).
		expect(writeAttempts).toBeGreaterThan(0);
	});

	it('H2: batch with one non-object entry returns per-entry error without blocking the valid entry', async () => {
		const ctx = createExecutionContext();
		const res = await worker.fetch(
			postMcp([
				null,
				{ jsonrpc: '2.0', id: 'init', method: 'initialize', params: {} },
			]),
			env,
			ctx,
		);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(200);
		const payloads = (await res.json()) as Array<{ id: unknown; result?: unknown; error?: { code: number; message: string } }>;
		expect(Array.isArray(payloads)).toBe(true);
		expect(payloads).toHaveLength(2);

		const malformed = payloads.find((p) => p.id === null);
		expect(malformed?.error).toBeDefined();
		expect(malformed?.error?.code).toBe(-32600); // JSON-RPC INVALID_REQUEST

		const initialize = payloads.find((p) => p.id === 'init');
		expect(initialize?.result).toBeDefined();
		expect(initialize?.error).toBeUndefined();
	});
});
