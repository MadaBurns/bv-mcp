// SPDX-License-Identifier: BUSL-1.1
//
// Chaos B (SQ-189): access-log D1 (INTELLIGENCE_DB) outage must never fail a
// tool call or the retention cron.
//
// Per testing-methodology principle 8, each `it` below is a falsifiable
// hypothesis of the form "Given <failure>, the system should <degradation>."
// A negative control is recorded above each hypothesis: the specific
// production guard that, if removed, turns that test red. Per this ticket's
// verify-discipline these are NOT executed as a revert-and-rerun step; they
// name the exact code path whose removal falsifies the hypothesis, so a
// reviewer (or a future edit) can check the claim against src/ directly.
//
// Existing coverage checked first (grepped test/ before writing this file):
//   - test/mcp-access-log.spec.ts covers fireAndForget's catch behavior in
//     isolation (a bare Promise.reject) and the inline-insert/queue-routing
//     split, but never makes a real D1 call reject through the full
//     recordMcpAccessLog -> executeMcpRequest path, and never asserts the
//     *response* still succeeds when it does. Not a duplicate of H1/H2.
//   - test/scheduled.spec.ts's "does NOT alert on an unrelated D1 error"
//     covers checkAccessRollupProvisioned swallowing a non-"no such table"
//     error in isolation, but never combines it with a failing retention
//     DELETE, never asserts handleScheduled *resolves*, and never asserts
//     sibling per-tick work still runs. Not a duplicate of H3.
//   - No existing coverage for H4 (an outaged INTELLIGENCE_DB reaching
//     /internal/analytics/*) beyond the happy-path specs in
//     test/internal-analytics-{usage,forensics,erase}.spec.ts.
//
// Mocks are at the boundary only: a D1Database-shaped stub (prepare/bind/run/
// first/all) and globalThis.fetch (DNS). Everything else — real dispatch,
// real check_spf, real route handlers — runs for real.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setupFetchMock, mockTxtRecords } from '../helpers/dns-mock';
import { resetAllRateLimits, resetConcurrencyLimits, resetGlobalDailyLimit } from '../../src/lib/rate-limiter';
import { resetSessions } from '../../src/lib/session';
import type { JsonRpcRequest } from '../../src/lib/json-rpc';
import type { ScheduledEnv } from '../../src/scheduled';

const { restore } = setupFetchMock();

beforeEach(() => {
	resetAllRateLimits();
	resetGlobalDailyLimit();
	resetConcurrencyLimits();
	resetSessions();
});

afterEach(() => {
	restore();
	vi.restoreAllMocks();
});

/** D1 stub whose every prepare()/bind()/run()/first()/all() rejects — models an unreachable or locked INTELLIGENCE_DB. */
function createOutageD1(message = 'D1_ERROR: database is locked: SQLITE_BUSY') {
	const stmt = {
		bind: () => stmt,
		run: async () => {
			throw new Error(message);
		},
		first: async () => {
			throw new Error(message);
		},
		all: async () => {
			throw new Error(message);
		},
	};
	const prepare = vi.fn(() => stmt);
	return { db: { prepare } as unknown as D1Database, prepare };
}

/** D1 stub whose every write succeeds — used as the "sibling" binding a D1 outage must not block. */
function createHealthyD1() {
	const run = vi.fn(async () => ({ success: true }) as unknown as D1Response);
	const bind = vi.fn(() => ({ run }));
	const prepare = vi.fn((sql: string) => ({ bind, sql }));
	return { db: { prepare } as unknown as D1Database, prepare, bind, run };
}

/** Drains every promise handed to a captured `waitUntil` mock (fire-and-forget tails). */
async function drain(waitUntil: ReturnType<typeof vi.fn>): Promise<void> {
	await Promise.allSettled(waitUntil.mock.calls.map((c) => c[0] as Promise<unknown>));
}

describe('Chaos B: access-log D1 (INTELLIGENCE_DB) outage', () => {
	describe('H1 — tools/call survives a rejecting INTELLIGENCE_DB', () => {
		/**
		 * Negative control: guarded by `fireAndForget()` (src/lib/log.ts)
		 * wrapping the inline insert's `work()` promise in `recordMcpAccessLog`
		 * (src/mcp/execute.ts) before it is handed to `options.waitUntil?.(...)`.
		 * If `work()` were `await`ed directly before the tool result is returned
		 * instead of being fired-and-forgotten, this test's `payload.result`
		 * assertion would fail — the whole request would reject instead of
		 * responding.
		 */
		it('Given INTELLIGENCE_DB.prepare().bind().run() rejects on every call, tools/call for check_spf still returns the tool result (not a thrown error), and the failure is logged, not thrown', async () => {
			mockTxtRecords(['v=spf1 -all']);
			const { executeMcpRequest } = await import('../../src/mcp/execute');
			const outage = createOutageD1();
			const waitUntil = vi.fn();
			const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);

			const result = await executeMcpRequest({
				body: {
					jsonrpc: '2.0',
					id: 1,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				allowStreaming: false,
				batchMode: false,
				batchSize: 1,
				responseTransport: 'json',
				startTime: Date.now(),
				ip: '203.0.113.30',
				ipHash: 'i_testhash1',
				isAuthenticated: true,
				validateSession: false,
				serverVersion: 'test',
				intelligenceDb: outage.db,
				waitUntil,
				country: 'NZ',
				userAgent: 'test-agent',
			});

			if (result.kind !== 'response') throw new Error(`expected a response, got ${result.kind}`);
			const payload = result.payload as { result?: unknown; error?: unknown };
			expect(payload.result).toBeDefined();
			expect(payload.error).toBeUndefined();

			// Prove the outaged DB was actually exercised (not skipped) and that the
			// rejection surfaced as a structured warn log, never an unhandled throw.
			await drain(waitUntil);
			expect(outage.prepare).toHaveBeenCalled();
			expect(
				consoleSpy.mock.calls.some((call) => {
					try {
						const parsed = JSON.parse(String(call[0]));
						return parsed.result === 'Fire-and-forget operation failed' && parsed.details?.operation === 'mcp_access_log_insert';
					} catch {
						return false;
					}
				}),
			).toBe(true);
		});
	});

	describe('H2 — tools/call with INTELLIGENCE_DB absent (BSL self-host)', () => {
		/**
		 * Negative control: guarded by the early return
		 * `if (!options.intelligenceDb && !options.analyticsQueue) return;` at
		 * the top of `recordMcpAccessLog` (src/mcp/execute.ts). Deleting that
		 * guard would make the inline-insert branch run
		 * `options.intelligenceDb!.prepare(...)` against `undefined`, throwing
		 * synchronously inside `work()` and (depending on how the throw is
		 * handled) either failing the request or firing a spurious waitUntil —
		 * either way, the "waitUntil never called" assertion below would fail.
		 */
		it('Given the INTELLIGENCE_DB binding is absent and no analyticsQueue is bound, tools/call for check_spf still succeeds and no access-log write is attempted', async () => {
			mockTxtRecords(['v=spf1 -all']);
			const { executeMcpRequest } = await import('../../src/mcp/execute');
			const waitUntil = vi.fn();

			const result = await executeMcpRequest({
				body: {
					jsonrpc: '2.0',
					id: 2,
					method: 'tools/call',
					params: { name: 'check_spf', arguments: { domain: 'example.com' } },
				} as JsonRpcRequest,
				allowStreaming: false,
				batchMode: false,
				batchSize: 1,
				responseTransport: 'json',
				startTime: Date.now(),
				ip: '203.0.113.31',
				ipHash: 'i_testhash2',
				isAuthenticated: true,
				validateSession: false,
				serverVersion: 'test',
				// intelligenceDb and analyticsQueue both omitted — models the absent binding.
				waitUntil,
				country: 'NZ',
				userAgent: 'test-agent',
			});

			if (result.kind !== 'response') throw new Error(`expected a response, got ${result.kind}`);
			const payload = result.payload as { result?: unknown; error?: unknown };
			expect(payload.result).toBeDefined();
			expect(payload.error).toBeUndefined();

			await drain(waitUntil);
			expect(waitUntil).not.toHaveBeenCalled();
		});
	});

	describe('H3 — the 15-min retention cron survives a rejecting INTELLIGENCE_DB', () => {
		/**
		 * Negative control: guarded by the `.catch(...)` on the retention DELETE
		 * chain and by `checkAccessRollupProvisioned`'s own try/catch (both in
		 * src/scheduled.ts). Removing either `.catch`/try-catch — letting the
		 * rejection propagate out of `handleScheduled` — would make the
		 * `resolves` assertion below reject instead, and the SCAN_SCHEDULE_DB
		 * sibling assertion would never even run (a rejected handleScheduled
		 * aborts the awaiting test before it gets there).
		 */
		it('Given INTELLIGENCE_DB throws on the retention DELETE and the rollup-missing SELECT, handleScheduled resolves and the sibling SCAN_SCHEDULE_DB prune still runs', async () => {
			const { handleScheduled } = await import('../../src/scheduled');
			const outage = createOutageD1();
			const sibling = createHealthyD1();

			const env = {
				INTELLIGENCE_DB: outage.db,
				SCAN_SCHEDULE_DB: sibling.db,
				ALERT_WEBHOOK_URL: 'https://hooks.example.com/test',
			} as unknown as ScheduledEnv;

			await expect(handleScheduled(env)).resolves.toBeUndefined();

			// Both D1 call sites named in the ticket were actually exercised, not skipped.
			expect(outage.prepare).toHaveBeenCalledWith(expect.stringContaining('DELETE FROM mcp_access_log'));
			expect(outage.prepare).toHaveBeenCalledWith(expect.stringContaining('FROM mcp_access_rollup'));
			// Sibling periodic work in the same tick still ran.
			expect(sibling.prepare).toHaveBeenCalledWith(expect.stringContaining('DELETE FROM scan_rollup'));
		});
	});

	describe('H4 — /internal/analytics/* routes survive a rejecting INTELLIGENCE_DB', () => {
		/**
		 * Negative control (all three below): guarded by the route's own
		 * try/catch around the D1 call in src/internal.ts, which returns a fixed
		 * `{ error, detail }` JSON body at a 5xx status. Removing a catch would
		 * let the rejection escape as an unhandled Worker exception instead — no
		 * `{ error: 'Usage query failed' | 'Forensics query failed' | 'Erase
		 * failed' }` body would ever be produced, so the exact-string assertions
		 * below would fail.
		 */
		it('Given INTELLIGENCE_DB throws, GET /internal/analytics/usage returns a structured 5xx JSON error with no stack trace', async () => {
			const { internalRoutes } = await import('../../src/internal');
			const outage = createOutageD1();
			const env = { REQUIRE_INTERNAL_AUTH: 'false', INTELLIGENCE_DB: outage.db };

			const res = await internalRoutes.request('/analytics/usage?days=7', {}, env);

			expect(res.status).toBeGreaterThanOrEqual(500);
			expect(res.status).toBeLessThan(600);
			const body = (await res.json()) as Record<string, unknown>;
			expect(body).toEqual({ error: 'Usage query failed', detail: expect.any(String) });
			expect(JSON.stringify(body)).not.toMatch(/at .*\.ts:\d+/);
			expect(outage.prepare).toHaveBeenCalled();
		});

		it('Given INTELLIGENCE_DB throws, GET /internal/analytics/forensics (strict bearer) returns a structured 5xx JSON error with no stack trace', async () => {
			const { internalRoutes } = await import('../../src/internal');
			const outage = createOutageD1();
			const env = { BV_WEB_INTERNAL_KEY: 'right', INTELLIGENCE_DB: outage.db };

			const res = await internalRoutes.request('/analytics/forensics?days=1', { headers: { authorization: 'Bearer right' } }, env);

			expect(res.status).toBeGreaterThanOrEqual(500);
			expect(res.status).toBeLessThan(600);
			const body = (await res.json()) as Record<string, unknown>;
			expect(body).toEqual({ error: 'Forensics query failed', detail: expect.any(String) });
			expect(JSON.stringify(body)).not.toMatch(/at .*\.ts:\d+/);
			expect(outage.prepare).toHaveBeenCalled();
		});

		it('Given INTELLIGENCE_DB throws, POST /internal/analytics/erase (strict bearer) returns a structured 5xx JSON error with no stack trace', async () => {
			const { internalRoutes } = await import('../../src/internal');
			const outage = createOutageD1();
			const env = { BV_WEB_INTERNAL_KEY: 'right', INTELLIGENCE_DB: outage.db };

			const res = await internalRoutes.request(
				'/analytics/erase?key_hash=abc123',
				{ method: 'POST', headers: { authorization: 'Bearer right' } },
				env,
			);

			expect(res.status).toBeGreaterThanOrEqual(500);
			expect(res.status).toBeLessThan(600);
			const body = (await res.json()) as Record<string, unknown>;
			expect(body).toEqual({ error: 'Erase failed', detail: expect.any(String) });
			expect(JSON.stringify(body)).not.toMatch(/at .*\.ts:\d+/);
			expect(outage.prepare).toHaveBeenCalled();
		});
	});
});
