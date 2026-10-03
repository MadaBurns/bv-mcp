// test/scheduler/dispatch.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 2 dark-wired dispatcher — C2 (per-row cadence) end-to-end.
//
// dispatchDueScans must NOT pass a lane-default cadence scalar into claimDue; the
// advance reads each row's OWN cadence_ms column. This exercises the full
// flag-on dispatch → claim path and asserts a custom-cadence row re-schedules at
// its own cadence, not the 6h fast-lane default that the dispatcher used to pass.
//
// Dynamic import inside the test fn for mock isolation (workers pool).

import { afterEach, describe, expect, it, vi } from 'vitest';
import { makeScanScheduleDb, makeSlowQueue } from '../helpers/scan-schedule-d1';

const NOW = 1_750_000_000_000;
const SIX_HOURS = 6 * 60 * 60 * 1000; // the old fast-lane default scalar

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('dispatchDueScans (C2) — advances by the row cadence, not the lane default', () => {
	it('a custom-cadence fast-lane row re-schedules at its own cadence_ms', async () => {
		const customCadence = 5_000; // 5s — far below the 6h fast-lane default
		const fake = makeScanScheduleDb([
			{ id: 1, tenant_id: 'tenant_a', domain: 'fast.com', lane: 'fast', next_scan_at: NOW - 1, cadence_ms: customCadence },
		]);
		const { queue, send, sent } = makeSlowQueue();
		const env = {
			SCAN_DISPATCH_ENABLED: 'true',
			SCAN_DISPATCH_BATCH_SIZE: '50',
			SCAN_SCHEDULE_DB: fake.db,
			BV_SCANNER_QUEUE: queue,
		} as unknown as import('../../src/scheduler/dispatch').ScanDispatchEnv;

		const { dispatchDueScans } = await import('../../src/scheduler/dispatch');
		await dispatchDueScans(env, { now: NOW });

		// It claimed + enqueued the due row.
		expect(send).toHaveBeenCalledTimes(1);
		expect((sent[0].message as { domain: string }).domain).toBe('fast.com');

		// And advanced it by its OWN cadence, not the 6h lane default.
		const next = fake.rows[0].next_scan_at;
		const maxJitter = Math.floor(customCadence / 10) + 1;
		expect(next).toBeGreaterThanOrEqual(NOW + customCadence);
		expect(next).toBeLessThan(NOW + customCadence + maxJitter);
		expect(next).toBeLessThan(NOW + SIX_HOURS);
	});
});

/**
 * logError → logEvent → console.log(JSON.stringify({...})). Mirrors the
 * repo's existing console-spy pattern (see test/kv-fallback-logging.spec.ts).
 */
function getStructuredLogs(spy: ReturnType<typeof vi.fn>): Record<string, unknown>[] {
	const logs: Record<string, unknown>[] = [];
	for (const call of spy.mock.calls) {
		const arg = call[0];
		if (typeof arg === 'string') {
			try {
				logs.push(JSON.parse(arg) as Record<string, unknown>);
			} catch {
				// not JSON, skip
			}
		}
	}
	return logs;
}

describe('dispatchDueScans — resolves the lane queue before claiming', () => {
	it('an unbound lane queue is skipped WITHOUT claiming (no unclaimed send loss)', async () => {
		// Both lanes have a due row, but neither BV_SCANNER_QUEUE nor
		// BV_SCANNER_SLOW_QUEUE is bound — the fast lane falls back to the slow
		// queue and vice versa (resolveLaneQueue), so with BOTH absent every
		// lane must be skipped before claimDue ever runs.
		const fake = makeScanScheduleDb([
			{ id: 1, tenant_id: 'tenant_a', domain: 'fast.com', lane: 'fast', next_scan_at: NOW - 1 },
			{ id: 2, tenant_id: 'tenant_a', domain: 'slow.com', lane: 'slow', next_scan_at: NOW - 1 },
		]);
		const consoleSpy = vi.spyOn(console, 'log');
		const env = {
			SCAN_DISPATCH_ENABLED: 'true',
			SCAN_DISPATCH_BATCH_SIZE: '50',
			SCAN_SCHEDULE_DB: fake.db,
			// No BV_SCANNER_QUEUE / BV_SCANNER_SLOW_QUEUE bound.
		} as unknown as import('../../src/scheduler/dispatch').ScanDispatchEnv;

		const { dispatchDueScans, SCAN_LANES } = await import('../../src/scheduler/dispatch');
		await dispatchDueScans(env, { now: NOW });

		// The rows were never claimed — no prepare() call at all — so the
		// schedule is untouched and nothing was silently consumed.
		expect(fake.prepare).not.toHaveBeenCalled();
		expect(fake.rows[0].next_scan_at).toBe(NOW - 1);
		expect(fake.rows[1].next_scan_at).toBe(NOW - 1);

		const logs = getStructuredLogs(consoleSpy);
		const skipLogs = logs.filter((l) => l.result === 'queue unbound — lane not dispatched');
		expect(skipLogs.length).toBe(SCAN_LANES.length);
	});
});

describe('dispatchDueScans — a mid-loop send failure is logged, other lanes still run', () => {
	it('send throws on row 2 of the fast lane: error logged with claimed/sent counts, slow lane still dispatches', async () => {
		const fake = makeScanScheduleDb([
			{ id: 1, tenant_id: 'tenant_a', domain: 'fast-1.com', lane: 'fast', next_scan_at: NOW - 1 },
			{ id: 2, tenant_id: 'tenant_a', domain: 'fast-2.com', lane: 'fast', next_scan_at: NOW - 1 },
			{ id: 3, tenant_id: 'tenant_a', domain: 'slow-1.com', lane: 'slow', next_scan_at: NOW - 1 },
		]);
		const consoleSpy = vi.spyOn(console, 'log');

		let fastCall = 0;
		const fastSend = vi.fn(async () => {
			fastCall += 1;
			if (fastCall === 2) throw new Error('queue send failed');
		});
		const { queue: slowQueue, send: slowSend } = makeSlowQueue();

		const env = {
			SCAN_DISPATCH_ENABLED: 'true',
			SCAN_DISPATCH_BATCH_SIZE: '50',
			SCAN_SCHEDULE_DB: fake.db,
			BV_SCANNER_QUEUE: { send: fastSend },
			BV_SCANNER_SLOW_QUEUE: slowQueue,
		} as unknown as import('../../src/scheduler/dispatch').ScanDispatchEnv;

		const { dispatchDueScans } = await import('../../src/scheduler/dispatch');
		await dispatchDueScans(env, { now: NOW });

		// Never rethrows — the call above resolved.
		expect(fastSend).toHaveBeenCalledTimes(2);

		const logs = getStructuredLogs(consoleSpy);
		const errorLogs = logs.filter((l) => l.severity === 'error');
		expect(errorLogs.length).toBe(1);
		const details = errorLogs[0].details as { lane: string; claimed: number; sent: number };
		expect(details.lane).toBe('fast');
		expect(details.claimed).toBe(2);
		expect(details.sent).toBe(1); // row 1 sent before row 2 threw

		// The slow lane is a separate try/catch iteration — it still ran.
		expect(slowSend).toHaveBeenCalledTimes(1);
	});
});
