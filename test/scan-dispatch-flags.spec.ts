// test/scan-dispatch-flags.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 2 scheduler core (F) — dispatchDueScans flag/binding gating (ship DARK).
//   With SCAN_SCHEDULE_DB ABSENT, OR isScanDispatchEnabled(env) false,
//   dispatchDueScans is a NO-OP: no claim (db.prepare never called) and no enqueue
//   (slow-queue send never called). Only with the flag === 'true' AND both
//   bindings present does it claim + fan onto BV_SCANNER_SLOW_QUEUE.
//   Gating reuses the existing readers in src/lib/scaling-flags.ts.
//
// Written BEFORE the impl → FAILS until src/lib/scan-scheduler.ts lands.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { makeScanScheduleDb, makeSlowQueue } from './helpers/scan-schedule-d1';

const NOW = 1_750_000_000_000;

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('dispatchDueScans (F) — DARK by default', () => {
	it('no-op when SCAN_SCHEDULE_DB is absent (flag on)', async () => {
		const { queue, send } = makeSlowQueue();
		const env = {
			SCAN_DISPATCH_ENABLED: 'true',
			BV_SCANNER_SLOW_QUEUE: queue,
		} as unknown as import('../src/lib/scan-scheduler').ScanDispatchEnv;
		const { dispatchDueScans } = await import('../src/lib/scan-scheduler');
		await dispatchDueScans(env, { now: NOW });
		expect(send).not.toHaveBeenCalled();
	});

	it('no-op when isScanDispatchEnabled is false (db + queue present)', async () => {
		const fake = makeScanScheduleDb([{ id: 1, domain: 'a.com', lane: 'daily', next_scan_at: NOW - 1 }]);
		const { queue, send } = makeSlowQueue();
		const env = {
			// SCAN_DISPATCH_ENABLED intentionally unset → disabled
			SCAN_SCHEDULE_DB: fake.db,
			BV_SCANNER_SLOW_QUEUE: queue,
		} as unknown as import('../src/lib/scan-scheduler').ScanDispatchEnv;
		const { dispatchDueScans } = await import('../src/lib/scan-scheduler');
		await dispatchDueScans(env, { now: NOW });

		expect(fake.prepare).not.toHaveBeenCalled(); // no claim issued
		expect(send).not.toHaveBeenCalled(); // nothing enqueued
	});

	it('flag on + both bindings present → claims due rows and enqueues each onto the slow lane', async () => {
		const { SCAN_LANES, dispatchDueScans } = await import('../src/lib/scan-scheduler');
		// One due row per configured lane so the claim returns something regardless of lane names.
		const seeds = SCAN_LANES.map((lane, i) => ({ id: i + 1, domain: `${lane}.com`, lane, next_scan_at: NOW - 1 }));
		const fake = makeScanScheduleDb(seeds);
		const { queue, send, sent } = makeSlowQueue();
		const env = {
			SCAN_DISPATCH_ENABLED: 'true',
			SCAN_DISPATCH_BATCH_SIZE: '50',
			SCAN_SCHEDULE_DB: fake.db,
			BV_SCANNER_SLOW_QUEUE: queue,
		} as unknown as import('../src/lib/scan-scheduler').ScanDispatchEnv;

		await dispatchDueScans(env, { now: NOW });

		expect(send).toHaveBeenCalledTimes(SCAN_LANES.length);
		const domains = sent.map((s) => (s.message as { domain: string }).domain);
		expect(domains).toEqual(expect.arrayContaining(SCAN_LANES.map((lane) => `${lane}.com`)));
	});
});
