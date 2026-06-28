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
