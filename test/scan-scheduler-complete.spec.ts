// test/scan-scheduler-complete.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 2 scheduler core (D) — markCompleted backoff/reset.
//   failure → increments consecutive_failures AND pushes next_scan_at out beyond
//             a normal cadence reschedule (exponential-ish backoff).
//   success → resets consecutive_failures to 0 and reschedules one cadence ahead.
//
// Written BEFORE the impl → FAILS until src/lib/scan-scheduler.ts lands.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { makeScanScheduleDb } from './helpers/scan-schedule-d1';

const NOW = 1_750_000_000_000;
const CADENCE = 60_000; // 1 min — small so backoff stays under any cap

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('markCompleted (D)', () => {
	it('failure increments consecutive_failures and pushes next_scan_at past one cadence (backoff)', async () => {
		const fake = makeScanScheduleDb([
			{ id: 1, domain: 'a.com', lane: 'daily', next_scan_at: NOW, cadence_ms: CADENCE, consecutive_failures: 0 },
		]);
		const { markCompleted } = await import('../src/lib/scan-scheduler');
		await markCompleted(fake.db, { id: 1, success: false, now: NOW, cadenceMs: CADENCE });

		const r = fake.rows[0];
		expect(r.consecutive_failures).toBe(1);
		expect(r.next_scan_at).toBeGreaterThan(NOW + CADENCE); // backoff exceeds a normal reschedule
	});

	it('repeated failures back off further each time', async () => {
		const fake = makeScanScheduleDb([
			{ id: 1, domain: 'a.com', lane: 'daily', next_scan_at: NOW, cadence_ms: CADENCE, consecutive_failures: 0 },
		]);
		const { markCompleted } = await import('../src/lib/scan-scheduler');
		await markCompleted(fake.db, { id: 1, success: false, now: NOW, cadenceMs: CADENCE });
		const afterFirst = fake.rows[0].next_scan_at;
		await markCompleted(fake.db, { id: 1, success: false, now: NOW, cadenceMs: CADENCE });
		expect(fake.rows[0].consecutive_failures).toBe(2);
		expect(fake.rows[0].next_scan_at).toBeGreaterThan(afterFirst);
	});

	it('success resets consecutive_failures to 0 and reschedules exactly one cadence ahead', async () => {
		const fake = makeScanScheduleDb([
			{ id: 1, domain: 'a.com', lane: 'daily', next_scan_at: NOW, cadence_ms: CADENCE, consecutive_failures: 3 },
		]);
		const { markCompleted } = await import('../src/lib/scan-scheduler');
		await markCompleted(fake.db, { id: 1, success: true, now: NOW, cadenceMs: CADENCE });

		const r = fake.rows[0];
		expect(r.consecutive_failures).toBe(0);
		expect(r.next_scan_at).toBe(NOW + CADENCE);
		expect(r.last_scanned_at).toBe(NOW);
	});
});
