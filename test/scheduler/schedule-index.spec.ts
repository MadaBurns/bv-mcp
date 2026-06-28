// test/scheduler/schedule-index.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 2 scheduler core — claim/advance correctness (dark-path internals).
// Regression coverage for three coupled claim/advance findings:
//
//   C1 (jitter collapse): claimDue must advance next_scan_at PER ROW inside the
//      SQL SET clause (now + cadence_ms + per-row random jitter), so a cohort
//      claimed together does NOT converge onto a single timestamp after cycle 1.
//   C2 (per-row cadence ignored): the advance must use each row's OWN cadence_ms
//      column, not a lane-default scalar — a custom-cadence domain re-schedules
//      at its own cadence.
//   C3 (upsert no reset): upsertSchedule's ON CONFLICT must also reset
//      next_scan_at into a fresh jittered slot and zero consecutive_failures, so
//      a re-activated domain isn't instantly due nor carrying a stale backoff.
//
// Dynamic import inside each test fn for mock isolation (workers pool).

import { afterEach, describe, expect, it, vi } from 'vitest';
import { makeScanScheduleDb } from '../helpers/scan-schedule-d1';

const NOW = 1_750_000_000_000;
const CADENCE = 86_400_000; // 1 day
const SIX_HOURS = 6 * 60 * 60 * 1000; // a "lane default" the advance must NOT use

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('claimDue — per-row advance (C1 jitter collapse)', () => {
	it('advances inside the SQL SET clause per row (cadence_ms + abs(random())), not via a precomputed scalar bind', async () => {
		const fake = makeScanScheduleDb([{ id: 1, domain: 'a.com', lane: 'daily', next_scan_at: NOW - 1, cadence_ms: CADENCE }]);
		const { claimDue } = await import('../../src/scheduler/schedule-index');
		await claimDue(fake.db, { lane: 'daily', now: NOW, limit: 10 });

		const sql = fake.calls[0].sql.replace(/\s+/g, ' ').trim();
		// The advance is expressed in SQL against the row's own column + random().
		expect(sql).toContain('SET next_scan_at = ? + cadence_ms + (abs(random()) % (cadence_ms / 10 + 1))');
		// The first SET bind is the raw `now` base — NOT a single precomputed
		// next_scan_at that every row would share (the C1 collapse).
		expect(fake.calls[0].binds[0]).toBe(NOW);
	});

	it('gives every claimed row a DISTINCT next_scan_at (no convergence onto one tick)', async () => {
		const seeds = Array.from({ length: 8 }, (_, i) => ({
			id: i + 1,
			domain: `d${i}.com`,
			lane: 'daily',
			next_scan_at: NOW - (i + 1),
			cadence_ms: CADENCE,
		}));
		const fake = makeScanScheduleDb(seeds);
		const { claimDue } = await import('../../src/scheduler/schedule-index');

		const claimed = await claimDue(fake.db, { lane: 'daily', now: NOW, limit: 8 });
		expect(claimed).toHaveLength(8);

		const nexts = fake.rows.map((r) => r.next_scan_at);
		// Spread, not a single shared value.
		expect(new Set(nexts).size).toBeGreaterThan(1);
		// Each still pushed at least a full cadence ahead (overlap/dedup safety).
		for (const n of nexts) expect(n).toBeGreaterThanOrEqual(NOW + CADENCE);
	});
});

describe('claimDue — honors the row cadence_ms (C2 per-row cadence)', () => {
	it('advances by the ROW cadence_ms, not a lane-default scalar', async () => {
		const customCadence = 5_000; // 5s — far below any plausible lane default
		const fake = makeScanScheduleDb([{ id: 1, domain: 'custom.com', lane: 'fast', next_scan_at: NOW - 1, cadence_ms: customCadence }]);
		const { claimDue } = await import('../../src/scheduler/schedule-index');

		// Note: no cadenceMs arg — the advance reads the row column, not the caller.
		await claimDue(fake.db, { lane: 'fast', now: NOW, limit: 10 });

		const next = fake.rows[0].next_scan_at;
		const maxJitter = Math.floor(customCadence / 10) + 1;
		expect(next).toBeGreaterThanOrEqual(NOW + customCadence);
		expect(next).toBeLessThan(NOW + customCadence + maxJitter);
		// Crucially it did NOT advance by a 6h lane default.
		expect(next).toBeLessThan(NOW + SIX_HOURS);
	});
});

describe('upsertSchedule — ON CONFLICT resets slot + backoff (C3)', () => {
	it('re-upserting an existing row resets next_scan_at into a fresh slot and zeroes consecutive_failures', async () => {
		const fake = makeScanScheduleDb([
			{
				id: 1,
				tenant_id: 'tenant_a',
				domain: 'reactivate.com',
				lane: 'daily',
				next_scan_at: NOW + 999 * CADENCE, // inflated stale backoff
				cadence_ms: CADENCE,
				consecutive_failures: 9,
			},
		]);
		const { upsertSchedule } = await import('../../src/scheduler/schedule-index');

		await upsertSchedule(fake.db, { tenantId: 'tenant_a', domain: 'reactivate.com', lane: 'daily', cadenceMs: CADENCE, now: NOW });

		const r = fake.rows[0];
		expect(r.consecutive_failures).toBe(0);
		// Re-scheduled into the [now, now + cadence) jittered window — not instantly
		// due and not carrying the stale multi-day backoff.
		expect(r.next_scan_at).toBeGreaterThanOrEqual(NOW);
		expect(r.next_scan_at).toBeLessThan(NOW + CADENCE);
	});

	it('emits the reset clauses in the ON CONFLICT UPDATE', async () => {
		const fake = makeScanScheduleDb();
		const { upsertSchedule } = await import('../../src/scheduler/schedule-index');
		await upsertSchedule(fake.db, { tenantId: 'tenant_a', domain: 'x.com', lane: 'daily', cadenceMs: CADENCE, now: NOW });

		const sql = fake.calls[0].sql.replace(/\s+/g, ' ').trim();
		expect(sql).toContain('next_scan_at = excluded.next_scan_at');
		expect(sql).toContain('consecutive_failures = 0');
	});
});
