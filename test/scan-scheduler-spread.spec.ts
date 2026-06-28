// test/scan-scheduler-spread.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 2 scheduler core (B + C) — anti-clumping.
//   B) upsertSchedule: two domains upserted at the SAME instant get DIFFERENT
//      next_scan_at via a deterministic per-domain seed (jitter), so a bulk
//      onboarding does not stack every domain on one tick.
//   C) reSpreadOnCadenceChange: re-spreads next_scan_at across the NEW cadence
//      window using SQLite random() (NOT rand()); distribution, not all-equal.
//
// Written BEFORE the impl → FAILS until src/lib/scan-scheduler.ts lands.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { makeScanScheduleDb } from './helpers/scan-schedule-d1';

const NOW = 1_750_000_000_000;
const CADENCE = 86_400_000; // 1 day

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('upsertSchedule (B) — per-domain jitter, no clumping', () => {
	it('two domains upserted at the same instant get DIFFERENT next_scan_at', async () => {
		const fake = makeScanScheduleDb();
		const { upsertSchedule } = await import('../src/lib/scan-scheduler');

		await upsertSchedule(fake.db, { tenantId: 'tenant_a', domain: 'one.com', lane: 'daily', cadenceMs: CADENCE, now: NOW });
		await upsertSchedule(fake.db, { tenantId: 'tenant_a', domain: 'two.com', lane: 'daily', cadenceMs: CADENCE, now: NOW });

		const one = fake.rows.find((r) => r.domain === 'one.com')!;
		const two = fake.rows.find((r) => r.domain === 'two.com')!;
		expect(one.next_scan_at).not.toBe(two.next_scan_at);
		// Jitter stays within one cadence window of the same base instant.
		for (const r of [one, two]) {
			expect(r.next_scan_at).toBeGreaterThanOrEqual(NOW);
			expect(r.next_scan_at).toBeLessThan(NOW + CADENCE);
		}
	});

	it('the per-domain seed is deterministic (same domain → same slot)', async () => {
		const { upsertSchedule } = await import('../src/lib/scan-scheduler');
		const a = makeScanScheduleDb();
		const b = makeScanScheduleDb();
		await upsertSchedule(a.db, { tenantId: 'tenant_a', domain: 'stable.com', lane: 'daily', cadenceMs: CADENCE, now: NOW });
		await upsertSchedule(b.db, { tenantId: 'tenant_a', domain: 'stable.com', lane: 'daily', cadenceMs: CADENCE, now: NOW });
		expect(a.rows[0].next_scan_at).toBe(b.rows[0].next_scan_at);
	});
});

describe('reSpreadOnCadenceChange (C) — spreads across the new window', () => {
	it('uses SQLite random() (NOT rand()) in the UPDATE', async () => {
		const fake = makeScanScheduleDb([{ id: 1, domain: 'a.com', lane: 'daily', next_scan_at: NOW }]);
		const { reSpreadOnCadenceChange } = await import('../src/lib/scan-scheduler');
		await reSpreadOnCadenceChange(fake.db, { lane: 'daily', now: NOW, cadenceMs: CADENCE });

		const sql = fake.calls[0].sql;
		expect(sql).toContain('random()');
		expect(sql).not.toContain('rand()'); // MySQL-ism; SQLite has no rand()
	});

	it('distributes next_scan_at across the window (not all-equal)', async () => {
		const seeds = Array.from({ length: 20 }, (_, i) => ({ id: i + 1, domain: `d${i}.com`, lane: 'daily', next_scan_at: NOW }));
		const fake = makeScanScheduleDb(seeds);
		const { reSpreadOnCadenceChange } = await import('../src/lib/scan-scheduler');
		await reSpreadOnCadenceChange(fake.db, { lane: 'daily', now: NOW, cadenceMs: CADENCE });

		const distinct = new Set(fake.rows.map((r) => r.next_scan_at));
		expect(distinct.size).toBeGreaterThan(1); // spread, not clumped on one value
		for (const r of fake.rows) {
			expect(r.next_scan_at).toBeGreaterThanOrEqual(NOW);
			expect(r.next_scan_at).toBeLessThan(NOW + CADENCE);
		}
	});
});
