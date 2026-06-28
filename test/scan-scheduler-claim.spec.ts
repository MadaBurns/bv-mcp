// test/scan-scheduler-claim.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 2 scheduler core (A) — claimDue claim-and-advance.
//
// GATE 4 (verified on local D1 = prod workerd SQLite): D1 REJECTS
// 'UPDATE … ORDER BY … LIMIT N RETURNING …'. The claim MUST use the Form-B
// subquery, atomic within the single statement:
//
//   UPDATE scan_schedule SET next_scan_at = ?, last_dispatched_at = ?
//   WHERE id IN (SELECT id FROM scan_schedule WHERE active=1 AND lane=? AND next_scan_at<=? ORDER BY next_scan_at LIMIT ?)
//   RETURNING id, tenant_id, domain, lane;
//
// Written BEFORE the impl (src/lib/scan-scheduler.ts does not exist yet) → FAILS
// until claimDue lands. Dynamic import inside the test fn for mock isolation.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { makeScanScheduleDb } from './helpers/scan-schedule-d1';

const NOW = 1_750_000_000_000;
const CADENCE = 86_400_000; // 1 day

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('claimDue (A)', () => {
	it('uses the GATE-4 Form-B subquery shape (no LIMIT+RETURNING together)', async () => {
		const fake = makeScanScheduleDb([{ id: 1, domain: 'a.com', lane: 'daily', next_scan_at: NOW - 1 }]);
		const { claimDue } = await import('../src/lib/scan-scheduler');
		await claimDue(fake.db, { lane: 'daily', now: NOW, limit: 10, cadenceMs: CADENCE });

		const sql = fake.calls[0].sql.replace(/\s+/g, ' ').trim();
		expect(sql).toContain(
			'WHERE id IN (SELECT id FROM scan_schedule WHERE active=1 AND lane=? AND next_scan_at<=? ORDER BY next_scan_at LIMIT ?)',
		);
		expect(sql).toContain('RETURNING id, tenant_id, domain, lane');
		// LIMIT must live INSIDE the subquery, never on the outer UPDATE alongside RETURNING.
		expect(sql).not.toMatch(/ORDER BY[^()]*LIMIT[^()]*RETURNING/);
	});

	it('returns the N lowest-next_scan_at eligible rows for the lane', async () => {
		const fake = makeScanScheduleDb([
			{ id: 1, domain: 'late.com', lane: 'daily', next_scan_at: NOW - 10 },
			{ id: 2, domain: 'earliest.com', lane: 'daily', next_scan_at: NOW - 100 },
			{ id: 3, domain: 'mid.com', lane: 'daily', next_scan_at: NOW - 50 },
			{ id: 4, domain: 'wronglane.com', lane: 'weekly', next_scan_at: NOW - 999 },
			{ id: 5, domain: 'notdue.com', lane: 'daily', next_scan_at: NOW + 10_000 },
		]);
		const { claimDue } = await import('../src/lib/scan-scheduler');
		const claimed = await claimDue(fake.db, { lane: 'daily', now: NOW, limit: 2, cadenceMs: CADENCE });
		expect(claimed.map((r) => r.domain)).toEqual(['earliest.com', 'mid.com']);
	});

	it('advances claimed rows a full cadence ahead so an immediate re-claim returns nothing (overlap/dedup safety)', async () => {
		const fake = makeScanScheduleDb([
			{ id: 1, domain: 'a.com', lane: 'daily', next_scan_at: NOW - 1 },
			{ id: 2, domain: 'b.com', lane: 'daily', next_scan_at: NOW - 2 },
		]);
		const { claimDue } = await import('../src/lib/scan-scheduler');

		const first = await claimDue(fake.db, { lane: 'daily', now: NOW, limit: 10, cadenceMs: CADENCE });
		expect(first).toHaveLength(2);
		for (const r of fake.rows) expect(r.next_scan_at).toBeGreaterThanOrEqual(NOW + CADENCE);

		const second = await claimDue(fake.db, { lane: 'daily', now: NOW, limit: 10, cadenceMs: CADENCE });
		expect(second).toHaveLength(0);
	});
});
