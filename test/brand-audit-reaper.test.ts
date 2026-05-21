// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the brand-audit reaper — the backstop for stuck `running`
 * rows the consumer's 300s cap doesn't unwedge.
 */

import { describe, it, expect } from 'vitest';
import {
	reapStuckBrandAudits,
	STUCK_TARGET_THRESHOLD_MS,
	MAX_REAP_PER_TICK,
	BRAND_AUDIT_TARGET_DEADLINE_MS,
} from '../src/lib/brand-audit-reaper';

interface MockOpts {
	stuckRows?: Array<{ audit_id: string; target: string }>;
	counterByAudit?: Record<string, { completed_targets: number; total_targets: number }>;
	throwOnSelect?: boolean;
	throwOnFlip?: boolean;
	throwOnCounter?: boolean;
	flipChanges?: number;
	finalizeChanges?: number;
}

interface Call {
	sql: string;
	binds: unknown[];
}

function makeMockD1(opts: MockOpts = {}) {
	const calls: Call[] = [];
	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first() {
					calls.push({ sql, binds });
					if (opts.throwOnCounter && sql.includes('SELECT completed_targets')) {
						throw new Error('d1_counter_failed');
					}
					if (sql.includes('SELECT completed_targets, total_targets')) {
						const auditId = binds[0] as string;
						return opts.counterByAudit?.[auditId] ?? null;
					}
					return null;
				},
				async run() {
					calls.push({ sql, binds });
					if (opts.throwOnFlip && sql.includes("status = 'failed'")) {
						throw new Error('d1_flip_failed');
					}
					let changes = 1;
					if (sql.includes("UPDATE brand_audit_targets SET status = 'failed'")) {
						changes = opts.flipChanges ?? 1;
					}
					if (sql.includes("UPDATE brand_audits SET status = 'completed'")) {
						changes = opts.finalizeChanges ?? 1;
					}
					return { success: true, meta: { changes, last_row_id: 0, duration: 0, rows_read: 0, rows_written: changes, size_after: 0 } };
				},
				async all<T = unknown>() {
					calls.push({ sql, binds });
					if (opts.throwOnSelect && sql.includes('SELECT audit_id, target')) {
						throw new Error('d1_select_failed');
					}
					if (sql.includes('SELECT audit_id, target FROM brand_audit_targets')) {
						return { results: (opts.stuckRows ?? []) as T[], success: true, meta: {} };
					}
					return { results: [] as T[], success: true, meta: {} };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return { db, calls };
}

const NOW = 1_750_000_000_000;

describe('reapStuckBrandAudits', () => {
	it('returns zero-result when nothing is stuck', async () => {
		const { db, calls } = makeMockD1({ stuckRows: [] });
		const result = await reapStuckBrandAudits({ db, now: () => NOW });
		expect(result).toEqual({ scannedRows: 0, reapedTargets: 0, finalizedAudits: 0, skippedOverCap: false });
		// SELECT issued, nothing else.
		expect(calls.filter((c) => c.sql.includes('UPDATE'))).toEqual([]);
	});

	it('flips a stuck target to failed and ticks the parent counter', async () => {
		const { db, calls } = makeMockD1({
			stuckRows: [{ audit_id: 'aud-1', target: 'brand-alpha.example.com' }],
			counterByAudit: { 'aud-1': { completed_targets: 1, total_targets: 3 } },
		});
		const result = await reapStuckBrandAudits({ db, now: () => NOW });
		expect(result.reapedTargets).toBe(1);
		expect(result.finalizedAudits).toBe(0);

		const flip = calls.find((c) => c.sql.includes("status = 'failed'") && c.binds.includes('brand-alpha.example.com'));
		expect(flip).toBeDefined();
		const counterTick = calls.find((c) => c.sql.includes('UPDATE brand_audits SET completed_targets'));
		expect(counterTick).toBeDefined();
	});

	it('finalizes the parent audit when the reaped target is the last one', async () => {
		const { db, calls } = makeMockD1({
			stuckRows: [{ audit_id: 'aud-1', target: 'brand-alpha.example.com' }],
			counterByAudit: { 'aud-1': { completed_targets: 1, total_targets: 1 } },
		});
		const result = await reapStuckBrandAudits({ db, now: () => NOW });
		expect(result.finalizedAudits).toBe(1);
		const finalize = calls.find(
			(c) => c.sql.includes('UPDATE brand_audits SET status') && c.sql.includes("'completed'"),
		);
		expect(finalize).toBeDefined();
	});

	it('uses the 15-minute threshold when querying for stuck rows', async () => {
		const { db, calls } = makeMockD1({ stuckRows: [] });
		await reapStuckBrandAudits({ db, now: () => NOW });
		const select = calls.find((c) => c.sql.includes('SELECT audit_id, target'));
		expect(select).toBeDefined();
		expect(select!.binds[0]).toBe('running');
		expect(select!.binds[1]).toBe(NOW - STUCK_TARGET_THRESHOLD_MS);
	});

	it('caps reaps per tick and reports skippedOverCap', async () => {
		const tooMany = Array.from({ length: MAX_REAP_PER_TICK + 5 }, (_, i) => ({
			audit_id: `aud-${i}`,
			target: `target-${i}.example`,
		}));
		const { db } = makeMockD1({
			stuckRows: tooMany,
			counterByAudit: Object.fromEntries(tooMany.map((r) => [r.audit_id, { completed_targets: 1, total_targets: 5 }])),
		});
		const result = await reapStuckBrandAudits({ db, now: () => NOW });
		// Mock doesn't honor SQL LIMIT, so all rows come back — confirms the
		// reaper itself caps execution to MAX_REAP_PER_TICK regardless of what
		// D1 returned.
		expect(result.scannedRows).toBeGreaterThan(MAX_REAP_PER_TICK);
		expect(result.reapedTargets).toBe(MAX_REAP_PER_TICK);
		expect(result.skippedOverCap).toBe(true);
	});

	it('returns empty result on SELECT failure (never throws)', async () => {
		const { db } = makeMockD1({ throwOnSelect: true });
		const result = await reapStuckBrandAudits({ db, now: () => NOW });
		expect(result).toEqual({ scannedRows: 0, reapedTargets: 0, finalizedAudits: 0, skippedOverCap: false });
	});

	it('skips counter tick when the flip UPDATE matched 0 rows (raced)', async () => {
		// Another consumer or reaper already flipped this row terminal between
		// our SELECT and UPDATE — flipChanges=0 should suppress the counter tick.
		const { db, calls } = makeMockD1({
			stuckRows: [{ audit_id: 'aud-1', target: 'brand-alpha.example.com' }],
			flipChanges: 0,
		});
		const result = await reapStuckBrandAudits({ db, now: () => NOW });
		expect(result.reapedTargets).toBe(0);
		const counterTick = calls.find((c) => c.sql.includes('UPDATE brand_audits SET completed_targets'));
		expect(counterTick).toBeUndefined();
	});

	it('uses a 10-minute STUCK_TARGET_THRESHOLD_MS (tightened from 15min after the 2026-05-21 disney dead-zone investigation)', () => {
		// The consumer cap is 5 min. We previously waited 15min to reap, leaving
		// a 5–15min dead zone. The read-path piggyback in `brand_audit_status`
		// now handles polling customers near-instantly; the cron reaper still
		// catches non-polled audits, but at 10min instead of 15min.
		expect(STUCK_TARGET_THRESHOLD_MS).toBe(10 * 60 * 1000);
	});

	it('exposes BRAND_AUDIT_TARGET_DEADLINE_MS for the read-path piggyback (~7min)', () => {
		// Consumer cap (300s) + 120s grace for queue delivery lag + cap-fire
		// macrotask + D1 flip. Used by `brand_audit_status` /
		// `brand_audit_get_report` to synthesise `failed` for targets the
		// consumer can no longer save. MUST be < STUCK_TARGET_THRESHOLD_MS so
		// the read path acts before the reaper.
		expect(BRAND_AUDIT_TARGET_DEADLINE_MS).toBe(7 * 60 * 1000);
		expect(BRAND_AUDIT_TARGET_DEADLINE_MS).toBeLessThan(STUCK_TARGET_THRESHOLD_MS);
	});

	it('continues reaping other rows when one flip throws', async () => {
		const { db } = makeMockD1({
			stuckRows: [
				{ audit_id: 'aud-1', target: 'a.example' },
				{ audit_id: 'aud-2', target: 'b.example' },
			],
			counterByAudit: {
				'aud-1': { completed_targets: 1, total_targets: 3 },
				'aud-2': { completed_targets: 1, total_targets: 3 },
			},
			throwOnFlip: true,
		});
		const result = await reapStuckBrandAudits({ db, now: () => NOW });
		// Both flips throw → neither reaped.
		expect(result.reapedTargets).toBe(0);
	});
});
