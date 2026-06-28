// test/helpers/scan-schedule-d1.ts
// SPDX-License-Identifier: BUSL-1.1
//
// In-memory `scan_schedule` D1 double for the Phase 2 scheduler-core specs.
//
// It is statement-aware: it recognizes each SQL the scheduler core is CONTRACTED
// to emit (by substring) and applies the EFFECT against an in-memory row array,
// so the same fixture verifies both the SQL SHAPE and the observable behavior.
// This follows the repo's existing "smart D1 fake" pattern (see
// test/brand-audit-reaper.test.ts). It is written BEFORE the implementation, so
// the specs FAIL at import (the scheduler module does not exist yet) and go green
// once the impl emits the contracted statements.
//
// CONTRACTED SQL (the impl MUST match these substrings + bind orders):
//
//   claimDue (GATE 4 — Form-B subquery, RETURNING):
//     UPDATE scan_schedule SET next_scan_at = ?, last_dispatched_at = ?
//     WHERE id IN (SELECT id FROM scan_schedule WHERE active=1 AND lane=? AND next_scan_at<=? ORDER BY next_scan_at LIMIT ?)
//     RETURNING id, tenant_id, domain, lane;
//     binds: [newNextScanAt, lastDispatchedAt, lane, nowBound, limit]
//
//   upsertSchedule (INSERT … ON CONFLICT):
//     INSERT INTO scan_schedule (tenant_id, domain, lane, next_scan_at, cadence_ms, active, consecutive_failures) …
//     binds: [tenant_id, domain, lane, next_scan_at, cadence_ms]
//
//   reSpreadOnCadenceChange (bulk spread via SQLite random(), NOT rand()):
//     UPDATE scan_schedule SET next_scan_at = ? + (abs(random()) % ?) WHERE active=1 AND lane=?
//     binds: [base, windowMs, lane]
//
//   markCompleted — read then update:
//     SELECT consecutive_failures FROM scan_schedule WHERE id = ?            (first)
//     failure: UPDATE scan_schedule SET consecutive_failures = consecutive_failures + 1, next_scan_at = ?, last_dispatched_at = ? WHERE id = ?
//     success: UPDATE scan_schedule SET consecutive_failures = 0, next_scan_at = ?, last_scanned_at = ? WHERE id = ?

import { vi } from 'vitest';

/** A single in-memory schedule row. */
export interface ScheduleRow {
	id: number;
	tenant_id: string;
	domain: string;
	lane: string;
	next_scan_at: number;
	cadence_ms: number;
	active: number;
	consecutive_failures: number;
	last_dispatched_at: number | null;
	last_scanned_at: number | null;
}

/** Partial seed → a fully-defaulted row. */
function row(seed: Partial<ScheduleRow> & Pick<ScheduleRow, 'id' | 'domain' | 'lane' | 'next_scan_at'>): ScheduleRow {
	return {
		tenant_id: seed.tenant_id ?? 'tenant_a',
		cadence_ms: seed.cadence_ms ?? 86_400_000,
		active: seed.active ?? 1,
		consecutive_failures: seed.consecutive_failures ?? 0,
		last_dispatched_at: seed.last_dispatched_at ?? null,
		last_scanned_at: seed.last_scanned_at ?? null,
		...seed,
	};
}

/** Deterministic LCG so the random()-spread test is varied but never flaky. */
function lcg(seed: number): () => number {
	let s = seed >>> 0;
	return () => {
		s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
		return s;
	};
}

export interface FakeScanScheduleDb {
	/** The D1Database to hand to the scheduler core. */
	db: D1Database;
	/** Live in-memory rows (inspect post-state directly). */
	rows: ScheduleRow[];
	/** Every prepared statement, in order: { sql, binds }. */
	calls: Array<{ sql: string; binds: unknown[] }>;
	/** prepare() spy (assert it is NOT called on the dispatch no-op path). */
	prepare: ReturnType<typeof vi.fn>;
}

/**
 * Build the in-memory `scan_schedule` D1 fake, pre-seeded with `seeds`.
 */
export function makeScanScheduleDb(
	seeds: Array<Partial<ScheduleRow> & Pick<ScheduleRow, 'id' | 'domain' | 'lane' | 'next_scan_at'>> = [],
): FakeScanScheduleDb {
	const rows: ScheduleRow[] = seeds.map(row);
	const calls: Array<{ sql: string; binds: unknown[] }> = [];
	const rand = lcg(0x9e3779b1);

	const prepare = vi.fn((sql: string) => {
		let binds: unknown[] = [];
		const record = () => calls.push({ sql, binds });

		const claim = () => {
			// GATE-4 Form-B claim-and-advance.
			const [newNext, lastDisp, lane, nowBound, limit] = binds as [number, number, string, number, number];
			const eligible = rows
				.filter((r) => r.active === 1 && r.lane === lane && r.next_scan_at <= nowBound)
				.sort((a, b) => a.next_scan_at - b.next_scan_at)
				.slice(0, limit);
			for (const r of eligible) {
				r.next_scan_at = newNext;
				r.last_dispatched_at = lastDisp;
			}
			return eligible.map((r) => ({ id: r.id, tenant_id: r.tenant_id, domain: r.domain, lane: r.lane }));
		};

		const stmt = {
			bind(...args: unknown[]) {
				binds = args;
				return stmt;
			},
			async first<T = unknown>(): Promise<T | null> {
				record();
				if (sql.includes('SELECT consecutive_failures')) {
					const id = binds[0] as number;
					const r = rows.find((x) => x.id === id);
					return (r ? { consecutive_failures: r.consecutive_failures } : null) as T | null;
				}
				return null;
			},
			async all<T = unknown>(): Promise<{ results: T[]; success: boolean }> {
				record();
				if (sql.includes('UPDATE scan_schedule') && sql.includes('RETURNING')) {
					return { results: claim() as T[], success: true };
				}
				return { results: [] as T[], success: true };
			},
			async run() {
				record();
				if (sql.includes('UPDATE scan_schedule') && sql.includes('RETURNING')) {
					// claimDue may also use .run() depending on impl; honor it.
					claim();
				} else if (sql.includes('INSERT INTO scan_schedule')) {
					const [tenantId, domain, lane, nextScanAt, cadenceMs] = binds as [string, string, string, number, number];
					const existing = rows.find((r) => r.tenant_id === tenantId && r.domain === domain);
					if (existing) {
						existing.lane = lane;
						existing.cadence_ms = cadenceMs;
						existing.active = 1;
					} else {
						rows.push(row({ id: rows.length + 1, tenant_id: tenantId, domain, lane, next_scan_at: nextScanAt, cadence_ms: cadenceMs }));
					}
				} else if (sql.includes('UPDATE scan_schedule') && sql.includes('random()')) {
					const [base, windowMs, lane] = binds as [number, number, string];
					for (const r of rows) {
						if (r.active === 1 && r.lane === lane) r.next_scan_at = base + (rand() % windowMs);
					}
				} else if (sql.includes('UPDATE scan_schedule') && sql.includes('WHERE id')) {
					const id = binds[binds.length - 1] as number;
					const r = rows.find((x) => x.id === id);
					if (r) {
						if (sql.includes('consecutive_failures = consecutive_failures + 1')) {
							r.consecutive_failures += 1;
							r.next_scan_at = binds[0] as number;
							r.last_dispatched_at = binds[1] as number;
						} else if (sql.includes('consecutive_failures = 0')) {
							r.consecutive_failures = 0;
							r.next_scan_at = binds[0] as number;
							r.last_scanned_at = binds[1] as number;
						}
					}
				}
				return { success: true, meta: { changes: 1 } };
			},
		};
		return stmt;
	});

	return { db: { prepare } as unknown as D1Database, rows, calls, prepare };
}

/** A queue spy matching the BV_SCANNER_SLOW_QUEUE send contract. */
export function makeSlowQueue() {
	const sent: Array<{ message: unknown; options?: { contentType?: 'json' } }> = [];
	const send = vi.fn(async (message: unknown, options?: { contentType?: 'json' }) => {
		sent.push({ message, options });
	});
	return { queue: { send } as unknown as Queue, send, sent };
}
