// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 2 scheduler core — the **schedule index** (claim-and-advance).
 *
 * This module owns the `scan_schedule` row lifecycle behind the default-OFF
 * Phase 2 dispatcher (see `src/scheduler/dispatch.ts`). It ships DARK: nothing
 * here runs unless `SCAN_DISPATCH_ENABLED === 'true'` AND the optional
 * `SCAN_SCHEDULE_DB` binding is present (both gated at the dispatch boundary).
 *
 * GATE 4 (verified on local D1 = prod workerd SQLite): D1 REJECTS
 * `UPDATE … ORDER BY … LIMIT N RETURNING …` (RETURNING + LIMIT together is a
 * syntax error). `claimDue` therefore uses the Form-B subquery — the `LIMIT`
 * lives INSIDE a `WHERE id IN (SELECT … ORDER BY … LIMIT ?)` subquery, atomic
 * within the single statement (D1 serializes writes), with `RETURNING` on the
 * outer `UPDATE`. SQLite exposes `random()` (signed 64-bit; scale via
 * `abs()`/modulo), NOT MySQL's `rand()`.
 *
 * Schema + migration: `src/scheduler/db/schema.ts` +
 * `src/scheduler/db/migrations/0000_scan_schedule.sql`.
 */

/** A row returned by a `claimDue` claim-and-advance. */
export interface ClaimedScanRow {
	/** Autoincrement schedule-row id. */
	id: number;
	/** Owning tenant. */
	tenant_id: string;
	/** Scheduled domain. */
	domain: string;
	/** Scheduling lane (e.g. `fast` / `slow`). */
	lane: string;
}

/** Args for {@link claimDue}. */
export interface ClaimDueOptions {
	/** Lane to claim from. */
	lane: string;
	/** Wall-clock epoch ms "now". Rows with `next_scan_at <= now` are eligible. */
	now: number;
	/** Max rows to claim (the Form-B `LIMIT ?`). */
	limit: number;
	/** Lane cadence in ms — claimed rows advance a full cadence ahead. */
	cadenceMs: number;
}

/** Args for {@link upsertSchedule}. */
export interface UpsertScheduleOptions {
	/** Owning tenant. */
	tenantId: string;
	/** Domain to schedule. */
	domain: string;
	/** Scheduling lane. */
	lane: string;
	/** Cadence between scans, ms. */
	cadenceMs: number;
	/** Wall-clock epoch ms "now". */
	now: number;
}

/** Args for {@link reSpreadOnCadenceChange}. */
export interface ReSpreadOptions {
	/** Lane to re-spread. */
	lane: string;
	/** Base instant (epoch ms) the new window starts from. */
	now: number;
	/** New cadence window width, ms. */
	cadenceMs: number;
}

/** Args for {@link markCompleted}. */
export interface MarkCompletedOptions {
	/** Schedule-row id (from {@link ClaimedScanRow}). */
	id: number;
	/** Whether the scan succeeded. */
	success: boolean;
	/** Wall-clock epoch ms "now" (completion time). */
	now: number;
	/** Lane cadence in ms. */
	cadenceMs: number;
}

/**
 * GATE-4 Form-B claim. The `LIMIT` is INSIDE the subquery (never on the outer
 * `UPDATE` alongside `RETURNING`, which D1 rejects). Bind order:
 * `[newNextScanAt, lastDispatchedAt, lane, now, limit]`.
 */
const CLAIM_DUE_SQL =
	'UPDATE scan_schedule SET next_scan_at = ?, last_dispatched_at = ? ' +
	'WHERE id IN (SELECT id FROM scan_schedule WHERE active=1 AND lane=? AND next_scan_at<=? ORDER BY next_scan_at LIMIT ?) ' +
	'RETURNING id, tenant_id, domain, lane';

/** Upsert keyed on the `UNIQUE(tenant_id, domain)` constraint. */
const UPSERT_SCHEDULE_SQL =
	'INSERT INTO scan_schedule (tenant_id, domain, lane, next_scan_at, cadence_ms, active, consecutive_failures) ' +
	'VALUES (?, ?, ?, ?, ?, 1, 0) ' +
	'ON CONFLICT(tenant_id, domain) DO UPDATE SET lane = excluded.lane, cadence_ms = excluded.cadence_ms, active = 1';

/** Bulk re-spread using SQLite `random()` (NOT `rand()`). Bind: `[base, windowMs, lane]`. */
const RESPREAD_SQL = 'UPDATE scan_schedule SET next_scan_at = ? + (abs(random()) % ?) WHERE active=1 AND lane=?';

const SELECT_FAILURES_SQL = 'SELECT consecutive_failures FROM scan_schedule WHERE id = ?';
const MARK_FAILURE_SQL =
	'UPDATE scan_schedule SET consecutive_failures = consecutive_failures + 1, next_scan_at = ?, last_dispatched_at = ? WHERE id = ?';
const MARK_SUCCESS_SQL = 'UPDATE scan_schedule SET consecutive_failures = 0, next_scan_at = ?, last_scanned_at = ? WHERE id = ?';

/** Cap the exponential-backoff exponent so a long-failing domain can't overflow. */
const MAX_BACKOFF_EXPONENT = 8;

/**
 * Claim up to `limit` due rows for `lane` and advance each a full cadence ahead
 * in a single atomic statement (overlap/dedup-safe: an immediate re-claim sees
 * nothing because the claimed rows' `next_scan_at` jumped past `now`).
 *
 * @returns The claimed rows (lowest `next_scan_at` first), or `[]`.
 */
export async function claimDue(db: D1Database, { lane, now, limit, cadenceMs }: ClaimDueOptions): Promise<ClaimedScanRow[]> {
	const newNextScanAt = now + cadenceMs + claimJitter(lane, now, cadenceMs);
	const { results } = await db.prepare(CLAIM_DUE_SQL).bind(newNextScanAt, now, lane, now, limit).all<ClaimedScanRow>();
	return results ?? [];
}

/**
 * Insert or refresh a schedule row. The first scan is jittered to a
 * DETERMINISTIC per-domain slot within `[now, now + cadenceMs)` so a bulk
 * onboarding does not stack every domain on a single dispatch tick.
 */
export async function upsertSchedule(db: D1Database, { tenantId, domain, lane, cadenceMs, now }: UpsertScheduleOptions): Promise<void> {
	const nextScanAt = now + perDomainJitter(tenantId, domain, cadenceMs);
	await db.prepare(UPSERT_SCHEDULE_SQL).bind(tenantId, domain, lane, nextScanAt, cadenceMs).run();
}

/**
 * Re-spread a lane's `next_scan_at` uniformly across `[now, now + cadenceMs)`
 * using SQLite `random()`. Call after a cadence change so the cohort that was
 * all due "now" doesn't herd onto one tick.
 */
export async function reSpreadOnCadenceChange(db: D1Database, { lane, now, cadenceMs }: ReSpreadOptions): Promise<void> {
	await db.prepare(RESPREAD_SQL).bind(now, cadenceMs, lane).run();
}

/**
 * Record a scan outcome. Success resets `consecutive_failures` and reschedules
 * exactly one cadence ahead; failure increments the counter and applies an
 * exponential backoff (`cadence * 2^failures`, exponent capped) on top of `now`.
 */
export async function markCompleted(db: D1Database, { id, success, now, cadenceMs }: MarkCompletedOptions): Promise<void> {
	if (success) {
		await db
			.prepare(MARK_SUCCESS_SQL)
			.bind(now + cadenceMs, now, id)
			.run();
		return;
	}
	const row = await db.prepare(SELECT_FAILURES_SQL).bind(id).first<{ consecutive_failures: number }>();
	const newFailures = (row?.consecutive_failures ?? 0) + 1;
	const backoffMs = cadenceMs * 2 ** Math.min(newFailures, MAX_BACKOFF_EXPONENT);
	await db
		.prepare(MARK_FAILURE_SQL)
		.bind(now + backoffMs, now, id)
		.run();
}

/** FNV-1a (32-bit) — small, fast, deterministic string hash. Never throws. */
function fnv1a(input: string): number {
	let h = 0x811c9dc5;
	for (let i = 0; i < input.length; i++) {
		h ^= input.charCodeAt(i);
		h = Math.imul(h, 0x01000193);
	}
	return h >>> 0;
}

/** Deterministic per-domain offset in `[0, cadenceMs)`; same domain → same slot. */
function perDomainJitter(tenantId: string, domain: string, cadenceMs: number): number {
	if (!Number.isFinite(cadenceMs) || cadenceMs <= 0) return 0;
	return fnv1a(`${tenantId}:${domain}`) % cadenceMs;
}

/** Small per-claim offset (≤ 10% of cadence) so re-claims don't re-clump on one instant. */
function claimJitter(lane: string, now: number, cadenceMs: number): number {
	if (!Number.isFinite(cadenceMs) || cadenceMs <= 0) return 0;
	const bound = Math.max(1, Math.floor(cadenceMs / 10));
	return fnv1a(`${lane}:${now}`) % bound;
}
