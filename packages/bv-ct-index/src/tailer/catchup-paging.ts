// SPDX-License-Identifier: BUSL-1.1
/**
 * Constants, SQL and the pure paging, lease and page-size helpers of the bounded catch-up reader (src/tailer/catchup.ts,
 * which documents the design). Nothing here touches the network or the database.
 */

import { RFC6962_PAGE } from './index';

/** Own schedule, apart from the tail's `* * * * *`: another invocation, so its own connection slots and subrequests. */
export const CATCHUP_CRON = '*/2 * * * *';
/** meta key: v = '1' stops the reader (the ops_ledger kill switch stops it too, and this one does not stop the tail). */
export const CATCHUP_KILL_KEY = 'catchup_killed';
/** CT-log fetches per row-run (the var of this name overrides it). */
export const CATCHUP_MAX_FETCHES = 800;
/**
 * Entries read per row-run. A fetch is a page, and a page is as large as the log serves, so the fetch budget alone bounds
 * queue volume only by the log's page size; this bounds it by a number. No page starts once the entries read plus the
 * entries in flight reach it, so a run reads at most one page less one more than this (255 on a first page of 256).
 */
export const CATCHUP_MAX_ENTRIES = 24_000;
/** Rows a dispatch starts: one message each, every row in its own invocation. */
export const CATCHUP_MAX_ROWS = 2;
/**
 * Requests in flight per row (the var of this name overrides it, clamped to 1..CATCHUP_PAGES_IN_FLIGHT_MAX). 6 is the
 * invocation's limit on connections waiting for headers, and the most the operator asked of one log host; a larger value
 * only queues behind HEADER_SLOTS for the header wait, and adds in-flight body reads.
 */
export const CATCHUP_PAGES_IN_FLIGHT = 6;
export const CATCHUP_PAGES_IN_FLIGHT_MAX = 8;
/**
 * No new fetch starts after this. The run then waits for pages already started (each ends within
 * CATCHUP_FETCH_TIMEOUT_MS) and commits: 100 + 15 + a commit stays inside the 120 s between dispatches, so a normal
 * run has released its lease before the next dispatch.
 */
export const CATCHUP_PHASE_MS = 100_000;
/** A request is cut off after this; longer than the tail's 5 s because a log answers get-entries in 1-3 s from a laptop. */
export const CATCHUP_FETCH_TIMEOUT_MS = 15_000;
/** A row that deferred or failed is left alone this long, counted from the failure (it skips one dispatch). */
export const CATCHUP_BACKOFF_MS = 180_000;
/** A lease outlasts the run's phase and one request timeout by this much; a normal run releases it long before. */
export const CATCHUP_LEASE_GRACE_MS = 60_000;
/** A dispatch message older than this is dropped unread: the next dispatch has sent a fresh one. */
export const CATCHUP_STALE_MS = 90_000;
/** A row's read re-reads the kill switches at most this often, so a switch thrown mid-run takes effect within it. */
export const KILL_RECHECK_MS = 5_000;
/** A short page's length is saved as the log's page size only after it was seen on this many consecutive pages. */
export const LEARN_CONSECUTIVE = 2;
/** Below MIN_TRUSTED_PAGE it takes this many (a transient 1-entry page must not become the size for good). */
export const LEARN_CONSECUTIVE_SMALL = 4;
export const MIN_TRUSTED_PAGE = 8;
/** A stored page size under this is probed for an upward correction on every run; a larger one on one run in PROBE_EVERY_RUNS. */
export const PROBE_BELOW = 32;
export const PROBE_EVERY_RUNS = 30;
/** The cron's period, for numbering runs by the clock. */
export const CATCHUP_PERIOD_MS = 120_000;
export const USER_AGENT = 'bv-ct-index (+https://blackveilsecurity.com)';

export const SELECT_KILLED = 'SELECT 1 AS killed FROM ops_ledger WHERE killed = 1 LIMIT 1';
export const SELECT_CATCHUP_KILL = 'SELECT v FROM meta WHERE k = ?1';
const CLAIMABLE = `state = 'active' AND next_index < upper_index AND (hold_until IS NULL OR hold_until <= ?1)`;
export const SELECT_ROWS = `SELECT log_id, kind, url, next_index, upper_index, page_size FROM log_backfill
WHERE ${CLAIMABLE} ORDER BY updated_at ASC, log_id ASC, upper_index ASC LIMIT ?2`;
export const SELECT_ONE = `SELECT log_id, kind, url, next_index, upper_index, page_size FROM log_backfill
WHERE ${CLAIMABLE} AND log_id = ?2 AND upper_index = ?3`;
export const CLAIM = `UPDATE log_backfill SET hold_until = ?1 WHERE log_id = ?2 AND upper_index = ?3 AND ${CLAIMABLE.replace('?1', '?4')}`;
export const RELEASE = 'UPDATE log_backfill SET hold_until = NULL WHERE log_id = ?1 AND upper_index = ?2 AND hold_until = ?3';
// Every write a run makes after claiming a row, except the cursor's compare-and-set (it guards on next_index), is guarded
// on the run's own lease: a run that outlived its lease matches no row and changes nothing.
export const SET_PAGE_SIZE = 'UPDATE log_backfill SET page_size = ?1 WHERE log_id = ?2 AND upper_index = ?3 AND hold_until = ?4';
export const ADVANCE = `UPDATE log_backfill SET next_index = ?1, state = CASE WHEN ?1 >= ?2 THEN 'done' ELSE state END,
	entries_read = entries_read + ?3, expired_skipped = expired_skipped + ?4, updated_at = ?5,
	last_error = COALESCE(?9, last_error), last_error_at = CASE WHEN ?9 IS NULL THEN last_error_at ELSE ?5 END
WHERE log_id = ?6 AND upper_index = ?7 AND next_index = ?8 AND state = 'active'`;
// Both move updated_at, which orders the work list: a row that keeps failing or deferring goes to the back, so it
// cannot hold the front of the list and starve the rows behind it. Both also set hold_until, the back-off.
export const RECORD_ERROR = `UPDATE log_backfill SET last_error = ?1, last_error_at = ?2, updated_at = ?2, hold_until = ?5
WHERE log_id = ?3 AND upper_index = ?4 AND hold_until = ?6`;
export const TOUCH = 'UPDATE log_backfill SET updated_at = ?1, hold_until = ?4 WHERE log_id = ?2 AND upper_index = ?3 AND hold_until = ?5';
export const ADD_TO_LEDGER = `INSERT INTO ops_ledger (day, r2_class_a, r2_class_b, d1_rows, killed) VALUES (?1, 0, ?2, ?3, 0)
ON CONFLICT (day) DO UPDATE SET r2_class_b = COALESCE(r2_class_b, 0) + excluded.r2_class_b, d1_rows = COALESCE(d1_rows, 0) + excluded.d1_rows`;

export const isTimeout = (error: unknown) => (error as { name?: unknown } | null)?.name === 'TimeoutError';

/** The last index of the page that starts at `start`: to the next multiple of `size`, and below the ceiling. */
export function pageEnd(start: number, size: number, ceiling: number): number {
	return Math.min((Math.floor(start / size) + 1) * size, ceiling) - 1;
}

export function budgetFrom(value: string | undefined, fallback: number): number {
	const parsed = Number(value);
	return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

/** How long a lease lasts: the run's phase, one request timeout and a grace. */
export function leaseEnd(now: number, phaseMs: number, timeoutMs: number): string {
	return new Date(now + phaseMs + timeoutMs + CATCHUP_LEASE_GRACE_MS).toISOString();
}

export interface ShortStreak {
	length: number;
	count: number;
}

/**
 * The page-size lesson of one short page: its length counts toward the streak of the same length, and is saved only once
 * the streak is long enough (LEARN_CONSECUTIVE, or LEARN_CONSECUTIVE_SMALL under MIN_TRUSTED_PAGE).
 */
export function nextStreak(streak: ShortStreak | null, length: number): { streak: ShortStreak; learn: boolean } {
	const count = streak && streak.length === length ? streak.count + 1 : 1;
	const needed = length < MIN_TRUSTED_PAGE ? LEARN_CONSECUTIVE_SMALL : LEARN_CONSECUTIVE;
	return { streak: { length, count }, learn: count >= needed };
}

/**
 * Whether this run probes for a larger page size: the stored size is under PROBE_BELOW (every run), or it is this row's
 * one run in PROBE_EVERY_RUNS (by the clock, as a run keeps no counter). A row with no stored size already asks for the most.
 */
export function probeDue(stored: number | null, now: number): boolean {
	if (stored === null || stored >= RFC6962_PAGE) return false;
	return stored < PROBE_BELOW || Math.floor(now / CATCHUP_PERIOD_MS) % PROBE_EVERY_RUNS === 0;
}

/** The first multiple of RFC6962_PAGE at or after the cursor, when it is below the ceiling: where a probe asks for a full page. */
export function probeStart(next: number, ceiling: number): number | null {
	const start = Math.ceil(next / RFC6962_PAGE) * RFC6962_PAGE;
	return start < ceiling ? start : null;
}

/** A probe's reply raises the stored size only when it is larger, at most a full page, and the page started on a multiple of it. */
export function probeRaises(stored: number, start: number, served: number): boolean {
	return served > stored && served <= RFC6962_PAGE && start % served === 0;
}
