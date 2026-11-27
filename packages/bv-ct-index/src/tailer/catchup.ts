// SPDX-License-Identifier: BUSL-1.1
/**
 * The bounded catch-up reader: reads [lower, upper) of a CT log, apart from the forward tail (src/tailer/index.ts).
 *
 * The forward tail follows a log only while the Chrome log list calls it usable or qualified, so a log that turns
 * readonly is dropped with its backlog unread (argon2027h1 and xenon2027h1, 2026-11-13: 303M entries). A row of
 * `log_backfill` (migrations/0006_log_backfill.sql) names one range of one log with its own url and kind, so this
 * reader needs neither the log list nor the log's state, and it changes nothing the tail follows. Rows are inserted by
 * an operator; the migration seeds none.
 *
 * Shape: one row per invocation. Cloudflare lets an invocation have 6 connections waiting for response headers, and
 * a log serves 32 entries a page in 1-3 s, so one invocation reading two logs would have 3 slots each and fall far
 * short of the pace the work needs. CATCHUP_CRON (every 2 min) therefore only DISPATCHES (dispatchCatchup): one message
 * per claimable row on the tail queue (the existing `bv-ct-index-tail` queue and consumer), and each message runs
 * runCatchup on its row in its own queue-consumer invocation, with its own 6 slots, its own subrequest budget and the
 * whole of the caps below. Without the TAIL binding the cron runs the first claimable row itself (one row a run, the
 * rows taking turns by updated_at); that is slower and is the fallback, not the design.
 *
 * Isolation from the tail: its own cron, so the dispatch is another invocation; its own table, so the tail's
 * compare-and-set on log_cursors is never contended and nothing is written to log_cursors. What it shares is the tail
 * queue (a different message kind) and the ENTRIES queue and its indexer: its rows are ordinary ObservationBatch messages.
 *
 * Limits this is sized against (Cloudflare docs, checked 2026-11-27): scheduled handlers and queue consumers 15 min wall
 * time (developers.cloudflare.com/workers/platform/limits/); CPU 30 s default, 300 s here via limits.cpu_ms; 10,000
 * subrequests per invocation on the paid plan (50 free); 6 simultaneous connections waiting for headers, more queue;
 * queue consumer 15 min wall, batch 100, 128 KB message, 5,000 messages/s per queue (queues/platform/limits/).
 *
 * One run of one row:
 * 1. Stop at once if either kill switch is set: ops_ledger.killed = 1 (the global one) or meta 'catchup_killed' = '1'.
 * 2. Claim the row: a compare-and-set on hold_until, which is the row's lease. A row another run holds, or one backing
 *    off after a deferral or error, is skipped, so a run still going when the next dispatch fires does not double the load.
 * 3. Read get-entries pages (or full static-ct data tiles), CATCHUP_PAGES_IN_FLIGHT at a time, sliding: a finished
 *    page is replaced by the next at once, and pages are consumed in order. Never at or past upper_index. A certificate
 *    already expired (notAfter < now) is counted and dropped before it is queued: it would only be dropped again at
 *    compaction. Ranges are aligned to the log's page size (page_size on the row), so no page is cut short at a boundary.
 * 4. Held rows are sent to ENTRIES, and only then does the row's cursor move, by a compare-and-set on the old
 *    next_index (and state 'active'), so an overlapping run or a paused row is never overwritten. Reaching the ceiling
 *    sets state 'done'. Re-reading an entry is harmless (rows merge idempotently), so a lost race wastes work only.
 * 5. Release the lease, and log one line (ct_catchup_run) with, per row, entries, fetches and page latency.
 *
 * A failed fetch or send is written to the row's last_error and leaves the cursor where the last good send put it. An
 * empty page and an HTTP 429 are deferrals, as in the tail: nothing is recorded but the time. Either way no further page
 * is started once one has failed, and the row is held off for CATCHUP_BACKOFF_MS, so a limited log is not hammered.
 *
 * A static-ct log is read in full tiles only, so its ceiling is upper_index rounded down to a tile; the partial tile
 * above it is not read and the row says so in last_error when it completes.
 *
 * WORST CASE, set by the caps and not by luck (per row-run; a dispatch is CATCHUP_MAX_ROWS = 2 of them):
 *   entries   <= CATCHUP_MAX_ENTRIES (24,000) + one page less one, so <= 24,031 a run, <= 48,062 per dispatch,
 *                <= 24,031 a minute across both rows at the 2-minute cadence (the queue sees at most that many certificates);
 *   fetches   <= CATCHUP_MAX_FETCHES (800) a row-run, 1,600 per dispatch; with queue sends (one per 120 KB of
 *                observations, a few dozen), kill checks (one D1 batch per 5 s, at most 21) and D1 writes, a row-run stays
 *                under about 1,000 subrequests against the 10,000 limit;
 *   in flight <= CATCHUP_PAGES_IN_FLIGHT (6) requests to one log host, and never more than HEADER_SLOTS (6) waiting for headers.
 * Pace at the phase of CATCHUP_PHASE_MS (100 s) in a 120 s cycle, 32 entries a page, pages in flight 6:
 *   a log answering in L seconds gives 6 x 100 / L pages a run: L = 1.5 -> ~12,900 entries a run (6,450/min);
 *   L = 3.15 -> ~6,170 a run (3,085/min); at twice those latencies half of each. Both caps sit above the fast case
 *   (L = 1.1 s reads ~17,500 entries in 545 fetches), so they bind only on a log faster than any measured.
 */

import type { Env } from '../index';
import { limiter } from '../indexer/blocks';
import type { ObservationBatch, RunRow } from '../types';
import { TILE_WIDTH, parseDataTile, precertTbsFromLeafInput, tilePath } from './ct';
import { FLUSH_ROWS, HEADER_SLOTS, MAX_EMITTED, RFC6962_PAGE, describeError } from './index';
import { newObservationSet, newRows, observeCert, toBatches, type ObservationSet, type SkipCounts } from './observations';
import { parseTbsCertificate } from './x509';

/** Own schedule, apart from the tail's `* * * * *`: another invocation, so its own connection slots and subrequests. */
export const CATCHUP_CRON = '*/2 * * * *';
/** meta key: v = '1' stops the reader (the ops_ledger kill switch stops it too, and this one does not stop the tail). */
export const CATCHUP_KILL_KEY = 'catchup_killed';
/** CT-log fetches per row-run (the var of this name overrides it). */
export const CATCHUP_MAX_FETCHES = 800;
/**
 * Entries read per row-run. A fetch is a page, and a page is as large as the log serves, so the fetch budget alone bounds
 * queue volume only by the log's page size; this bounds it by a number. No page starts once the entries read plus the
 * entries in flight reach it, so a run reads at most one page less one more than this.
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
/** A row that deferred or failed is left alone this long (it skips one dispatch, and is retried at the second). */
export const CATCHUP_BACKOFF_MS = 180_000;
/** A lease outlasts the run's phase and one request timeout by this much; a normal run releases it long before. */
export const CATCHUP_LEASE_GRACE_MS = 60_000;
/** A dispatch message older than this is dropped unread: the next dispatch has sent a fresh one. */
export const CATCHUP_STALE_MS = 90_000;
/** A row's read re-reads the kill switches at most this often, so a switch thrown mid-run takes effect within it. */
export const KILL_RECHECK_MS = 5_000;
const USER_AGENT = 'bv-ct-index (+https://blackveilsecurity.com)';

const SELECT_KILLED = 'SELECT 1 AS killed FROM ops_ledger WHERE killed = 1 LIMIT 1';
const SELECT_CATCHUP_KILL = 'SELECT v FROM meta WHERE k = ?1';
const CLAIMABLE = `state = 'active' AND next_index < upper_index AND (hold_until IS NULL OR hold_until <= ?1)`;
const SELECT_ROWS = `SELECT log_id, kind, url, next_index, upper_index, page_size FROM log_backfill
WHERE ${CLAIMABLE} ORDER BY updated_at ASC, log_id ASC, upper_index ASC LIMIT ?2`;
const SELECT_ONE = `SELECT log_id, kind, url, next_index, upper_index, page_size FROM log_backfill
WHERE ${CLAIMABLE} AND log_id = ?2 AND upper_index = ?3`;
const CLAIM = `UPDATE log_backfill SET hold_until = ?1 WHERE log_id = ?2 AND upper_index = ?3 AND ${CLAIMABLE.replace('?1', '?4')}`;
const RELEASE = 'UPDATE log_backfill SET hold_until = NULL WHERE log_id = ?1 AND upper_index = ?2 AND hold_until = ?3';
const SET_PAGE_SIZE =
	'UPDATE log_backfill SET page_size = ?1 WHERE log_id = ?2 AND upper_index = ?3 AND (page_size IS NULL OR page_size <> ?1)';
const ADVANCE = `UPDATE log_backfill SET next_index = ?1, state = CASE WHEN ?1 >= ?2 THEN 'done' ELSE state END,
	entries_read = entries_read + ?3, expired_skipped = expired_skipped + ?4, updated_at = ?5,
	last_error = COALESCE(?9, last_error), last_error_at = CASE WHEN ?9 IS NULL THEN last_error_at ELSE ?5 END
WHERE log_id = ?6 AND upper_index = ?7 AND next_index = ?8 AND state = 'active'`;
// Both move updated_at, which orders the work list: a row that keeps failing or deferring goes to the back, so it
// cannot hold the front of the list and starve the rows behind it. Both also set hold_until, the back-off.
const RECORD_ERROR = `UPDATE log_backfill SET last_error = ?1, last_error_at = ?2, updated_at = ?2, hold_until = ?5
WHERE log_id = ?3 AND upper_index = ?4`;
const TOUCH = 'UPDATE log_backfill SET updated_at = ?1, hold_until = ?4 WHERE log_id = ?2 AND upper_index = ?3';
const ADD_TO_LEDGER = `INSERT INTO ops_ledger (day, r2_class_a, r2_class_b, d1_rows, killed) VALUES (?1, 0, ?2, ?3, 0)
ON CONFLICT (day) DO UPDATE SET r2_class_b = COALESCE(r2_class_b, 0) + excluded.r2_class_b, d1_rows = COALESCE(d1_rows, 0) + excluded.d1_rows`;

interface BackfillRow {
	log_id: string;
	kind: 'rfc6962' | 'static';
	url: string;
	next_index: number;
	upper_index: number;
	page_size: number | null;
}

/** One dispatch message on the tail queue: run the catch-up reader on this row. */
export interface CatchupRequest {
	kind: 'catchup';
	scheduledTime: number;
	logId: string;
	upperIndex: number;
}

export interface CatchupOptions {
	/** Clock for the expiry test, timestamps, leases and the ledger day. Defaults to Date.now(). */
	now?: number;
	/** Outbound fetch. Defaults to the global fetch; tests inject a fake. */
	fetch?: typeof fetch;
	/** Overrides CATCHUP_MAX_FETCHES (and the env var). */
	maxFetches?: number;
	/** Overrides CATCHUP_MAX_ENTRIES (and the env var). */
	maxEntries?: number;
	/** Overrides CATCHUP_PAGES_IN_FLIGHT (and the env var). */
	pagesInFlight?: number;
	/** Overrides CATCHUP_PHASE_MS. */
	phaseMs?: number;
	/** How often a row's read re-reads the kill switches (default KILL_RECHECK_MS). */
	killRecheckMs?: number;
	fetchTimeoutMs?: number;
	/** Overrides FLUSH_ROWS. */
	flushRows?: number;
	/** Entries asked per get-entries page; defaults to the row's page_size, then to RFC6962_PAGE. */
	pageSize?: number;
	/** Reads this row only (a dispatch message); without it, the first claimable row. */
	only?: { logId: string; upperIndex: number };
}

/** What one row's read measured, for the run's log line. */
export interface RowStats {
	logId: string;
	entries: number;
	/** Requests started. */
	fetches: number;
	/** Pages that completed, and their latency (request start to body read) in ms. */
	pages: number;
	medianMs: number | null;
	maxMs: number | null;
	timeouts: number;
	rateLimited: number;
	/** Non-2xx replies other than 429. */
	httpErrors: number;
	/** Deferrals other than 429: an empty page, a tile not served yet. */
	deferrals: number;
}

export interface CatchupSummary {
	killed: boolean;
	/** Rows this run read: 0 or 1 (a row another run holds, or one backing off, is not read). */
	rows: number;
	/** Rows that reached their ceiling this run. */
	done: number;
	entries: number;
	precerts: number;
	/** Certificates dropped because notAfter was already past; not queued. */
	expired: number;
	badEntries: number;
	badNames: number;
	noApex: number;
	names: number;
	siblings: number;
	batches: number;
	subrequests: number;
	d1Rows: number;
	/** Rows whose cursor an overlapping run had already moved. */
	lost: number;
	/** Rows another run held, so this one did not read them. */
	held: number;
	perRow: RowStats[];
	/** log_id -> error, for the rows that recorded one. */
	errors: Record<string, string>;
	/** log_id -> why its read ended early without an error. */
	deferred: Record<string, string>;
}

interface Pending {
	start: number;
	end: number;
	promise: Promise<unknown[]>;
	/** The request has ended (either way); a finished page waiting its turn to be consumed no longer holds a slot. */
	settled: boolean;
	/** Which pipeline it belongs to; a page of a discarded pipeline starts nothing when it ends. */
	generation: number;
}

interface Work {
	row: BackfillRow;
	/** Nothing at or past this is read: upper_index, or for a static-ct log upper_index rounded down to a tile. */
	ceiling: number;
	/** Requests this row may start. */
	fetchCap: number;
	/** No page starts once the entries read plus the entries in flight reach this. */
	entryCap: number;
	next: number;
	/** The cursor as last written (the compare-and-set guard). */
	sentThrough: number;
	/** Entries per get-entries page the ranges are aligned to. */
	pageSize: number;
	/** Where the next page starts; equals `next` while nothing is in flight. */
	launchNext: number;
	pending: Pending[];
	generation: number;
	/** The row's read is over: nothing further starts. */
	closed: boolean;
	launches: number;
	/** A request failed: nothing further starts. */
	halt: boolean;
	observations: ObservationSet;
	entriesSince: number;
	expiredSince: number;
	finished: boolean;
	latencies: number[];
	stats: { fetches: number; timeouts: number; rateLimited: number; httpErrors: number; deferrals: number };
	startEntries: number;
}

interface Run {
	db: D1Database;
	fetch: typeof fetch;
	queue: Pick<Queue<ObservationBatch>, 'send'>;
	slot: <T>(task: () => Promise<T>) => Promise<T>;
	until: number;
	timeoutMs: number;
	flushRows: number;
	pageSize: number | undefined;
	pagesInFlight: number;
	certDetails: boolean;
	now: number;
	nowSec: number;
	emitted: Map<string, RunRow>;
	sendFailed: boolean;
	/** A kill switch was found set part-way through the run. */
	killed: boolean;
	killRecheckMs: number;
	killCheckedAt: number;
	fetches: number;
	sends: number;
	d1Rows: number;
	entries: number;
	precerts: number;
	expired: number;
	badEntries: number;
	names: number;
	siblings: number;
	batches: number;
	done: number;
	lost: number;
	held: number;
	perRow: RowStats[];
	skips: SkipCounts;
	errors: Record<string, string>;
	deferred: Record<string, string>;
}

class HttpError extends Error {
	constructor(
		readonly status: number,
		url: string,
	) {
		super(`HTTP ${status} from ${url}`);
	}
}
/** Ends a row's read without an error: not served yet, or rate limited. */
class Deferral extends Error {}
class RateLimited extends Deferral {}
/** A request that had no slot before the phase ended: the normal end of a run, not a failure. */
class PhaseEnded extends Error {}
/** Ends a row's read after a failed send; the error is already recorded. */
class SendFailed extends Error {}
/** Ends a row's read: an overlapping run moved the cursor, so this run's work on the row is over. */
class Lost extends Error {}

function rowsTouched(meta: { rows_read?: number; rows_written?: number } | undefined): number {
	return (meta?.rows_read ?? 0) + (meta?.rows_written ?? 0);
}

function held(work: Work): number {
	return work.observations.names.size + work.observations.siblings.size;
}

function canFetch(run: Run, work: Work): boolean {
	return !run.sendFailed && !work.halt && Date.now() < run.until && work.launches < work.fetchCap && run.entries < work.entryCap;
}

/** Pages of `size` entries a tile window may start without the run's entries passing the row's cap by more than one page. */
function pagesWithinEntryCap(run: Run, work: Work, size: number): number {
	return Math.max(1, Math.ceil((work.entryCap - run.entries) / size));
}

const isTimeout = (error: unknown) => (error as { name?: unknown } | null)?.name === 'TimeoutError';

/**
 * GETs `url` through a header slot; a 429 is a RateLimited deferral, any other non-2xx an HttpError, a network failure
 * names the URL. The time from the request's start to the end of the body read is the page's latency.
 */
async function get<T>(run: Run, work: Work, url: string, read: (response: Response) => Promise<T>): Promise<T> {
	const named = (error: unknown) =>
		error instanceof Deferral || error instanceof PhaseEnded ? error : new Error(`${describeError(error)} (${url})`);
	let response: Response;
	let started = 0;
	try {
		response = await run.slot(() => {
			if (Date.now() >= run.until) throw new PhaseEnded('read phase ended before this request had a slot');
			run.fetches++;
			work.stats.fetches++;
			started = Date.now();
			return run.fetch(url, { headers: { 'user-agent': USER_AGENT }, signal: AbortSignal.timeout(run.timeoutMs) });
		});
	} catch (error) {
		if (isTimeout(error)) work.stats.timeouts++;
		throw named(error);
	}
	if (!response.ok) {
		await response.body?.cancel();
		if (response.status === 429) {
			work.stats.rateLimited++;
			throw new RateLimited(`rate limited: HTTP 429 from ${url}`);
		}
		work.stats.httpErrors++;
		throw new HttpError(response.status, url);
	}
	try {
		const value = await read(response);
		work.latencies.push(Date.now() - started);
		return value;
	} catch (error) {
		if (isTimeout(error)) work.stats.timeouts++;
		throw named(error);
	}
}

/** Starts every request at once; a rejection is still seen by whoever awaits it, but never goes unhandled. */
function together<T>(requests: Array<() => Promise<T>>): Array<Promise<T>> {
	const pending = requests.map((request) => request());
	for (const promise of pending) promise.catch(() => undefined);
	return pending;
}

/** Parses one entry; an unexpired precert's names go into the row's observations. Never throws. */
function observeEntry(run: Run, work: Work, readTbs: () => Uint8Array | null): void {
	run.entries++;
	work.entriesSince++;
	try {
		const tbs = readTbs();
		if (!tbs) return;
		run.precerts++;
		const cert = parseTbsCertificate(tbs);
		if (cert.notAfter < run.nowSec) {
			run.expired++;
			work.expiredSince++;
			return;
		}
		observeCert(cert, work.observations, run.skips, run.certDetails);
	} catch {
		run.badEntries++;
	}
}

/** The last index of the page that starts at `start`: to the next multiple of `size`, and below the ceiling. */
function pageEnd(start: number, size: number, ceiling: number): number {
	return Math.min((Math.floor(start / size) + 1) * size, ceiling) - 1;
}

async function getEntries(run: Run, work: Work, start: number, end: number): Promise<unknown[]> {
	const url = `${work.row.url}ct/v1/get-entries?start=${start}&end=${end}`;
	const { entries } = await get(run, work, url, (response) => response.json<{ entries?: unknown }>());
	if (!Array.isArray(entries) || entries.length > end - start + 1) throw new Error(`get-entries ${start}-${end}: bad entries array`);
	return entries;
}

/**
 * Starts pages until `pagesInFlight` requests are outstanding or a limit is reached; called again whenever a request
 * ends, so a slow oldest page does not leave the others' slots idle. Pages are consumed in order, so up to twice as many
 * finished-or-running pages may be held. Never starts a page once one has failed.
 */
function fillPages(run: Run, work: Work): void {
	let queued = work.pending.reduce((sum, page) => sum + (page.end - page.start + 1), 0);
	let running = work.pending.filter((page) => !page.settled).length;
	while (
		running < run.pagesInFlight &&
		work.pending.length < 2 * run.pagesInFlight &&
		work.launchNext < work.ceiling &&
		!work.closed &&
		canFetch(run, work) &&
		run.entries + queued < work.entryCap
	) {
		const start = work.launchNext;
		const end = pageEnd(start, work.pageSize, work.ceiling);
		const promise = getEntries(run, work, start, end);
		const page: Pending = { start, end, promise, settled: false, generation: work.generation };
		promise.then(
			() => {
				page.settled = true;
				if (page.generation === work.generation) fillPages(run, work);
			},
			() => {
				page.settled = true;
				work.halt = true;
			},
		);
		work.launches++;
		work.pending.push(page);
		queued += end - start + 1;
		running++;
		work.launchNext = end + 1;
	}
}

/** Remembers the page size a log serves on the row, so the next run starts aligned. Best effort: it only saves fetches. */
async function learnPageSize(run: Run, work: Work, size: number): Promise<void> {
	if (size < 1 || size > RFC6962_PAGE || size === work.pageSize) return;
	work.pageSize = size;
	try {
		const result = await run.db.prepare(SET_PAGE_SIZE).bind(size, work.row.log_id, work.row.upper_index).run();
		run.d1Rows += rowsTouched(result.meta);
	} catch {
		// the size is still used for the rest of this run
	}
}

/**
 * Takes the oldest outstanding get-entries page (refilling the pipeline first, so the slots stay busy while it is
 * awaited) and observes it. A short page ends the pipeline: the pages after it start past a gap.
 */
async function readEntries(run: Run, work: Work): Promise<void> {
	fillPages(run, work);
	const head = work.pending[0];
	if (!head) return;
	const { start, end } = head;
	// Stays counted in `pending` while awaited, so the pages started meanwhile are measured against the entry cap correctly.
	const entries = await head.promise;
	work.pending.shift();
	if (entries.length === 0) throw new Deferral(`get-entries ${start}-${end}: no entries served yet`);
	for (const entry of entries) {
		observeEntry(run, work, () => {
			const leafInput = (entry as { leaf_input?: unknown } | null)?.leaf_input;
			if (typeof leafInput !== 'string') throw new TypeError('entry has no leaf_input');
			return precertTbsFromLeafInput(leafInput);
		});
	}
	work.next = start + entries.length;
	if (entries.length === end - start + 1) {
		fillPages(run, work);
	} else {
		// A later page that did come back with entries means the short page was the log's own cap, not the end of the log.
		// The cap is the length of a short page that starts on a multiple of it, from this page or the next: a page cut
		// at a boundary starts off one and teaches nothing.
		const later = work.pending[0];
		const laterEntries = later ? await later.promise.then((list) => list, () => [] as unknown[]) : [];
		const shorts: Array<[number, number]> = [[start, entries.length]];
		if (later && laterEntries.length < later.end - later.start + 1) shorts.push([later.start, laterEntries.length]);
		const taught = laterEntries.length > 0 ? shorts.find(([from, length]) => length > 0 && from % length === 0) : undefined;
		work.pending = [];
		work.generation++;
		work.launchNext = work.next;
		if (taught) await learnPageSize(run, work, taught[1]);
	}
}

async function getTile(run: Run, work: Work, tile: number): Promise<Array<Uint8Array | null>> {
	let body: ArrayBuffer;
	try {
		body = await get(run, work, `${work.row.url}tile/data/${tilePath(tile)}`, (response) => response.arrayBuffer());
	} catch (error) {
		if (error instanceof HttpError && error.status === 404) throw new Deferral(`data tile ${tile}: HTTP 404, not served yet`);
		throw error;
	}
	const entries = parseDataTile(new Uint8Array(body));
	if (entries.length !== TILE_WIDTH) throw new Error(`data tile ${tile}: ${entries.length} entries, expected ${TILE_WIDTH}`);
	return entries;
}

/** Up to `pagesInFlight` full data tiles from the one holding the cursor; entries before the cursor are skipped. The ceiling is tile-aligned. */
async function readTiles(run: Run, work: Work): Promise<void> {
	const first = Math.floor(work.next / TILE_WIDTH);
	const count = Math.min(run.pagesInFlight, work.ceiling / TILE_WIDTH - first, work.fetchCap - work.launches, pagesWithinEntryCap(run, work, TILE_WIDTH));
	const tiles = Array.from({ length: count }, (_, i) => first + i);
	work.launches += tiles.length;
	const bodies = together(
		tiles.map((tile) => () =>
			getTile(run, work, tile).catch((error: unknown) => {
				work.halt = true;
				throw error;
			}),
		),
	);
	for (const [i, tile] of tiles.entries()) {
		const entries = await bodies[i]!;
		for (let k = work.next - tile * TILE_WIDTH; k < TILE_WIDTH; k++) observeEntry(run, work, () => entries[k] ?? null);
		work.next = (tile + 1) * TILE_WIDTH;
	}
}

/** Sends the batches together; a failure stops the run (catchUpRow records it on the row). */
async function sendAll(run: Run, batches: readonly ObservationBatch[]): Promise<void> {
	try {
		await Promise.all(
			batches.map((batch) => {
				run.sends++;
				return run.slot(() => run.queue.send(batch, { contentType: 'json' }));
			}),
		);
	} catch (error) {
		run.sendFailed = true;
		throw new SendFailed(`queue send: ${describeError(error)}`);
	}
}

/**
 * Sends what the row holds, then moves its cursor to where the sent rows end. A failed send leaves the cursor; a lost
 * compare-and-set ends the row (the rows were sent, and re-reading is harmless).
 */
async function commit(run: Run, db: D1Database, work: Work): Promise<void> {
	const through = work.next;
	const done = through >= work.ceiling;
	if (work.finished || run.sendFailed || (through === work.sentThrough && !done)) return;
	if (run.emitted.size > MAX_EMITTED) run.emitted.clear();
	const rows = newRows(work.observations, run.emitted);
	const batches = toBatches(work.row.log_id, work.sentThrough, through, rows);
	work.observations = newObservationSet();
	await sendAll(run, batches);
	run.names += rows.names.length;
	run.siblings += rows.siblings.length;
	run.batches += batches.length;

	const note =
		done && work.ceiling < work.row.upper_index
			? `partial tile [${work.ceiling}, ${work.row.upper_index}) of a static-ct log not read`
			: null;
	const at = new Date(run.now).toISOString();
	const result = await db
		.prepare(ADVANCE)
		.bind(through, work.ceiling, work.entriesSince, work.expiredSince, at, work.row.log_id, work.row.upper_index, work.sentThrough, note)
		.run();
	run.d1Rows += rowsTouched(result.meta);
	if ((result.meta?.changes ?? 0) === 0) {
		run.lost++;
		throw new Lost(`cursor of ${work.row.log_id} moved by another run`);
	}
	work.sentThrough = through;
	work.entriesSince = 0;
	work.expiredSince = 0;
	if (done) {
		work.finished = true;
		run.done++;
	}
}

/** One row's read, to its caps, the ceiling or the first failure. Progress up to the last good page stands. */
async function catchUpRow(run: Run, db: D1Database, work: Work): Promise<void> {
	let failure: unknown;
	try {
		while (work.next < work.ceiling && (work.pending.length > 0 || canFetch(run, work))) {
			// A switch thrown mid-row stops the read within killRecheckMs; what was already read is still committed below.
			if (Date.now() - run.killCheckedAt >= run.killRecheckMs && (await isKilled(run, db))) {
				run.killed = true;
				break;
			}
			await (work.row.kind === 'static' ? readTiles(run, work) : readEntries(run, work));
			if (held(work) >= run.flushRows) await commit(run, db, work);
		}
	} catch (error) {
		failure = error;
	}
	work.closed = true;
	if (failure instanceof Lost) return;
	if (!(failure instanceof SendFailed)) {
		try {
			await commit(run, db, work);
		} catch (error) {
			if (error instanceof Lost) return;
			failure ??= error;
		}
	}
	if (failure instanceof PhaseEnded) failure = undefined;
	const holdUntil = new Date(run.now + CATCHUP_BACKOFF_MS).toISOString();
	if (failure instanceof Deferral) {
		if (!(failure instanceof RateLimited)) work.stats.deferrals++;
		run.deferred[work.row.log_id] = failure.message;
		const result = await db.prepare(TOUCH).bind(new Date(run.now).toISOString(), work.row.log_id, work.row.upper_index, holdUntil).run();
		run.d1Rows += rowsTouched(result.meta);
	} else if (failure) {
		const message = describeError(failure);
		run.errors[work.row.log_id] = message;
		const result = await db
			.prepare(RECORD_ERROR)
			.bind(message, new Date(run.now).toISOString(), work.row.log_id, work.row.upper_index, holdUntil)
			.run();
		run.d1Rows += rowsTouched(result.meta);
	}
}

function newRun(env: Pick<Env, 'ENTRIES' | 'CERT_DETAILS' | 'CATCHUP_PAGES_IN_FLIGHT'>, db: D1Database, options: CatchupOptions, now: number): Run {
	return {
		db,
		fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
		queue: env.ENTRIES,
		slot: limiter(HEADER_SLOTS),
		until: Date.now() + (options.phaseMs ?? CATCHUP_PHASE_MS),
		timeoutMs: options.fetchTimeoutMs ?? CATCHUP_FETCH_TIMEOUT_MS,
		flushRows: options.flushRows ?? FLUSH_ROWS,
		pageSize: options.pageSize,
		pagesInFlight: Math.min(
			CATCHUP_PAGES_IN_FLIGHT_MAX,
			options.pagesInFlight ?? budgetFrom(env.CATCHUP_PAGES_IN_FLIGHT, CATCHUP_PAGES_IN_FLIGHT),
		),
		certDetails: env.CERT_DETAILS === 'on',
		now,
		nowSec: Math.floor(now / 1000),
		emitted: new Map(),
		sendFailed: false,
		killed: false,
		killRecheckMs: options.killRecheckMs ?? KILL_RECHECK_MS,
		killCheckedAt: 0,
		fetches: 0,
		sends: 0,
		d1Rows: 0,
		entries: 0,
		precerts: 0,
		expired: 0,
		badEntries: 0,
		names: 0,
		siblings: 0,
		batches: 0,
		done: 0,
		lost: 0,
		held: 0,
		perRow: [],
		skips: { badNames: 0, noApex: 0 },
		errors: {},
		deferred: {},
	};
}

function rowStats(work: Work, run: Run): RowStats {
	const sorted = [...work.latencies].sort((a, b) => a - b);
	return {
		logId: work.row.log_id,
		entries: run.entries - work.startEntries,
		fetches: work.stats.fetches,
		pages: sorted.length,
		medianMs: sorted.length > 0 ? sorted[Math.floor(sorted.length / 2)]! : null,
		maxMs: sorted.length > 0 ? sorted[sorted.length - 1]! : null,
		timeouts: work.stats.timeouts,
		rateLimited: work.stats.rateLimited,
		httpErrors: work.stats.httpErrors,
		deferrals: work.stats.deferrals,
	};
}

function summarize(run: Run, killed: boolean, rows: number): CatchupSummary {
	return {
		killed,
		rows,
		done: run.done,
		entries: run.entries,
		precerts: run.precerts,
		expired: run.expired,
		badEntries: run.badEntries,
		badNames: run.skips.badNames,
		noApex: run.skips.noApex,
		names: run.names,
		siblings: run.siblings,
		batches: run.batches,
		subrequests: run.fetches + run.sends,
		d1Rows: run.d1Rows,
		lost: run.lost,
		held: run.held,
		perRow: run.perRow,
		errors: run.errors,
		deferred: run.deferred,
	};
}

/** The global ops_ledger switch or the reader's own meta switch. Read every run. */
async function isKilled(run: Run, db: D1Database): Promise<boolean> {
	const [ledger, own] = await db.batch<{ killed?: number; v?: string }>([
		db.prepare(SELECT_KILLED),
		db.prepare(SELECT_CATCHUP_KILL).bind(CATCHUP_KILL_KEY),
	]);
	run.d1Rows += rowsTouched(ledger?.meta) + rowsTouched(own?.meta);
	run.killCheckedAt = Date.now();
	return (ledger?.results.length ?? 0) > 0 || own?.results[0]?.v === '1';
}

function budgetFrom(value: string | undefined, fallback: number): number {
	const parsed = Number(value);
	return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * One row's run (see the header). Reads the row `options.only` names, else the first claimable row. A row another run
 * holds, or one backing off, is not read: `rows` is 0 and `held` counts it.
 */
export async function runCatchup(
	env: Pick<Env, 'CURSORS' | 'ENTRIES' | 'CERT_DETAILS' | 'CATCHUP_MAX_FETCHES' | 'CATCHUP_MAX_ENTRIES' | 'CATCHUP_PAGES_IN_FLIGHT'>,
	options: CatchupOptions = {},
): Promise<CatchupSummary> {
	const now = options.now ?? Date.now();
	const db = env.CURSORS;
	const run = newRun(env, db, options, now);
	if (await isKilled(run, db)) return summarize(run, true, 0);

	const at = new Date(now).toISOString();
	const taken = options.only
		? await db.prepare(SELECT_ONE).bind(at, options.only.logId, options.only.upperIndex).all<BackfillRow>()
		: await db.prepare(SELECT_ROWS).bind(at, CATCHUP_MAX_ROWS).all<BackfillRow>();
	run.d1Rows += rowsTouched(taken.meta);

	const lease = new Date(now + (options.phaseMs ?? CATCHUP_PHASE_MS) + run.timeoutMs + CATCHUP_LEASE_GRACE_MS).toISOString();
	let claimed: BackfillRow | undefined;
	for (const row of taken.results) {
		const result = await db.prepare(CLAIM).bind(lease, row.log_id, row.upper_index, at).run();
		run.d1Rows += rowsTouched(result.meta);
		if ((result.meta?.changes ?? 0) > 0) {
			claimed = row;
			break;
		}
		run.held++;
	}
	if (!claimed && options.only && taken.results.length === 0) run.held++;

	if (claimed) {
		const row = claimed;
		const work: Work = {
			row,
			ceiling: row.kind === 'static' ? Math.floor(row.upper_index / TILE_WIDTH) * TILE_WIDTH : row.upper_index,
			fetchCap: options.maxFetches ?? budgetFrom(env.CATCHUP_MAX_FETCHES, CATCHUP_MAX_FETCHES),
			entryCap: run.entries + (options.maxEntries ?? budgetFrom(env.CATCHUP_MAX_ENTRIES, CATCHUP_MAX_ENTRIES)),
			next: row.next_index,
			sentThrough: row.next_index,
			pageSize: run.pageSize ?? row.page_size ?? RFC6962_PAGE,
			launchNext: row.next_index,
			pending: [],
			generation: 0,
			closed: false,
			launches: 0,
			halt: false,
			observations: newObservationSet(),
			entriesSince: 0,
			expiredSince: 0,
			finished: false,
			latencies: [],
			stats: { fetches: 0, timeouts: 0, rateLimited: 0, httpErrors: 0, deferrals: 0 },
			startEntries: run.entries,
		};
		try {
			await catchUpRow(run, db, work);
		} finally {
			// Only our own lease: a back-off the row recorded, or another run's lease, is left as it is.
			const released = await db.prepare(RELEASE).bind(row.log_id, row.upper_index, lease).run();
			run.d1Rows += rowsTouched(released.meta);
			run.perRow.push(rowStats(work, run));
		}
	}

	const summary = summarize(run, run.killed, claimed ? 1 : 0);
	await db.prepare(ADD_TO_LEDGER).bind(new Date(now).toISOString().slice(0, 10), summary.subrequests, summary.d1Rows).run();
	return summary;
}

export interface DispatchSummary {
	killed: boolean;
	/** Claimable rows found, and messages sent for them. */
	rows: number;
	sent: number;
	failed: string | null;
}

/**
 * The cron's work: one message per claimable row (at most CATCHUP_MAX_ROWS) on the tail queue, each run by its own
 * queue-consumer invocation. The claim itself happens in runCatchup, so a message that finds the row taken does nothing.
 */
export async function dispatchCatchup(
	env: Pick<Env, 'CURSORS'>,
	queue: Pick<Queue<CatchupRequest>, 'sendBatch'>,
	scheduledTime: number,
	options: { now?: number } = {},
): Promise<DispatchSummary> {
	const db = env.CURSORS;
	const [ledger, own] = await db.batch<{ killed?: number; v?: string }>([
		db.prepare(SELECT_KILLED),
		db.prepare(SELECT_CATCHUP_KILL).bind(CATCHUP_KILL_KEY),
	]);
	if ((ledger?.results.length ?? 0) > 0 || own?.results[0]?.v === '1') return { killed: true, rows: 0, sent: 0, failed: null };
	const at = new Date(options.now ?? Date.now()).toISOString();
	const taken = await db.prepare(SELECT_ROWS).bind(at, CATCHUP_MAX_ROWS).all<BackfillRow>();
	const requests = taken.results.map((row) => ({
		body: { kind: 'catchup' as const, scheduledTime, logId: row.log_id, upperIndex: row.upper_index },
		contentType: 'json' as const,
	}));
	if (requests.length === 0) return { killed: false, rows: 0, sent: 0, failed: null };
	try {
		await queue.sendBatch(requests);
	} catch (error) {
		return { killed: false, rows: requests.length, sent: 0, failed: describeError(error) };
	}
	return { killed: false, rows: requests.length, sent: requests.length, failed: null };
}

export function isCatchupRequest(body: unknown): body is CatchupRequest {
	const request = body as Partial<CatchupRequest> | null;
	return (
		request?.kind === 'catchup' &&
		typeof request.scheduledTime === 'number' &&
		typeof request.logId === 'string' &&
		typeof request.upperIndex === 'number'
	);
}

/** Runs one dispatch message; a message older than CATCHUP_STALE_MS is dropped (the next dispatch sent a fresh one). */
export async function runCatchupMessage(
	env: Parameters<typeof runCatchup>[0],
	body: CatchupRequest,
	options: CatchupOptions = {},
): Promise<CatchupSummary | { skipped: 'stale' }> {
	if ((options.now ?? Date.now()) - body.scheduledTime > CATCHUP_STALE_MS) return { skipped: 'stale' };
	return runCatchup(env, { ...options, only: { logId: body.logId, upperIndex: body.upperIndex } });
}
