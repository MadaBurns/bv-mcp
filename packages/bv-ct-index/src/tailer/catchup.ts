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
 * Isolation from the tail: its own cron (CATCHUP_CRON), so its fetches use another invocation's connection slots and
 * subrequest budget; its own table, so the tail's compare-and-set on log_cursors is never contended; a small per-run
 * budget (CATCHUP_MAX_FETCHES, raised with the CATCHUP_MAX_FETCHES var). What it does share is the ENTRIES queue and
 * its indexer: its rows are ordinary ObservationBatch messages.
 *
 * One run:
 * 1. Stop at once if either kill switch is set: ops_ledger.killed = 1 (the global one) or meta 'catchup_killed' = '1'.
 * 2. Take up to CATCHUP_MAX_ROWS active rows, least recently advanced first; each gets an equal share of the budget.
 * 3. A row reads WINDOW get-entries pages (or full static-ct data tiles) at a time from its cursor, never at or past
 *    upper_index. A certificate already expired (notAfter < now) is counted and dropped before it is queued: it would
 *    only be dropped again at compaction.
 * 4. Held rows are sent to ENTRIES, and only then does the row's cursor move, by a compare-and-set on the old
 *    next_index (and state 'active'), so an overlapping run or a paused row is never overwritten. Reaching the ceiling
 *    sets state 'done'. Re-reading an entry is harmless (rows merge idempotently), so a lost race wastes work only.
 *
 * A failed fetch or send is written to the row's last_error and leaves the cursor where the last good send put it. An
 * empty page and an HTTP 429 are deferrals, as in the tail: the run ends, nothing is recorded, the next run retries.
 *
 * A static-ct log is read in full tiles only, so its ceiling is upper_index rounded down to a tile; the partial tile
 * above it is not read and the row says so in last_error when it completes.
 */

import type { Env } from '../index';
import { limiter } from '../indexer/blocks';
import type { ObservationBatch, RunRow } from '../types';
import { TILE_WIDTH, parseDataTile, precertTbsFromLeafInput, tilePath } from './ct';
import { FLUSH_ROWS, FETCH_TIMEOUT_MS, HEADER_SLOTS, MAX_EMITTED, RFC6962_PAGE, WINDOW, describeError } from './index';
import { newObservationSet, newRows, observeCert, toBatches, type ObservationSet, type SkipCounts } from './observations';
import { parseTbsCertificate } from './x509';

/** Own schedule, apart from the tail's `* * * * *`: another invocation, so its own connection slots and subrequests. */
export const CATCHUP_CRON = '*/2 * * * *';
/** meta key: v = '1' stops the reader (the ops_ledger kill switch stops it too, and this one does not stop the tail). */
export const CATCHUP_KILL_KEY = 'catchup_killed';
/** CT-log fetches per run, split across the rows taken. At 32 entries a page that is about 19k entries a run. */
export const CATCHUP_MAX_FETCHES = 600;
export const CATCHUP_MAX_ROWS = 2;
/** No new fetch starts after this; with FETCH_TIMEOUT_MS the run ends well inside a cron invocation. */
export const CATCHUP_PHASE_MS = 30_000;
/** A row's read re-reads the kill switches at most this often, so a switch thrown mid-run takes effect within it. */
export const KILL_RECHECK_MS = 5_000;
const USER_AGENT = 'bv-ct-index (+https://blackveilsecurity.com)';

const SELECT_KILLED = 'SELECT 1 AS killed FROM ops_ledger WHERE killed = 1 LIMIT 1';
const SELECT_CATCHUP_KILL = 'SELECT v FROM meta WHERE k = ?1';
const SELECT_ROWS = `SELECT log_id, kind, url, next_index, upper_index FROM log_backfill
WHERE state = 'active' AND next_index < upper_index ORDER BY updated_at ASC, log_id ASC, upper_index ASC LIMIT ?1`;
const ADVANCE = `UPDATE log_backfill SET next_index = ?1, state = CASE WHEN ?1 >= ?2 THEN 'done' ELSE state END,
	entries_read = entries_read + ?3, expired_skipped = expired_skipped + ?4, updated_at = ?5,
	last_error = COALESCE(?9, last_error), last_error_at = CASE WHEN ?9 IS NULL THEN last_error_at ELSE ?5 END
WHERE log_id = ?6 AND upper_index = ?7 AND next_index = ?8 AND state = 'active'`;
// Both move updated_at, which orders the work list: a row that keeps failing or deferring goes to the back, so it
// cannot hold the front of the list and starve the rows behind it.
const RECORD_ERROR =
	'UPDATE log_backfill SET last_error = ?1, last_error_at = ?2, updated_at = ?2 WHERE log_id = ?3 AND upper_index = ?4';
const TOUCH = 'UPDATE log_backfill SET updated_at = ?1 WHERE log_id = ?2 AND upper_index = ?3';
const ADD_TO_LEDGER = `INSERT INTO ops_ledger (day, r2_class_a, r2_class_b, d1_rows, killed) VALUES (?1, 0, ?2, ?3, 0)
ON CONFLICT (day) DO UPDATE SET r2_class_b = COALESCE(r2_class_b, 0) + excluded.r2_class_b, d1_rows = COALESCE(d1_rows, 0) + excluded.d1_rows`;

interface BackfillRow {
	log_id: string;
	kind: 'rfc6962' | 'static';
	url: string;
	next_index: number;
	upper_index: number;
}

export interface CatchupOptions {
	/** Clock for the expiry test, timestamps and the ledger day. Defaults to Date.now(). */
	now?: number;
	/** Outbound fetch. Defaults to the global fetch; tests inject a fake. */
	fetch?: typeof fetch;
	/** Overrides CATCHUP_MAX_FETCHES (and the env var). */
	maxFetches?: number;
	/** Overrides CATCHUP_PHASE_MS. */
	phaseMs?: number;
	/** How often a row's read re-reads the kill switches (default KILL_RECHECK_MS). */
	killRecheckMs?: number;
	fetchTimeoutMs?: number;
	/** Overrides FLUSH_ROWS. */
	flushRows?: number;
	/** Entries asked per get-entries page; defaults to RFC6962_PAGE, then to the size the log has been seen to serve. */
	pageSize?: number;
}

export interface CatchupSummary {
	killed: boolean;
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
	/** log_id -> error, for the rows that recorded one. */
	errors: Record<string, string>;
	/** log_id -> why its read ended early without an error. */
	deferred: Record<string, string>;
}

interface Work {
	row: BackfillRow;
	/** Nothing at or past this is read: upper_index, or for a static-ct log upper_index rounded down to a tile. */
	ceiling: number;
	/** Fetches this row may start before the run's counter reaches this. */
	fetchCap: number;
	next: number;
	/** The cursor as last written (the compare-and-set guard). */
	sentThrough: number;
	observations: ObservationSet;
	entriesSince: number;
	expiredSince: number;
	finished: boolean;
}

interface Run {
	fetch: typeof fetch;
	queue: Pick<Queue<ObservationBatch>, 'send'>;
	slot: <T>(task: () => Promise<T>) => Promise<T>;
	until: number;
	timeoutMs: number;
	flushRows: number;
	pageSize: number | undefined;
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
/** Ends a row's read after a failed send; the error is already recorded. */
class SendFailed extends Error {}
/** Ends a row's read: an overlapping run moved the cursor, so this run's work on the row is over. */
class Lost extends Error {}

/** logId -> entries per get-entries page the log has been seen to serve, when fewer than RFC6962_PAGE. */
const pageSizes = new Map<string, number>();

/** Forgets the learned page sizes (tests). */
export function resetCatchupMemo(): void {
	pageSizes.clear();
}

function rowsTouched(meta: { rows_read?: number; rows_written?: number } | undefined): number {
	return (meta?.rows_read ?? 0) + (meta?.rows_written ?? 0);
}

function held(work: Work): number {
	return work.observations.names.size + work.observations.siblings.size;
}

function canFetch(run: Run, work: Work): boolean {
	return !run.sendFailed && Date.now() < run.until && run.fetches < work.fetchCap;
}

/** GETs `url` through a header slot; a 429 is a Deferral, any other non-2xx an HttpError, a network failure names the URL. */
async function get<T>(run: Run, url: string, read: (response: Response) => Promise<T>): Promise<T> {
	const named = (error: unknown) => (error instanceof Deferral ? error : new Error(`${describeError(error)} (${url})`));
	let response: Response;
	try {
		response = await run.slot(() => {
			if (Date.now() >= run.until) throw new Deferral('read phase ended before this request had a slot');
			run.fetches++;
			return run.fetch(url, { headers: { 'user-agent': USER_AGENT }, signal: AbortSignal.timeout(run.timeoutMs) });
		});
	} catch (error) {
		throw named(error);
	}
	if (!response.ok) {
		await response.body?.cancel();
		if (response.status === 429) throw new Deferral(`rate limited: HTTP 429 from ${url}`);
		throw new HttpError(response.status, url);
	}
	try {
		return await read(response);
	} catch (error) {
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

/** The window's [start, end] ranges from the cursor; the last end is below the ceiling. */
function pageRanges(run: Run, work: Work): Array<[number, number]> {
	const size = run.pageSize ?? pageSizes.get(work.row.log_id) ?? RFC6962_PAGE;
	const count = Math.min(WINDOW, work.fetchCap - run.fetches);
	const ranges: Array<[number, number]> = [];
	for (let start = work.next; start < work.ceiling && ranges.length < count; start += size) {
		ranges.push([start, Math.min(start + size, work.ceiling) - 1]);
	}
	return ranges;
}

async function getEntries(run: Run, work: Work, start: number, end: number): Promise<unknown[]> {
	const url = `${work.row.url}ct/v1/get-entries?start=${start}&end=${end}`;
	const { entries } = await get(run, url, (response) => response.json<{ entries?: unknown }>());
	if (!Array.isArray(entries) || entries.length > end - start + 1) throw new Error(`get-entries ${start}-${end}: bad entries array`);
	return entries;
}

/** Up to WINDOW get-entries pages from the cursor, read in order; a short page ends the window (the pages after it start past a gap). */
async function readEntries(run: Run, work: Work): Promise<void> {
	const ranges = pageRanges(run, work);
	const pages = together(
		ranges.map(
			([start, end]) =>
				() =>
					getEntries(run, work, start, end),
		),
	);
	for (const [i, [start, end]] of ranges.entries()) {
		const entries = await pages[i]!;
		if (entries.length === 0) throw new Deferral(`get-entries ${start}-${end}: no entries served yet`);
		for (const entry of entries) {
			observeEntry(run, work, () => {
				const leafInput = (entry as { leaf_input?: unknown } | null)?.leaf_input;
				if (typeof leafInput !== 'string') throw new TypeError('entry has no leaf_input');
				return precertTbsFromLeafInput(leafInput);
			});
		}
		work.next = start + entries.length;
		if (entries.length < end - start + 1) {
			// A later page that did come back with entries means the short page was the log's own cap.
			const later = await pages[i + 1]?.then(
				(next) => next.length > 0,
				() => false,
			);
			if (later) pageSizes.set(work.row.log_id, entries.length);
			return;
		}
	}
}

async function getTile(run: Run, work: Work, tile: number): Promise<Array<Uint8Array | null>> {
	let body: ArrayBuffer;
	try {
		body = await get(run, `${work.row.url}tile/data/${tilePath(tile)}`, (response) => response.arrayBuffer());
	} catch (error) {
		if (error instanceof HttpError && error.status === 404) throw new Deferral(`data tile ${tile}: HTTP 404, not served yet`);
		throw error;
	}
	const entries = parseDataTile(new Uint8Array(body));
	if (entries.length !== TILE_WIDTH) throw new Error(`data tile ${tile}: ${entries.length} entries, expected ${TILE_WIDTH}`);
	return entries;
}

/** Up to WINDOW full data tiles from the one holding the cursor; entries before the cursor are skipped. The ceiling is tile-aligned. */
async function readTiles(run: Run, work: Work): Promise<void> {
	const first = Math.floor(work.next / TILE_WIDTH);
	const count = Math.min(WINDOW, work.ceiling / TILE_WIDTH - first, work.fetchCap - run.fetches);
	const tiles = Array.from({ length: count }, (_, i) => first + i);
	const bodies = together(tiles.map((tile) => () => getTile(run, work, tile)));
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

/** One row's read, to its share of the budget, the ceiling or the first failure. Progress up to the last good page stands. */
async function catchUpRow(run: Run, db: D1Database, work: Work): Promise<void> {
	let failure: unknown;
	try {
		while (work.next < work.ceiling && canFetch(run, work)) {
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
	if (failure instanceof Lost) return;
	if (!(failure instanceof SendFailed)) {
		try {
			await commit(run, db, work);
		} catch (error) {
			if (error instanceof Lost) return;
			failure ??= error;
		}
	}
	if (failure instanceof Deferral) {
		run.deferred[work.row.log_id] = failure.message;
		const result = await db.prepare(TOUCH).bind(new Date(run.now).toISOString(), work.row.log_id, work.row.upper_index).run();
		run.d1Rows += rowsTouched(result.meta);
	} else if (failure) {
		const message = describeError(failure);
		run.errors[work.row.log_id] = message;
		const result = await db
			.prepare(RECORD_ERROR)
			.bind(message, new Date(run.now).toISOString(), work.row.log_id, work.row.upper_index)
			.run();
		run.d1Rows += rowsTouched(result.meta);
	}
}

function newRun(env: Pick<Env, 'ENTRIES' | 'CERT_DETAILS'>, options: CatchupOptions, now: number): Run {
	return {
		fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
		queue: env.ENTRIES,
		slot: limiter(HEADER_SLOTS),
		until: Date.now() + (options.phaseMs ?? CATCHUP_PHASE_MS),
		timeoutMs: options.fetchTimeoutMs ?? FETCH_TIMEOUT_MS,
		flushRows: options.flushRows ?? FLUSH_ROWS,
		pageSize: options.pageSize,
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
		skips: { badNames: 0, noApex: 0 },
		errors: {},
		deferred: {},
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

function budgetFrom(value: string | undefined): number {
	const parsed = Number(value);
	return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : CATCHUP_MAX_FETCHES;
}

export async function runCatchup(
	env: Pick<Env, 'CURSORS' | 'ENTRIES' | 'CERT_DETAILS' | 'CATCHUP_MAX_FETCHES'>,
	options: CatchupOptions = {},
): Promise<CatchupSummary> {
	const now = options.now ?? Date.now();
	const run = newRun(env, options, now);
	const db = env.CURSORS;
	if (await isKilled(run, db)) return summarize(run, true, 0);

	const taken = await db.prepare(SELECT_ROWS).bind(CATCHUP_MAX_ROWS).all<BackfillRow>();
	run.d1Rows += rowsTouched(taken.meta);
	const share = Math.ceil((options.maxFetches ?? budgetFrom(env.CATCHUP_MAX_FETCHES)) / Math.max(1, taken.results.length));
	let rows = 0;
	for (const row of taken.results) {
		// Checked again inside each row's read (catchUpRow); once set, no further row starts.
		if (run.killed) break;
		rows++;
		const work: Work = {
			row,
			ceiling: row.kind === 'static' ? Math.floor(row.upper_index / TILE_WIDTH) * TILE_WIDTH : row.upper_index,
			fetchCap: run.fetches + share,
			next: row.next_index,
			sentThrough: row.next_index,
			observations: newObservationSet(),
			entriesSince: 0,
			expiredSince: 0,
			finished: false,
		};
		await catchUpRow(run, db, work);
		if (run.sendFailed) break;
	}

	const summary = summarize(run, run.killed, rows);
	await db.prepare(ADD_TO_LEDGER).bind(new Date(now).toISOString().slice(0, 10), summary.subrequests, summary.d1Rows).run();
	return summary;
}
