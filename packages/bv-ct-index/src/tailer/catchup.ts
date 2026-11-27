// SPDX-License-Identifier: BUSL-1.1
/**
 * The bounded catch-up reader: reads [lower, upper) of a CT log, apart from the forward tail (src/tailer/index.ts).
 *
 * The forward tail follows a log only while the Chrome log list calls it usable or qualified, so a log that turns
 * readonly is dropped with its backlog unread. A row of
 * `log_backfill` (migrations/0006_log_backfill.sql) names one range of one log with its own url and kind, so this
 * reader needs neither the log list nor the log's state, and it changes nothing the tail follows. Rows are inserted by
 * an operator; the migration seeds none.
 *
 * Shape: one row per invocation. Cloudflare lets an invocation have 6 connections waiting for response headers, and
 * a log serves 32 entries a page in 1-3 s, so one invocation reading two logs would have 3 slots each and fall far
 * short of the pace the work needs. CATCHUP_CRON (every 2 min) therefore only DISPATCHES (dispatchCatchup): one message
 * per claimable row on its OWN queue, `bv-ct-index-catchup` (binding CATCHUP, max_batch_size 1, max_retries 0,
 * max_concurrency 2), and each message runs runCatchup on its row in its own queue-consumer invocation, with its own 6
 * slots, its own subrequest budget and the whole of the caps below. It is a queue of its own because a run holds its
 * consumer invocation for about two minutes, and the forward tail's shard messages (on `bv-ct-index-tail`) are dropped
 * when 50 s old: they must never wait behind it. Without the CATCHUP binding the cron runs the first claimable row itself
 * (one row a run, the rows taking turns by updated_at); that is slower and is the fallback, not the design.
 *
 * Isolation from the tail: its own cron, queue and table, so the tail's compare-and-set on log_cursors is never contended
 * and nothing is written to log_cursors. What it shares is the ENTRIES queue and its indexer: its rows are ordinary
 * ObservationBatch messages.
 *
 * Files: this one (the run), catchup-paging.ts (constants, SQL, pure paging/lease/page-size helpers), catchup-types.ts,
 * catchup-dispatch.ts (the cron's side). All are re-exported from here.
 *
 * Limits this is sized against (Cloudflare docs): scheduled handlers and queue consumers 15 min wall
 * time (developers.cloudflare.com/workers/platform/limits/); CPU 30 s default, 300 s here via limits.cpu_ms; 10,000
 * subrequests per invocation on the paid plan (50 free); 6 simultaneous connections waiting for headers, more queue;
 * queue consumer 15 min wall, batch 100, 128 KB message, 5,000 messages/s per queue (queues/platform/limits/).
 *
 * One run of one row:
 * 1. Stop at once if either kill switch is set: ops_ledger.killed = 1 (the global one) or meta 'catchup_killed' = '1'.
 * 2. Claim the row: a compare-and-set on hold_until, which is the row's lease. A row another run holds, or one backing
 *    off after a deferral or error, is skipped, so a run still going when the next dispatch fires does not double the load.
 *    Every later write the run makes to the row, but the cursor's (which guards on next_index), is guarded on its own
 *    lease: a run that outlived its lease matches no row, changes nothing and stops quietly.
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
 * is started once one has failed, and the row is held off for CATCHUP_BACKOFF_MS from the failure, so a limited log is
 * not hammered.
 *
 * Page size: a short page's length is saved on the row (page_size) only after it was seen on LEARN_CONSECUTIVE consecutive
 * pages (4 under 8 entries), and a stored size is probed upward (one request for a full page at an aligned start) on every
 * run while it is under 32 and on one run in 30 otherwise.
 *
 * Kill switches are read at the start and every KILL_RECHECK_MS inside a row. A switch thrown mid-run is therefore seen
 * after up to KILL_RECHECK_MS plus one fetch timeout (the loop is awaiting the oldest page, at most CATCHUP_FETCH_TIMEOUT_MS
 * = 15 s), so up to about 20 s; requests already started finish, and none starts once the switch has been read.
 *
 * A static-ct log is read in full tiles only, so its ceiling is upper_index rounded down to a tile; the partial tile
 * above it is not read and the row says so in last_error when it completes.
 *
 * WORST CASE, set by the caps and not by luck (per row-run; a dispatch is CATCHUP_MAX_ROWS = 2 of them):
 *   entries   <= CATCHUP_MAX_ENTRIES (24,000) + one page less one: a first page on a cold start asks for RFC6962_PAGE
 *                (256), so <= 24,255 a row-run, <= 48,510 per dispatch, <= 24,255 a minute across both rows at the
 *                2-minute cadence (with a stored page size of 32: 24,031, 48,062 and 24,031);
 *   fetches   <= CATCHUP_MAX_FETCHES (800) a row-run, 1,600 per dispatch; with queue sends (one per 120 KB of
 *                observations, a few dozen), kill checks (one D1 batch per 5 s, at most 21) and D1 writes, a row-run stays
 *                under about 1,000 subrequests against the 10,000 limit;
 *   in flight <= CATCHUP_PAGES_IN_FLIGHT (6) requests per row, and never more than HEADER_SLOTS (6) waiting for headers
 *                per invocation. Two rows on the SAME log host (two ranges of one log) therefore mean up to
 *                2 x CATCHUP_PAGES_IN_FLIGHT requests in flight to that host, one per invocation. A short-page reset
 *                abandons the pages in flight (they still run to their end) and starts a new pipeline, so for a moment a
 *                row can have up to twice its limit in flight. Neither is capped here.
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
import {
	ADD_TO_LEDGER,
	ADVANCE,
	CATCHUP_BACKOFF_MS,
	CATCHUP_FETCH_TIMEOUT_MS,
	CATCHUP_KILL_KEY,
	CATCHUP_MAX_ENTRIES,
	CATCHUP_MAX_FETCHES,
	CATCHUP_MAX_ROWS,
	CATCHUP_PAGES_IN_FLIGHT,
	CATCHUP_PAGES_IN_FLIGHT_MAX,
	CATCHUP_PHASE_MS,
	CATCHUP_STALE_MS,
	CLAIM,
	KILL_RECHECK_MS,
	RECORD_ERROR,
	RELEASE,
	SELECT_CATCHUP_KILL,
	SELECT_KILLED,
	SELECT_ONE,
	SELECT_ROWS,
	SET_PAGE_SIZE,
	TOUCH,
	USER_AGENT,
	budgetFrom,
	isTimeout,
	leaseEnd,
	nextStreak,
	pageEnd,
	probeDue,
	probeRaises,
	probeStart,
	type ShortStreak,
} from './catchup-paging';
import { newObservationSet, newRows, observeCert, toBatches, type ObservationSet, type SkipCounts } from './observations';
import { parseTbsCertificate } from './x509';
import type { BackfillRow, CatchupOptions, CatchupRequest, CatchupSummary, RowStats } from './catchup-types';

export * from './catchup-paging';
export * from './catchup-dispatch';
export type * from './catchup-types';

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
	/** A write guarded on this run's lease matched no row: another run holds the row now, so this one stops quietly. */
	leaseLost: boolean;
	/** The short-page length seen on the latest consecutive short pages. */
	streak: ShortStreak | null;
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
	/** This run's lease on the row (the hold_until it set when it claimed it). */
	lease: string;
	/** Date.now() when the run began; the clock for measuring a back-off from the failure. */
	startedMs: number;
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
	return (
		!run.sendFailed &&
		!run.killed &&
		!work.leaseLost &&
		!work.halt &&
		Date.now() < run.until &&
		work.launches < work.fetchCap &&
		run.entries < work.entryCap
	);
}

/** Pages of `size` entries a tile window may start without the run's entries passing the row's cap by more than one page. */
function pagesWithinEntryCap(run: Run, work: Work, size: number): number {
	return Math.max(1, Math.ceil((work.entryCap - run.entries) / size));
}

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
				// A page of a discarded pipeline (after a short page) failing says nothing about the pages read from here on.
				if (page.generation === work.generation) work.halt = true;
			},
		);
		work.launches++;
		work.pending.push(page);
		queued += end - start + 1;
		running++;
		work.launchNext = end + 1;
	}
}

/**
 * Saves the page size a log serves on the row, so the next run starts aligned, and uses it for the rest of this run. The
 * write is guarded on this run's lease: matching no row means another run holds the row now, and this one stops quietly.
 * Best effort otherwise: a D1 failure only costs the next run a re-learn.
 */
async function savePageSize(run: Run, work: Work, size: number): Promise<void> {
	if (size < 1 || size > RFC6962_PAGE || size === work.pageSize) return;
	try {
		const result = await run.db.prepare(SET_PAGE_SIZE).bind(size, work.row.log_id, work.row.upper_index, run.lease).run();
		run.d1Rows += rowsTouched(result.meta);
		if ((result.meta?.changes ?? 0) === 0) {
			work.leaseLost = true;
			return;
		}
	} catch {
		// the size is still used for the rest of this run
	}
	work.pageSize = size;
}

/**
 * One request for a full page at an aligned start, to correct a stored page size that is too small (it can only have
 * come from a transient short page, or from an operator): raised when the log serves more than is stored. Due on every
 * run while the stored size is under PROBE_BELOW, and on one run in PROBE_EVERY_RUNS otherwise. Not for a fixed `pageSize` option.
 */
async function probePageSize(run: Run, work: Work): Promise<void> {
	const stored = work.row.page_size;
	if (work.row.kind !== 'rfc6962' || run.pageSize !== undefined || stored === null || !probeDue(stored, run.now)) return;
	const start = probeStart(work.next, work.ceiling);
	if (start === null || !canFetch(run, work)) return;
	work.launches++;
	const entries = await getEntries(run, work, start, Math.min(start + RFC6962_PAGE, work.ceiling) - 1);
	if (probeRaises(stored, start, entries.length)) await savePageSize(run, work, entries.length);
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
		work.streak = null;
		fillPages(run, work);
	} else {
		// A later page that did come back with entries means the short page was the log's own cap, not the end of the log.
		// The cap is the length of a short page that starts on a multiple of it, from this page or the next: a page cut
		// at a boundary starts off one and teaches nothing.
		// The pipeline is reset first, before anything is awaited: the pages that end meanwhile are of a discarded generation
		// and start nothing, so no request is launched from the old cursor.
		const later = work.pending[0];
		work.pending = [];
		work.generation++;
		work.launchNext = work.next;
		// A discarded page that failed before this reset had already set halt; it says nothing about the pages read from here.
		work.halt = false;
		const laterEntries = later
			? await later.promise.then(
					(list) => list,
					() => [] as unknown[],
				)
			: [];
		const shorts: Array<[number, number]> = [[start, entries.length]];
		if (later && laterEntries.length < later.end - later.start + 1) shorts.push([later.start, laterEntries.length]);
		const taught = laterEntries.length > 0 ? shorts.find(([from, length]) => length > 0 && from % length === 0) : undefined;
		// A short length is saved only once seen on consecutive pages (nextStreak): one transient short page must not stick.
		if (taught) {
			const lesson = nextStreak(work.streak, taught[1]);
			work.streak = lesson.streak;
			if (lesson.learn) await savePageSize(run, work, taught[1]);
		} else {
			work.streak = null;
		}
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
	const count = Math.min(
		run.pagesInFlight,
		work.ceiling / TILE_WIDTH - first,
		work.fetchCap - work.launches,
		pagesWithinEntryCap(run, work, TILE_WIDTH),
	);
	const tiles = Array.from({ length: count }, (_, i) => first + i);
	work.launches += tiles.length;
	const bodies = together(
		tiles.map(
			(tile) => () =>
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
	let failedAt = 0;
	try {
		await probePageSize(run, work);
		while (work.next < work.ceiling && (work.pending.length > 0 || canFetch(run, work))) {
			// A switch thrown mid-row stops the read within killRecheckMs (plus up to one fetch timeout while the oldest page is
			// awaited); isKilled sets run.killed in the same tick it reads the switch, so no request starts after that.
			if (Date.now() - run.killCheckedAt >= run.killRecheckMs && (await isKilled(run, db))) break;
			if (work.leaseLost) break;
			await (work.row.kind === 'static' ? readTiles(run, work) : readEntries(run, work));
			if (held(work) >= run.flushRows) await commit(run, db, work);
		}
	} catch (error) {
		failure = error;
		failedAt = Date.now();
	}
	work.closed = true;
	if (failure instanceof Lost || work.leaseLost) return;
	if (!(failure instanceof SendFailed)) {
		try {
			await commit(run, db, work);
		} catch (error) {
			if (error instanceof Lost) return;
			failure ??= error;
			failedAt ||= Date.now();
		}
	}
	if (failure instanceof PhaseEnded) failure = undefined;
	// The back-off runs from the failure, not from the start of a run that may have lasted two minutes.
	const holdUntil = new Date(run.now + (failedAt - run.startedMs) + CATCHUP_BACKOFF_MS).toISOString();
	const at = new Date(run.now).toISOString();
	const { log_id: logId, upper_index: upper } = work.row;
	if (failure instanceof Deferral) {
		const result = await db.prepare(TOUCH).bind(at, logId, upper, holdUntil, run.lease).run();
		run.d1Rows += rowsTouched(result.meta);
		// Matching no row means the lease was lost: another run owns the row and this one says nothing about it.
		if ((result.meta?.changes ?? 0) === 0) return;
		if (!(failure instanceof RateLimited)) work.stats.deferrals++;
		run.deferred[logId] = failure.message;
	} else if (failure) {
		const message = describeError(failure);
		const result = await db.prepare(RECORD_ERROR).bind(message, at, logId, upper, holdUntil, run.lease).run();
		run.d1Rows += rowsTouched(result.meta);
		if ((result.meta?.changes ?? 0) === 0) return;
		run.errors[logId] = message;
	}
}

function newRun(
	env: Pick<Env, 'ENTRIES' | 'CERT_DETAILS' | 'CATCHUP_PAGES_IN_FLIGHT'>,
	db: D1Database,
	options: CatchupOptions,
	now: number,
): Run {
	const timeoutMs = options.fetchTimeoutMs ?? CATCHUP_FETCH_TIMEOUT_MS;
	return {
		db,
		lease: leaseEnd(now, options.phaseMs ?? CATCHUP_PHASE_MS, timeoutMs),
		startedMs: Date.now(),
		fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
		queue: env.ENTRIES,
		slot: limiter(HEADER_SLOTS),
		until: Date.now() + (options.phaseMs ?? CATCHUP_PHASE_MS),
		timeoutMs,
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
	const killed = (ledger?.results.length ?? 0) > 0 || own?.results[0]?.v === '1';
	// Set in the same tick the switch is read: canFetch and fillPages look at it, so no request starts after this returns.
	if (killed) run.killed = true;
	return killed;
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

	const lease = run.lease;
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
			leaseLost: false,
			streak: null,
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

/** Runs one dispatch message; a message older than CATCHUP_STALE_MS is dropped (the next dispatch sent a fresh one). */
export async function runCatchupMessage(
	env: Parameters<typeof runCatchup>[0],
	body: CatchupRequest,
	options: CatchupOptions = {},
): Promise<CatchupSummary | { skipped: 'stale' }> {
	if ((options.now ?? Date.now()) - body.scheduledTime > CATCHUP_STALE_MS) return { skipped: 'stale' };
	return runCatchup(env, { ...options, only: { logId: body.logId, upperIndex: body.upperIndex } });
}
