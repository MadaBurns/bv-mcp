// SPDX-License-Identifier: BUSL-1.1
/**
 * The bv-ct-index tailer (US-12 contract v2, wave 2a). One run per `* * * * *` cron tick, either over every
 * log or, fanned out by fanout.ts, over one shard of them:
 *
 * 1. Stop at once if the ops ledger kill switch is set.
 * 2. Load the Chrome CT log list (memoized for at most an hour) and the per-log cursors.
 * 3. Fetch phase: LANES lanes visit the logs in an order that rotates every tick. A visit reads the log's
 *    head, then RFC 6962 get-entries pages or full static-ct data tiles from the cursor, WINDOW of them at
 *    once, at most MAX_ENTRIES_PER_VISIT entries before the log goes to the back of the queue. Every fetch
 *    waits for one of HEADER_SLOTS slots until its response headers arrive (the platform's own limit), and its
 *    timeout starts when it gets the slot. Only precert entries are parsed; x509 entries are skipped (contract
 *    v2). A log seen for the first time starts at its current tree size (forward-only). No new fetch starts
 *    after the fetch budget.
 * 4. Sends: a log's held rows are sent to ENTRIES as ObservationBatch messages once they reach FLUSH_ROWS,
 *    and the rest after the fetch phase, log by log in the same order. Rows already sent this tick by another
 *    log are dropped. A log's cursor advances only to the entry its last resolved send covered; the first
 *    failed send stops the tick, so the logs after it keep their cursors.
 * 5. One D1 batch writes the cursors (compare-and-set on the old next_index, so an overlapping tick cannot
 *    move one backwards) and the per-log errors, then the day's ops_ledger row is incremented.
 *
 * A fetch or parse error in one log is recorded in its last_error / last_error_at and never fails the other
 * logs. An entry whose leaf or certificate does not parse is skipped and counted, so it cannot wedge a log.
 *
 * Three answers are not errors but a deferral: the visit ends, progress so far stands, nothing goes to
 * last_error, and the next tick retries from the cursor (TickSummary.deferred names them). They are an empty
 * get-entries page (a log serves a range from a replica that does not hold it yet: Sectigo answers 200 with
 * no entries), a 404 for a data tile the checkpoint covers (a CDN serves a 404 it cached before the tile was
 * published: TrustAsia Luoshu, for about a minute), and an HTTP 429 (TrustAsia, with no Retry-After).
 *
 * Throughput (measured 2026-10-22): the logs grew by about 212k entries a minute while a
 * single six-lane tick read about 22k, so the 2027h1 shards fell 13M to 68M entries behind. Google's RFC 6962
 * logs serve 32 entries per get-entries page whatever is asked for, and a 20 s tick visited each hot log about
 * once. Windows, more lanes, the longer phase and the fan-out are the fix.
 */

import type { Env } from '../index';
import { limiter } from '../indexer/blocks';
import type { ObservationBatch, RunRow } from '../types';
import {
	LOG_LIST_URL,
	TILE_WIDTH,
	checkpointTreeSize,
	parseDataTile,
	precertTbsFromLeafInput,
	selectLogs,
	tilePath,
	type TailedLog,
} from './ct';
import { newObservationSet, newRows, observeCert, toBatches, type ObservationSet, type SkipCounts } from './observations';
import { parseTbsCertificate } from './x509';

export const LOG_LIST_TTL_MS = 60 * 60 * 1000;
/** Logs visited at once. More than HEADER_SLOTS, so one log's slow body read does not hold a slot it no longer needs. */
export const LANES = 24;
/**
 * Fetches and queue sends waiting for response headers at once. Workers allow six per invocation; since 2026-04-09 a
 * connection stops counting once its headers arrive, so the body is read outside the slot.
 */
export const HEADER_SLOTS = 6;
/** Pages or tiles of one log requested together in a visit. */
export const WINDOW = 4;
/** No new fetch starts after this. With FETCH_TIMEOUT_MS the fetch phase ends by ~40 s, before the next minute's tick. */
export const FETCH_PHASE_MS = 35_000;
export const FETCH_TIMEOUT_MS = 5_000;
/** CT-log fetches per tick: inside the 10,000 subrequests per invocation, leaving room for queue sends and D1. */
export const MAX_LOG_FETCHES = 3_000;
/** The fetch phase stops early once this many observations are held: a guard, as FLUSH_ROWS keeps the heap far below it. */
export const MAX_TICK_OBSERVATIONS = 40_000;
/** Entries one visit may read before its log goes to the back of the queue, so one deep backlog cannot starve the rest. */
export const MAX_ENTRIES_PER_VISIT = 4_096;
/** get-entries asks for this many entries; logs return fewer (measured 3 to 246 per page, and 32 on Google's logs). */
export const RFC6962_PAGE = 256;
/**
 * A log's held rows are sent once they reach this many. A held row costs about 400 B of heap (measured in V8), and the
 * fan-out's shards may share one 128 MB isolate, so a shard keeps its rows and its dedup memory to about 12 MB.
 */
export const FLUSH_ROWS = 2_000;
/** Rows remembered for the cross-log dedup. Past this the memory is cleared: that sends more rows, never fewer. */
export const MAX_EMITTED = 15_000;
const MAX_ERROR_LENGTH = 500;
const USER_AGENT = 'bv-ct-index (+https://blackveilsecurity.com)';

const SELECT_KILLED = 'SELECT 1 AS killed FROM ops_ledger WHERE killed = 1 LIMIT 1';
const SELECT_CURSORS = 'SELECT log_id, next_index FROM log_cursors';
const SELECT_BACKLOG = 'SELECT log_id, tree_size - next_index AS behind FROM log_cursors';
const UPSERT_CURSOR = `INSERT INTO log_cursors (log_id, kind, url, next_index, tree_size, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
ON CONFLICT (log_id) DO UPDATE SET kind = excluded.kind, url = excluded.url, next_index = excluded.next_index,
	tree_size = excluded.tree_size, updated_at = excluded.updated_at
WHERE log_cursors.next_index IS ?7`;
const RECORD_ERROR = `INSERT INTO log_cursors (log_id, kind, url, last_error, last_error_at) VALUES (?1, ?2, ?3, ?4, ?5)
ON CONFLICT (log_id) DO UPDATE SET last_error = excluded.last_error, last_error_at = excluded.last_error_at`;
const ADD_TO_LEDGER = `INSERT INTO ops_ledger (day, r2_class_a, r2_class_b, d1_rows, killed) VALUES (?1, 0, ?2, ?3, 0)
ON CONFLICT (day) DO UPDATE SET r2_class_b = COALESCE(r2_class_b, 0) + excluded.r2_class_b, d1_rows = COALESCE(d1_rows, 0) + excluded.d1_rows`;

export interface TailerOptions {
	/** The cron controller's scheduledTime; picks this tick's rotation of the log order. */
	scheduledTime: number;
	/** Clock for the log-list filter, timestamps and the ledger day. Defaults to Date.now(). */
	now?: number;
	/** Outbound fetch. Defaults to the global fetch; tests inject a fake. */
	fetch?: typeof fetch;
	/** Overrides FETCH_PHASE_MS. */
	fetchPhaseMs?: number;
	/** Overrides FETCH_TIMEOUT_MS. */
	fetchTimeoutMs?: number;
	/** Overrides FLUSH_ROWS. */
	flushRows?: number;
	/** Tail only these logs (one shard of a fan-out). Defaults to every tailed log. */
	logIds?: ReadonlySet<string>;
}

export interface TickSummary {
	killed: boolean;
	logs: number;
	/** Cursors written this tick (new logs included). */
	cursorsWritten: number;
	entries: number;
	precerts: number;
	/** Entries whose leaf or TBSCertificate did not parse. */
	badEntries: number;
	badNames: number;
	noApex: number;
	names: number;
	siblings: number;
	batches: number;
	/** Subrequests: CT-log and log-list fetches plus queue sends. */
	subrequests: number;
	d1Rows: number;
	/** logId -> error, for the logs that recorded one. */
	errors: Record<string, string>;
	/** logId -> why its visit ended early without an error (not served yet, rate limited); not written to D1. */
	deferred: Record<string, string>;
}

interface LogState {
	log: TailedLog;
	/** next_index as read at tick start: null for a new or never-initialized log. The compare-and-set guard. */
	cursorAt: number | null;
	/** The next leaf index to read; null until a new log's head is known. */
	next: number | null;
	/** The entry the sent rows cover up to: the cursor this tick writes. */
	sentThrough: number | null;
	treeSize: number | null;
	observations: ObservationSet;
	error: string | null;
	deferred: string | null;
}

interface Tick {
	fetch: typeof fetch;
	queue: Pick<Queue<unknown>, 'send'>;
	slot: <T>(task: () => Promise<T>) => Promise<T>;
	fetchUntil: number;
	fetchTimeoutMs: number;
	flushRows: number;
	/** CERT_DETAILS is 'on': name rows carry the certificate details (see the Env field). */
	certDetails: boolean;
	states: LogState[];
	/** Rows sent this tick, by key: the cross-log dedup (observations.ts `newRows`). */
	emitted: Map<string, RunRow>;
	sendFailed: boolean;
	fetches: number;
	sends: number;
	d1Rows: number;
	entries: number;
	precerts: number;
	badEntries: number;
	names: number;
	siblings: number;
	batches: number;
	skips: SkipCounts;
}

/** A non-2xx answer other than 429. */
class HttpError extends Error {
	constructor(
		readonly status: number,
		url: string,
	) {
		super(`HTTP ${status} from ${url}`);
	}
}

/** Ends a visit without an error: the log has not served the next entries yet, or asked us to slow down. */
class Deferral extends Error {}

/** Ends a visit after a failed send; the error is already on the log. */
class SendFailed extends Error {}

let logListMemo: { fetchedAt: number; logs: TailedLog[] } | undefined;
/** logId -> the entries per get-entries page a log has been seen to serve, when fewer than RFC6962_PAGE. */
const pageSizes = new Map<string, number>();

/** Forgets the memoized log list and the learned page sizes (tests). */
export function resetLogListMemo(): void {
	logListMemo = undefined;
	pageSizes.clear();
}

function describe(error: unknown): string {
	return (error instanceof Error ? error.message : String(error)).slice(0, MAX_ERROR_LENGTH);
}

function rowsTouched(meta: { rows_read?: number; rows_written?: number } | undefined): number {
	return (meta?.rows_read ?? 0) + (meta?.rows_written ?? 0);
}

function held(state: LogState): number {
	return state.observations.names.size + state.observations.siblings.size;
}

function canFetch(tick: Tick): boolean {
	if (tick.sendFailed || Date.now() >= tick.fetchUntil || tick.fetches >= MAX_LOG_FETCHES) return false;
	let total = 0;
	for (const state of tick.states) total += held(state);
	return total < MAX_TICK_OBSERVATIONS;
}

/**
 * GETs `url` and reads its body with `read`. The request waits for a header slot; its timeout starts with the slot
 * and covers the body, and a request that gets its slot after the fetch phase ended is not sent (a Deferral), so
 * queued requests cannot run into the next tick. A 429 is a Deferral, any other non-2xx an HttpError; a network
 * failure or timeout names the URL (the bare abort message does not).
 */
async function get<T>(tick: Tick, url: string, read: (response: Response) => Promise<T>): Promise<T> {
	const named = (error: unknown) => (error instanceof Deferral ? error : new Error(`${describe(error)} (${url})`));
	let response: Response;
	try {
		response = await tick.slot(() => {
			if (Date.now() >= tick.fetchUntil) throw new Deferral('fetch phase ended before this request had a slot');
			tick.fetches++;
			return tick.fetch(url, { headers: { 'user-agent': USER_AGENT }, signal: AbortSignal.timeout(tick.fetchTimeoutMs) });
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

async function loadLogs(tick: Tick, now: number): Promise<TailedLog[]> {
	if (logListMemo && now - logListMemo.fetchedAt < LOG_LIST_TTL_MS) return logListMemo.logs;
	const logs = selectLogs(await get(tick, LOG_LIST_URL, (response) => response.json()), now);
	logListMemo = { fetchedAt: now, logs };
	return logs;
}

async function readHead(tick: Tick, log: TailedLog): Promise<number> {
	if (log.kind === 'static') return checkpointTreeSize(await get(tick, `${log.url}checkpoint`, (response) => response.text()));
	const { tree_size: size } = await get(tick, `${log.url}ct/v1/get-sth`, (response) => response.json<{ tree_size?: unknown }>());
	if (typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0)
		throw new Error(`get-sth: bad tree_size ${JSON.stringify(size)}`);
	return size;
}

/** Parses one entry; a precert's names go into the log's observations. Never throws. */
function observeEntry(tick: Tick, state: LogState, readTbs: () => Uint8Array | null): void {
	tick.entries++;
	try {
		const tbs = readTbs();
		if (!tbs) return;
		tick.precerts++;
		observeCert(parseTbsCertificate(tbs), state.observations, tick.skips, tick.certDetails);
	} catch {
		tick.badEntries++;
	}
}

/** Starts every request at once; a rejection is still seen by whoever awaits it, but never goes unhandled. */
function together<T>(requests: Array<() => Promise<T>>): Array<Promise<T>> {
	const pending = requests.map((request) => request());
	for (const promise of pending) promise.catch(() => undefined);
	return pending;
}

function fetchesLeft(tick: Tick): number {
	return Math.max(1, MAX_LOG_FETCHES - tick.fetches);
}

async function getEntries(tick: Tick, state: LogState, start: number, end: number): Promise<unknown[]> {
	const url = `${state.log.url}ct/v1/get-entries?start=${start}&end=${end}`;
	const { entries } = await get(tick, url, (response) => response.json<{ entries?: unknown }>());
	if (!Array.isArray(entries) || entries.length > end - start + 1) throw new Error(`get-entries ${start}-${end}: bad entries array`);
	return entries;
}

/**
 * Up to WINDOW get-entries pages from the cursor, requested together and read in order. The cursor moves past
 * whatever each page returned. A short page ends the window: the pages after it start past a gap. When a later
 * page of the window did come back with entries, the short page was the log's own cap rather than a replica that
 * has not caught up, so later windows ask for that many per page.
 */
async function readEntries(tick: Tick, state: LogState): Promise<void> {
	const ranges = pageRanges(tick, state);
	const pages = together(
		ranges.map(
			([start, end]) =>
				() =>
					getEntries(tick, state, start, end),
		),
	);
	for (const [i, [start, end]] of ranges.entries()) {
		const entries = await pages[i]!;
		observePage(tick, state, entries, start, end);
		if (entries.length < end - start + 1) {
			if (await hasEntries(pages[i + 1])) pageSizes.set(state.log.logId, entries.length);
			return;
		}
	}
}

/** The window's [start, end] ranges from the cursor, at the log's learned page size. */
function pageRanges(tick: Tick, state: LogState): Array<[number, number]> {
	const size = pageSizes.get(state.log.logId) ?? RFC6962_PAGE;
	const count = Math.min(WINDOW, fetchesLeft(tick));
	const ranges: Array<[number, number]> = [];
	for (let start = state.next!; start < state.treeSize! && ranges.length < count; start += size) {
		ranges.push([start, Math.min(start + size, state.treeSize!) - 1]);
	}
	return ranges;
}

/** One page's entries into the log's observations; the cursor moves past them. */
function observePage(tick: Tick, state: LogState, entries: unknown[], start: number, end: number): void {
	// Fewer entries than asked is normal (RFC 6962 section 4.6); none at all means the replica that answered
	// does not hold the range yet, although the tree head covers it.
	if (entries.length === 0) throw new Deferral(`get-entries ${start}-${end}: no entries served yet`);
	for (const entry of entries) {
		observeEntry(tick, state, () => {
			const leafInput = (entry as { leaf_input?: unknown } | null)?.leaf_input;
			if (typeof leafInput !== 'string') throw new TypeError('entry has no leaf_input');
			return precertTbsFromLeafInput(leafInput);
		});
	}
	state.next = start + entries.length;
}

/** Whether a page of the window came back with entries; a missing or failed page did not. */
async function hasEntries(page: Promise<unknown[]> | undefined): Promise<boolean> {
	if (!page) return false;
	return page.then(
		(entries) => entries.length > 0,
		() => false,
	);
}

async function getTile(tick: Tick, state: LogState, tile: number): Promise<Array<Uint8Array | null>> {
	let body: ArrayBuffer;
	try {
		body = await get(tick, `${state.log.url}tile/data/${tilePath(tile)}`, (response) => response.arrayBuffer());
	} catch (error) {
		// The checkpoint covers this tile, so a 404 is a CDN replaying one it cached before the tile was published.
		if (error instanceof HttpError && error.status === 404) throw new Deferral(`data tile ${tile}: HTTP 404, not served yet`);
		throw error;
	}
	const entries = parseDataTile(new Uint8Array(body));
	if (entries.length !== TILE_WIDTH) throw new Error(`data tile ${tile}: ${entries.length} entries, expected ${TILE_WIDTH}`);
	return entries;
}

/**
 * Up to WINDOW full data tiles from the one holding the cursor, requested together and read in order; entries
 * before the cursor (a new log's start) are skipped. `end` is tile-aligned.
 */
async function readTiles(tick: Tick, state: LogState, end: number): Promise<void> {
	const first = Math.floor(state.next! / TILE_WIDTH);
	const count = Math.min(WINDOW, end / TILE_WIDTH - first, fetchesLeft(tick));
	const tiles = Array.from({ length: count }, (_, i) => first + i);
	const bodies = together(tiles.map((tile) => () => getTile(tick, state, tile)));
	for (const [i, tile] of tiles.entries()) {
		const entries = await bodies[i]!;
		for (let k = state.next! - tile * TILE_WIDTH; k < TILE_WIDTH; k++) observeEntry(tick, state, () => entries[k] ?? null);
		state.next = (tile + 1) * TILE_WIDTH;
	}
}

/**
 * The dedup memory one flush works against: reads see the rows already sent this tick, writes stay here until this
 * flush's own sends resolve. So a log never drops a row on the strength of another log's send that is still in flight
 * and may yet fail (two logs in flight may both send a row; the merge makes that harmless).
 */
class StagedRows extends Map<string, RunRow> {
	constructor(private readonly sent: ReadonlyMap<string, RunRow>) {
		super();
	}
	override get(key: string): RunRow | undefined {
		return super.get(key) ?? this.sent.get(key);
	}
}

/** Sends the batches together; a failure is recorded on the log and stops the tick. */
async function sendAll(tick: Tick, state: LogState, batches: readonly ObservationBatch[]): Promise<void> {
	try {
		await Promise.all(
			batches.map((batch) => {
				tick.sends++;
				return tick.slot(() => tick.queue.send(batch, { contentType: 'json' }));
			}),
		);
	} catch (error) {
		state.error = `queue send: ${describe(error)}`;
		tick.sendFailed = true;
		throw new SendFailed(state.error);
	}
}

/**
 * Sends a log's held rows, minus those another log's resolved sends already covered this tick, and moves its
 * sentThrough to the entry they cover. A failure is recorded on the log and stops the tick.
 */
async function flush(tick: Tick, state: LogState): Promise<void> {
	if (tick.sendFailed || state.next === state.sentThrough) return;
	if (tick.emitted.size > MAX_EMITTED) tick.emitted.clear();
	const through = state.next!;
	const staged = new StagedRows(tick.emitted);
	const rows = newRows(state.observations, staged);
	const batches = toBatches(state.log.logId, state.sentThrough!, through, rows);
	state.observations = newObservationSet();
	await sendAll(tick, state, batches);
	for (const [key, row] of staged) tick.emitted.set(key, row);
	tick.names += rows.names.length;
	tick.siblings += rows.siblings.length;
	tick.batches += batches.length;
	state.sentThrough = through;
}

/**
 * Reads a log's head on its first visit of the tick. Returns false for a log seen for the first time: it starts at
 * its current tree size (forward-only) and has nothing to read yet.
 */
async function readHeadOnce(tick: Tick, state: LogState): Promise<boolean> {
	if (state.treeSize !== null) return true;
	state.treeSize = await readHead(tick, state.log);
	if (state.next !== null) return true;
	state.next = state.sentThrough = state.treeSize;
	return false;
}

/** The entry a log can be read up to: a static-ct log in full tiles only, its partial tail waiting until the tile fills. */
function readableEnd(state: LogState): number {
	return state.log.kind === 'static' ? Math.floor(state.treeSize! / TILE_WIDTH) * TILE_WIDTH : state.treeSize!;
}

/** One visit to a log. Returns true when entries remain and the log should be visited again this tick. */
async function visit(tick: Tick, state: LogState): Promise<boolean> {
	if (!(await readHeadOnce(tick, state))) return false;
	const end = readableEnd(state);
	for (let read = 0; state.next! < end && read < MAX_ENTRIES_PER_VISIT;) {
		if (!canFetch(tick)) return false;
		const before = state.next!;
		await (state.log.kind === 'static' ? readTiles(tick, state, end) : readEntries(tick, state));
		read += state.next! - before;
		if (held(state) >= tick.flushRows) await flush(tick, state);
	}
	return state.next! < end;
}

/** Why a visit ended early. Progress up to the last complete page or tile stands; the cursor still advances to it. */
function recordVisitFailure(state: LogState, error: unknown): void {
	if (error instanceof Deferral) state.deferred = error.message;
	else if (!(error instanceof SendFailed)) state.error = describe(error); // a failed send is already on the log
}

async function fetchPhase(tick: Tick, order: LogState[]): Promise<void> {
	const queue = [...order];
	const lane = async () => {
		while (canFetch(tick)) {
			const state = queue.shift();
			if (!state) return;
			try {
				if (await visit(tick, state)) queue.push(state);
			} catch (error) {
				recordVisitFailure(state, error);
			}
		}
	};
	await Promise.all(Array.from({ length: LANES }, lane));
}

/** Sends what each log still holds, log by log in the tick's order; the first failure stops it. */
async function sendPhase(tick: Tick, order: LogState[]): Promise<void> {
	for (const state of order) {
		if (state.treeSize === null) continue; // head never read: nothing to send
		try {
			await flush(tick, state);
		} catch {
			return;
		}
	}
}

function summarize(tick: Tick, killed: boolean, cursorsWritten: number): TickSummary {
	const errors: Record<string, string> = {};
	const deferred: Record<string, string> = {};
	for (const state of tick.states) {
		if (state.error) errors[state.log.logId] = state.error;
		if (state.deferred) deferred[state.log.logId] = state.deferred;
	}
	return {
		killed,
		logs: tick.states.length,
		cursorsWritten,
		entries: tick.entries,
		precerts: tick.precerts,
		badEntries: tick.badEntries,
		badNames: tick.skips.badNames,
		noApex: tick.skips.noApex,
		names: tick.names,
		siblings: tick.siblings,
		batches: tick.batches,
		subrequests: tick.fetches + tick.sends,
		d1Rows: tick.d1Rows,
		errors,
		deferred,
	};
}

function newTick(env: Pick<Env, 'ENTRIES' | 'CERT_DETAILS'>, options: Omit<TailerOptions, 'scheduledTime' | 'now' | 'logIds'>): Tick {
	return {
		fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
		queue: env.ENTRIES,
		slot: limiter(HEADER_SLOTS),
		fetchUntil: Date.now() + (options.fetchPhaseMs ?? FETCH_PHASE_MS),
		fetchTimeoutMs: options.fetchTimeoutMs ?? FETCH_TIMEOUT_MS,
		flushRows: options.flushRows ?? FLUSH_ROWS,
		certDetails: env.CERT_DETAILS === 'on',
		states: [],
		emitted: new Map(),
		sendFailed: false,
		fetches: 0,
		sends: 0,
		d1Rows: 0,
		entries: 0,
		precerts: 0,
		badEntries: 0,
		names: 0,
		siblings: 0,
		batches: 0,
		skips: { badNames: 0, noApex: 0 },
	};
}

async function isKilled(tick: Tick, db: D1Database): Promise<boolean> {
	const killed = await db.prepare(SELECT_KILLED).all();
	tick.d1Rows += rowsTouched(killed.meta);
	return killed.results.length > 0;
}

async function addToLedger(db: D1Database, now: number, subrequests: number, d1Rows: number): Promise<void> {
	await db.prepare(ADD_TO_LEDGER).bind(new Date(now).toISOString().slice(0, 10), subrequests, d1Rows).run();
}

export async function runTailer(env: Pick<Env, 'CURSORS' | 'ENTRIES' | 'CERT_DETAILS'>, options: TailerOptions): Promise<TickSummary> {
	const now = options.now ?? Date.now();
	const tick = newTick(env, options);
	const db = env.CURSORS;

	if (await isKilled(tick, db)) return summarize(tick, true, 0);

	const logs = (await loadLogs(tick, now)).filter((log) => !options.logIds || options.logIds.has(log.logId));
	const cursors = await db.prepare(SELECT_CURSORS).all<{ log_id: string; next_index: number | null }>();
	tick.d1Rows += rowsTouched(cursors.meta);
	const cursorAt = new Map(cursors.results.map((row) => [row.log_id, row.next_index]));
	const offset = logs.length > 0 ? Math.floor(options.scheduledTime / 60_000) % logs.length : 0;
	tick.states = [...logs.slice(offset), ...logs.slice(0, offset)].map((log) => {
		const at = cursorAt.get(log.logId) ?? null;
		return {
			log,
			cursorAt: at,
			next: at,
			sentThrough: at,
			treeSize: null,
			observations: newObservationSet(),
			error: null,
			deferred: null,
		};
	});

	await fetchPhase(tick, tick.states);
	await sendPhase(tick, tick.states);

	const at = new Date(now).toISOString();
	const writable = tick.states.filter((s) => s.treeSize !== null);
	const statements = [
		...writable.map((s) => db.prepare(UPSERT_CURSOR).bind(s.log.logId, s.log.kind, s.log.url, s.sentThrough, s.treeSize, at, s.cursorAt)),
		...tick.states.filter((s) => s.error).map((s) => db.prepare(RECORD_ERROR).bind(s.log.logId, s.log.kind, s.log.url, s.error, at)),
	];
	for (const result of statements.length > 0 ? await db.batch(statements) : []) tick.d1Rows += rowsTouched(result.meta);
	const summary = summarize(tick, false, writable.length);
	await addToLedger(db, now, summary.subrequests, summary.d1Rows);
	return summary;
}

export interface PlanInputs {
	killed: boolean;
	/** The tailed logs' ids, from the memoized log list. */
	logIds: string[];
	/** logId -> entries its head was ahead of its cursor at its last write (never negative); absent for a new log. */
	behind: Map<string, number>;
}

/**
 * What the fan-out (fanout.ts) plans a tick from: the kill switch, the tailed logs and how far each is behind. Its
 * log-list fetch and D1 reads go to the ops ledger like a tick's.
 */
export async function loadPlanInputs(
	env: Pick<Env, 'CURSORS' | 'ENTRIES' | 'CERT_DETAILS'>,
	options: { now?: number; fetch?: typeof fetch } = {},
): Promise<PlanInputs> {
	const now = options.now ?? Date.now();
	const tick = newTick(env, options);
	const db = env.CURSORS;
	if (await isKilled(tick, db)) return { killed: true, logIds: [], behind: new Map() };

	const logIds = (await loadLogs(tick, now)).map((log) => log.logId);
	const tailed = new Set(logIds);
	const rows = await db.prepare(SELECT_BACKLOG).all<{ log_id: string; behind: number | null }>();
	tick.d1Rows += rowsTouched(rows.meta);
	await addToLedger(db, now, tick.fetches, tick.d1Rows);
	const behind = new Map(rows.results.filter((row) => tailed.has(row.log_id)).map((row) => [row.log_id, Math.max(0, row.behind ?? 0)]));
	return { killed: false, logIds, behind };
}

export { describe as describeError };
