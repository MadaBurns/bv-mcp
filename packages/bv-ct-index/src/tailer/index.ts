// SPDX-License-Identifier: BUSL-1.1
/**
 * The bv-ct-index tailer (US-12 contract v2, wave 2a). One run per `* * * * *` cron tick:
 *
 * 1. Stop at once if the ops ledger kill switch is set.
 * 2. Load the Chrome CT log list (memoized for at most an hour) and the per-log cursors.
 * 3. Fetch phase: six lanes (the per-invocation connection limit) visit the logs in an order that rotates
 *    every tick. A visit reads the log's head, then RFC 6962 get-entries pages or full static-ct data tiles
 *    from the cursor, at most MAX_ENTRIES_PER_VISIT entries before the log goes to the back of the queue.
 *    Only precert entries are parsed; x509 entries are skipped (contract v2). A log seen for the first time
 *    starts at its current tree size (forward-only). No new fetch starts after the fetch budget.
 * 4. Send phase: log by log in the same order, rows already covered by an earlier log this tick are dropped
 *    and the rest are sent to ENTRIES as ObservationBatch messages. A log's cursor may advance only once all
 *    of its sends resolved; the first failed send stops the phase, so later logs keep their cursors.
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
 */

import type { Env } from '../index';
import type { RunRow } from '../types';
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
/** Workers allow six simultaneous open connections per invocation; more lanes would only queue. */
export const CONCURRENCY = 6;
/** No new fetch starts after this. With FETCH_TIMEOUT_MS the fetch phase ends by ~25 s; sub-hourly crons get 30 s of CPU. */
export const FETCH_PHASE_MS = 20_000;
export const FETCH_TIMEOUT_MS = 5_000;
/** CT-log fetches per tick: well inside the per-invocation subrequest limit, leaving room for queue sends and D1. */
export const MAX_LOG_FETCHES = 900;
/** The fetch phase stops early once this many observations are held (memory: a few hundred bytes of heap each). */
export const MAX_TICK_OBSERVATIONS = 200_000;
/** Entries one visit may read before its log goes to the back of the queue, so one deep backlog cannot starve the rest. */
export const MAX_ENTRIES_PER_VISIT = 1_024;
/** get-entries asks for this many entries; logs return fewer (measured 3 to 246 per page). */
export const RFC6962_PAGE = 256;
const MAX_ERROR_LENGTH = 500;
const USER_AGENT = 'bv-ct-index (+https://blackveilsecurity.com)';

const SELECT_KILLED = 'SELECT 1 AS killed FROM ops_ledger WHERE killed = 1 LIMIT 1';
const SELECT_CURSORS = 'SELECT log_id, next_index FROM log_cursors';
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
	treeSize: number | null;
	observations: ObservationSet;
	error: string | null;
	deferred: string | null;
}

interface Tick {
	fetch: typeof fetch;
	fetchUntil: number;
	fetchTimeoutMs: number;
	states: LogState[];
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

let logListMemo: { fetchedAt: number; logs: TailedLog[] } | undefined;

/** Forgets the memoized log list (tests). */
export function resetLogListMemo(): void {
	logListMemo = undefined;
}

function describe(error: unknown): string {
	return (error instanceof Error ? error.message : String(error)).slice(0, MAX_ERROR_LENGTH);
}

function rowsTouched(meta: { rows_read?: number; rows_written?: number } | undefined): number {
	return (meta?.rows_read ?? 0) + (meta?.rows_written ?? 0);
}

function canFetch(tick: Tick): boolean {
	if (Date.now() >= tick.fetchUntil || tick.fetches >= MAX_LOG_FETCHES) return false;
	let held = 0;
	for (const state of tick.states) held += state.observations.names.size + state.observations.siblings.size;
	return held < MAX_TICK_OBSERVATIONS;
}

/**
 * GETs `url` and reads its body with `read`, both inside the fetch timeout. A 429 is a Deferral, any other
 * non-2xx an HttpError; a network failure or timeout names the URL (the bare abort message does not).
 */
async function get<T>(tick: Tick, url: string, read: (response: Response) => Promise<T>): Promise<T> {
	tick.fetches++;
	const named = (error: unknown) => new Error(`${describe(error)} (${url})`);
	let response: Response;
	try {
		response = await tick.fetch(url, { headers: { 'user-agent': USER_AGENT }, signal: AbortSignal.timeout(tick.fetchTimeoutMs) });
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
		observeCert(parseTbsCertificate(tbs), state.observations, tick.skips);
	} catch {
		tick.badEntries++;
	}
}

/** One get-entries page from the cursor. The cursor moves past whatever the log returned. */
async function readEntries(tick: Tick, state: LogState): Promise<void> {
	const start = state.next!;
	const end = Math.min(start + RFC6962_PAGE, state.treeSize!) - 1;
	const url = `${state.log.url}ct/v1/get-entries?start=${start}&end=${end}`;
	const { entries } = await get(tick, url, (response) => response.json<{ entries?: unknown }>());
	if (!Array.isArray(entries) || entries.length > end - start + 1) throw new Error(`get-entries ${start}-${end}: bad entries array`);
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

/** The full data tile holding the cursor; entries before the cursor (a new log's start) are skipped. */
async function readTile(tick: Tick, state: LogState): Promise<void> {
	const tile = Math.floor(state.next! / TILE_WIDTH);
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
	for (let i = state.next! - tile * TILE_WIDTH; i < TILE_WIDTH; i++) observeEntry(tick, state, () => entries[i] ?? null);
	state.next = (tile + 1) * TILE_WIDTH;
}

/** One visit to a log. Returns true when entries remain and the log should be visited again this tick. */
async function visit(tick: Tick, state: LogState): Promise<boolean> {
	if (state.treeSize === null) {
		state.treeSize = await readHead(tick, state.log);
		if (state.next === null) {
			// Forward-only: a log seen for the first time starts at its current tree size.
			state.next = state.treeSize;
			return false;
		}
	}
	// A static-ct log is read in full tiles only; its partial tail waits until the tile fills.
	const end = state.log.kind === 'static' ? Math.floor(state.treeSize / TILE_WIDTH) * TILE_WIDTH : state.treeSize;
	for (let read = 0; state.next! < end && read < MAX_ENTRIES_PER_VISIT;) {
		if (!canFetch(tick)) return false;
		const before = state.next!;
		await (state.log.kind === 'static' ? readTile(tick, state) : readEntries(tick, state));
		read += state.next! - before;
	}
	return state.next! < end;
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
				// Progress up to the last complete page or tile stands; the cursor still advances to it.
				if (error instanceof Deferral) state.deferred = error.message;
				else state.error = describe(error);
			}
		}
	};
	await Promise.all(Array.from({ length: CONCURRENCY }, lane));
}

/** Sends each log's new rows. Returns the logs whose cursors may be written. */
async function sendPhase(env: Pick<Env, 'ENTRIES'>, tick: Tick, order: LogState[]): Promise<LogState[]> {
	const emitted = new Map<string, RunRow>();
	const writable: LogState[] = [];
	let failed = false;
	for (const state of order) {
		if (state.treeSize === null) continue; // head never read: nothing to write but the error
		if (state.cursorAt === null || state.next === state.cursorAt) {
			writable.push(state); // first sight, or nothing read: no rows to send
			continue;
		}
		if (failed) continue;
		const rows = newRows(state.observations, emitted);
		const batches = toBatches(state.log.logId, state.cursorAt, state.next!, rows);
		try {
			await Promise.all(
				batches.map((batch) => {
					tick.sends++;
					return env.ENTRIES.send(batch, { contentType: 'json' });
				}),
			);
		} catch (error) {
			state.error = `queue send: ${describe(error)}`;
			failed = true;
			continue;
		}
		tick.names += rows.names.length;
		tick.siblings += rows.siblings.length;
		tick.batches += batches.length;
		writable.push(state);
	}
	return writable;
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

export async function runTailer(env: Pick<Env, 'CURSORS' | 'ENTRIES'>, options: TailerOptions): Promise<TickSummary> {
	const now = options.now ?? Date.now();
	const tick: Tick = {
		fetch: options.fetch ?? globalThis.fetch.bind(globalThis),
		fetchUntil: Date.now() + (options.fetchPhaseMs ?? FETCH_PHASE_MS),
		fetchTimeoutMs: options.fetchTimeoutMs ?? FETCH_TIMEOUT_MS,
		states: [],
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
	const db = env.CURSORS;

	const killed = await db.prepare(SELECT_KILLED).all();
	tick.d1Rows += rowsTouched(killed.meta);
	if (killed.results.length > 0) return summarize(tick, true, 0);

	const logs = await loadLogs(tick, now);
	const cursors = await db.prepare(SELECT_CURSORS).all<{ log_id: string; next_index: number | null }>();
	tick.d1Rows += rowsTouched(cursors.meta);
	const cursorAt = new Map(cursors.results.map((row) => [row.log_id, row.next_index]));
	const offset = logs.length > 0 ? Math.floor(options.scheduledTime / 60_000) % logs.length : 0;
	tick.states = [...logs.slice(offset), ...logs.slice(0, offset)].map((log) => {
		const at = cursorAt.get(log.logId) ?? null;
		return { log, cursorAt: at, next: at, treeSize: null, observations: newObservationSet(), error: null, deferred: null };
	});

	await fetchPhase(tick, tick.states);
	const writable = await sendPhase(env, tick, tick.states);

	const at = new Date(now).toISOString();
	const statements = [
		...writable.map((s) => db.prepare(UPSERT_CURSOR).bind(s.log.logId, s.log.kind, s.log.url, s.next, s.treeSize, at, s.cursorAt)),
		...tick.states.filter((s) => s.error).map((s) => db.prepare(RECORD_ERROR).bind(s.log.logId, s.log.kind, s.log.url, s.error, at)),
	];
	for (const result of statements.length > 0 ? await db.batch(statements) : []) tick.d1Rows += rowsTouched(result.meta);
	const summary = summarize(tick, false, writable.length);
	await db.prepare(ADD_TO_LEDGER).bind(at.slice(0, 10), summary.subrequests, summary.d1Rows).run();
	return summary;
}
