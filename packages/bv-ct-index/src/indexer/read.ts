// SPDX-License-Identifier: BUSL-1.1
/**
 * The read seam (types.ts IndexReader) over the sorted runs of `meta.current_generation`.
 *
 * A scan is ONE D1 query (`catalogQuery`) for the current generation's runs whose [key_lo, key_hi] overlaps the key
 * range and whose key filter admits it, with their block indexes. The runs are then k-way merged across tiers the way
 * `mergeSortedRuns` merges them (rows sharing a key fold in input order, expired rows drop), but lazily (SQ-402): a
 * block's first key bounds every key it holds, so a run's next block is read, with one R2 range GET, only once that
 * bound is at or below the smallest row already read, and the merge stops at `limit` rows plus the one that says the
 * page is truncated. A page therefore reads the runs that hold its rows, not every run the range overlaps (a big apex
 * overlaps thousands of T1 runs). While a run must be read, the next runs in bound order are read alongside it, so up
 * to READ_CONCURRENCY GETs are in flight and runs that hold the same first key are read together.
 *
 * Errors: any D1 or R2 fault throws, so the API answers 503 and never an empty page. One exception is retried:
 * a compaction job deletes its input objects right after swapping the catalog, so a scan that read the catalog
 * just before a swap can find an input gone. The scan then runs once more against the fresh catalog; an object
 * the catalog still lists and R2 still lacks throws MissingRunObjectError. An invalid domain, apex, limit or
 * cursor throws RangeError (the API's 400).
 *
 * Cursor: base64url of the last key on the page (keys are ASCII). The next page starts after it.
 */

import {
	KEY_FILTER_VERSION,
	SIBLING_PREFIX,
	decodeBlock,
	keyFilterHashes,
	keyFilterProbe,
	mergeObservations,
	parseBlockIndex,
	pathSplitKeys,
	rangeFor,
	siblingKey,
} from '../codec';
import type { Env } from '../index';
import type { BlockIndexEntry, IndexReader, NameObservation, RunRow, SiblingObservation } from '../types';
import { MissingRunObjectError, readRange } from './blocks';
import { CURRENT_GENERATION_SQL, DEFAULT_GENERATION } from './catalog';

export const READ_CONCURRENCY = 6;

export interface ScanQuery {
	lo: string;
	hi: string;
	/** Exclusive start (the cursor key), or null to start at lo. */
	after: string | null;
	limit: number;
	siblings: boolean;
	now: number;
}

interface CatalogRun {
	r2_key: string;
	key_lo: string;
	block_index: ArrayBuffer | ArrayBufferView | number[];
}

/**
 * The blocks of a run that can hold keys in [start, hi]: block i holds keys from its firstKey up to, not
 * including, the next block's firstKey.
 */
export function blocksFor(blockIndex: readonly BlockIndexEntry[], start: string, hi: string): BlockIndexEntry[] {
	let lo = 0;
	let high = blockIndex.length;
	while (lo < high) {
		const mid = (lo + high) >>> 1;
		if (blockIndex[mid]!.firstKey <= start) lo = mid + 1;
		else high = mid;
	}
	const from = Math.max(0, lo - 1);
	let to = from;
	while (to < blockIndex.length && blockIndex[to]!.firstKey <= hi) to++;
	return blockIndex.slice(from, to);
}

function encodeCursor(key: string): string {
	return btoa(key).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeCursor(cursor: string, lo: string, hi: string): string {
	let key: string;
	try {
		key = atob(cursor.replace(/-/g, '+').replace(/_/g, '/'));
	} catch {
		throw new RangeError('malformed cursor');
	}
	if (key < lo || key > hi) throw new RangeError('cursor does not belong to this scan');
	return key;
}

function checkLimit(limit: number): void {
	if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError(`limit must be a positive integer: ${limit}`);
}

/** One run in a scan's merge: the blocks it has left and, once its next block is read, that block's rows in range. */
interface Source {
	/** Position among the scan's runs: rows sharing a key fold in this order, as in `mergeSortedRuns`. */
	readonly input: number;
	readonly r2Key: string;
	readonly blocks: readonly BlockIndexEntry[];
	/** The next block to read; blocks.length once the run has nothing left in range. */
	next: number;
	/** No unread key of the run in range is below this: the scan start or the next block's first key, whichever is higher. */
	bound: string;
	/** The GET of block `next`, once started. */
	read: Promise<Uint8Array> | null;
	/** The rows of the block being merged that are in range, ascending; rows[at] is the run's current row. */
	rows: RunRow[];
	at: number;
}

const rowOf = (source: Source) => source.rows[source.at]!;

/** Run order while waiting to be read: by bound, then input. */
const beforeByBound = (a: Source, b: Source) => a.bound < b.bound || (a.bound === b.bound && a.input < b.input);

/** Run order once read: by current key, then input, so ties pop in input order. */
const beforeByRow = (a: Source, b: Source) => {
	const x = rowOf(a).key;
	const y = rowOf(b).key;
	return x < y || (x === y && a.input < b.input);
};

/** Inserts `source` into `list`, kept sorted by `before`, after every entry that does not sort after it. */
function insertSorted(list: Source[], source: Source, before: (a: Source, b: Source) => boolean): void {
	let lo = 0;
	let hi = list.length;
	while (lo < hi) {
		const mid = (lo + hi) >>> 1;
		if (before(source, list[mid]!)) hi = mid;
		else lo = mid + 1;
	}
	list.splice(lo, 0, source);
}

/** The merge's order rests on the bound: a key below it, or out of order, would be emitted late, so it throws. */
function assertAscending(source: Source, last: string | null, key: string): void {
	const ordered = last === null ? key >= source.bound : key > last;
	if (!ordered) {
		throw new RangeError(`run ${source.r2Key} is not key-sorted: ${JSON.stringify(key)} after ${JSON.stringify(last ?? source.bound)}`);
	}
}

/**
 * The lazy k-way merge of a scan (see the header): `pending` holds the runs whose next block is unread, in bound
 * order; `ready` the runs with a current row, in row order. The smallest row is emitted only once every pending
 * bound is above it, so no unread block can hold a smaller or equal key.
 */
class LazyMerge {
	private readonly pending: Source[] = [];
	private readonly ready: Source[] = [];
	private reading = 0;

	constructor(
		private readonly bucket: R2Bucket,
		private readonly query: ScanQuery,
		sources: readonly Source[],
	) {
		for (const source of sources) insertSorted(this.pending, source, beforeByBound);
	}

	/** The next merged row (expired rows included), or null once every run is done. */
	async nextRow(): Promise<RunRow | null> {
		while (this.mustRead()) await this.readFront();
		return this.ready.length === 0 ? null : this.popMerged();
	}

	/** True when the front pending run could hold a key at or below the smallest row read so far. */
	private mustRead(): boolean {
		const front = this.pending[0];
		const top = this.ready[0];
		return front !== undefined && (top === undefined || front.bound <= rowOf(top).key);
	}

	/** Takes the smallest row, folded with every other run's row of the same key in input order. */
	private popMerged(): RunRow {
		const top = this.ready.shift()!;
		let merged = rowOf(top);
		this.advance(top);
		for (let tie = this.ready[0]; tie !== undefined && rowOf(tie).key === merged.key; tie = this.ready[0]) {
			merged = mergeObservations(merged, rowOf(tie));
			this.advance(this.ready.shift()!);
		}
		return merged;
	}

	/** Reads the front run's next block, with the next runs in bound order alongside it. */
	private async readFront(): Promise<void> {
		const front = this.pending[0]!;
		this.startRead(front);
		for (const source of this.pending) {
			if (this.reading >= READ_CONCURRENCY) break;
			this.startRead(source);
		}
		const bytes = await front.read!;
		this.pending.shift();
		this.reading--;
		front.read = null;
		front.next++;
		front.rows = this.inRange(front, await decodeBlock(bytes));
		front.at = 0;
		this.place(front);
	}

	private startRead(source: Source): void {
		if (source.read !== null) return;
		const entry = source.blocks[source.next]!;
		source.read = readRange(this.bucket, source.r2Key, entry.offset, entry.length);
		// A read the merge never reaches (it stopped at `limit`) must not surface as an unhandled rejection.
		source.read.catch(() => undefined);
		this.reading++;
	}

	/** The rows of a decoded block inside the scan range. Past `hi`, the run is done. */
	private inRange(source: Source, rows: readonly RunRow[]): RunRow[] {
		const kept: RunRow[] = [];
		let last: string | null = null;
		for (const row of rows) {
			if (this.beforeStart(row.key)) continue;
			if (row.key > this.query.hi) {
				source.next = source.blocks.length;
				break;
			}
			assertAscending(source, last, row.key);
			kept.push(row);
			last = row.key;
		}
		return kept;
	}

	private beforeStart(key: string): boolean {
		return this.query.after === null ? key < this.query.lo : key <= this.query.after;
	}

	/** Moves a run on: to its next row, to pending with its next block, or out of the merge. */
	private advance(source: Source): void {
		source.at++;
		this.place(source);
	}

	private place(source: Source): void {
		if (source.at < source.rows.length) {
			insertSorted(this.ready, source, beforeByRow);
			return;
		}
		source.rows = [];
		if (source.next >= source.blocks.length) return;
		source.bound = source.blocks[source.next]!.firstKey;
		insertSorted(this.pending, source, beforeByBound);
	}
}

/** A BLOB whose byte i is i: `instr(BYTE_VALUES, substr(blob, p, 1)) - 1` is the byte at p, which SQLite has no function for. */
const BYTE_VALUES = Uint8Array.from({ length: 256 }, (_, i) => i);

/**
 * SQL that is false only when the key filter in `filter` (codec KEY_FILTER_VERSION) has a clear bit for one of the
 * probe `hashes`, i.e. the run holds no key the probe covers. A NULL, unknown-version or empty filter is true.
 * `byteValues` is an expression for BYTE_VALUES. Hashes are cast because D1 binds a JS number as REAL, and
 * REAL % INTEGER is REAL.
 */
export function keyFilterSql(filter: string, byteValues: string, hashes: readonly string[]): string {
	const bits = `((length(${filter}) - 1) * 8)`;
	const tests: string[] = [];
	for (const hash of hashes) {
		const bit = `(CAST(${hash} AS INTEGER) % ${bits})`;
		tests.push(`((instr(${byteValues}, substr(${filter}, 2 + ${bit} / 8, 1)) - 1) >> (${bit} % 8)) & 1`);
	}
	const version = KEY_FILTER_VERSION.toString(16).padStart(2, '0');
	return `(${filter} IS NULL OR substr(${filter}, 1, 1) <> X'${version}' OR length(${filter}) < 2 OR (${tests.join(' AND ')}))`;
}

/** The key filter term of a scan and its parameters (?7 on): none for a lookup that no filter can prune. */
function filterTerm(lo: string): { sql: string; params: unknown[] } {
	const probe = keyFilterProbe(lo);
	if (probe === null) return { sql: '1', params: [] };
	const hashes = keyFilterHashes(probe);
	const names: string[] = [];
	for (let i = 0; i < hashes.length; i++) names.push(`?${8 + i}`);
	return { sql: keyFilterSql('key_filter', '?7', names), params: [BYTE_VALUES, ...hashes] };
}

/** The smallest key above every key of a scan range, whose hi ends with U+FFFF after '\x01' (names) or '\x00' (siblings). */
function rangeBound(hi: string): string {
	return hi.slice(0, -2) + String.fromCharCode(hi.charCodeAt(hi.length - 2) + 1);
}

/**
 * The catalog query of a scan: the current generation's runs whose [key_lo, key_hi] overlaps [start, hi] and whose
 * key filter admits the range's probe. Candidates come from the interval index (codec runSplitKey) for the range
 * [lo, bound), a superset of what the overlap test keeps, so each branch reads index rows of overlapping runs only;
 * runs from before migration 0005 have no split and are read by key_lo.
 */
export function catalogQuery(query: ScanQuery): { sql: string; params: unknown[] } {
	const bound = rangeBound(query.hi);
	const filter = filterTerm(query.lo);
	const current = `generation = ${CURRENT_GENERATION_SQL}`;
	const turns = [JSON.stringify([...pathSplitKeys(query.lo, 1), query.lo]), JSON.stringify(pathSplitKeys(bound, 0))];
	return {
		sql: `SELECT r2_key, key_lo, block_index FROM runs WHERE rowid IN (
				SELECT rowid FROM runs WHERE ${current} AND key_split > ?3 AND key_split <= ?4
				UNION ALL SELECT rowid FROM runs WHERE ${current} AND key_split IN (SELECT value FROM json_each(?5)) AND key_hi >= ?3
				UNION ALL SELECT rowid FROM runs WHERE ${current} AND key_split IN (SELECT value FROM json_each(?6)) AND key_lo < ?4
				UNION ALL SELECT rowid FROM runs WHERE ${current} AND key_split IS NULL AND key_lo <= ?1
			) AND key_lo <= ?1 AND key_hi >= ?2 AND ${filter.sql}`,
		params: [query.hi, query.after ?? query.lo, query.lo, bound, ...turns, ...filter.params],
	};
}

async function scanOnce(env: Env, query: ScanQuery): Promise<{ rows: RunRow[]; truncated: boolean }> {
	const catalogRuns = catalogQuery(query);
	const { results } = await env.CURSORS.prepare(catalogRuns.sql)
		.bind(...catalogRuns.params)
		.all<CatalogRun>();
	return readPage(new LazyMerge(env.INDEX, query, sourcesOf(results, query)), query);
}

/** The merge inputs of a scan: each catalog run of the scan's kind with a block that can hold keys in range. */
function sourcesOf(runs: readonly CatalogRun[], query: ScanQuery): Source[] {
	const sources: Source[] = [];
	for (const run of runs) {
		const source = sourceOf(run, query, sources.length);
		if (source !== null) sources.push(source);
	}
	return sources;
}

function sourceOf(run: CatalogRun, query: ScanQuery, input: number): Source | null {
	// A run holds one kind only, and name ranges never reach into the sibling keyspace.
	if (run.key_lo.startsWith(SIBLING_PREFIX) !== query.siblings) return null;
	const start = query.after ?? query.lo;
	const blocks = blocksFor(parseBlockIndex(run.block_index), start, query.hi);
	if (blocks.length === 0) return null;
	const bound = blocks[0]!.firstKey > start ? blocks[0]!.firstKey : start;
	return { input, r2Key: run.r2_key, blocks, next: 0, bound, read: null, rows: [], at: 0 };
}

/** Up to `limit` live rows, and whether another live row follows them. */
async function readPage(merge: LazyMerge, query: ScanQuery): Promise<{ rows: RunRow[]; truncated: boolean }> {
	const rows: RunRow[] = [];
	for (let row = await merge.nextRow(); row !== null; row = await merge.nextRow()) {
		if (row.notAfter < query.now) continue;
		if (rows.length === query.limit) return { rows, truncated: true };
		rows.push(row);
	}
	return { rows, truncated: false };
}

async function scanRange(env: Env, query: ScanQuery): Promise<{ rows: RunRow[]; truncated: boolean }> {
	try {
		return await scanOnce(env, query);
	} catch (error) {
		if (!(error instanceof MissingRunObjectError)) throw error;
		return scanOnce(env, query);
	}
}

/** `clock` returns epoch ms; tests pin it. */
export function createReader(env: Env, clock: () => number = Date.now): IndexReader {
	const now = () => Math.floor(clock() / 1000);
	return {
		async scan(domain, opts) {
			const { lo, hi } = rangeFor(domain);
			checkLimit(opts.limit);
			const after = opts.cursor ? decodeCursor(opts.cursor, lo, hi) : null;
			const page = await scanRange(env, { lo, hi, after, limit: opts.limit, siblings: false, now: now() });
			return {
				names: page.rows as NameObservation[],
				truncated: page.truncated,
				cursor: page.truncated ? encodeCursor(page.rows.at(-1)!.key) : null,
			};
		},
		async siblings(apex, opts) {
			checkLimit(opts.limit);
			// 's\x00' + reversed(apex) + '\x00': siblingKey normalizes and checks the apex exactly as the writers did.
			const prefix = siblingKey(apex, 'a').slice(0, -1);
			const page = await scanRange(env, { lo: prefix, hi: `${prefix}\uffff`, after: null, limit: opts.limit, siblings: true, now: now() });
			return { siblings: page.rows as SiblingObservation[], truncated: page.truncated };
		},
		async meta() {
			// One round trip: the meta keys, plus the tailer's backlog as a row of its own (null with no cursors yet).
			// Each log counts at least 0: a log can serve a stale head below the cursor, and a negative difference
			// would otherwise cancel other logs' unread entries.
			const { results } = await env.CURSORS.prepare(
				"SELECT k, v FROM meta WHERE k IN ('current_generation', 'index_started_at', 'fresh_through') " +
					"UNION ALL SELECT 'entries_behind', CAST(SUM(MAX(tree_size - next_index, 0)) AS TEXT) FROM log_cursors",
			).all<{ k: string; v: string | null }>();
			const meta = new Map(results.map((row) => [row.k, row.v]));
			const behind = meta.get('entries_behind');
			return {
				indexStartedAt: meta.get('index_started_at') ?? null,
				freshThrough: meta.get('fresh_through') ?? null,
				entriesBehind: behind == null ? null : Number(behind),
				generation: Number(meta.get('current_generation') ?? DEFAULT_GENERATION),
			};
		},
	};
}
