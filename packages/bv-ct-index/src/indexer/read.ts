// SPDX-License-Identifier: BUSL-1.1
/**
 * The read seam (types.ts IndexReader) over the sorted runs of `meta.current_generation`.
 *
 * A scan is ONE D1 query for the current generation's runs whose [key_lo, key_hi] overlaps the key range,
 * with their block indexes; then only the blocks that can hold keys in the range are fetched, with R2 range
 * GETs, at most READ_CONCURRENCY at a time (the first block of every run is requested up front). The runs are
 * k-way merged across tiers with `mergeSortedRuns`, which folds rows sharing a key and drops expired rows.
 *
 * Errors: any D1 or R2 fault throws, so the API answers 503 and never an empty page. One exception is retried:
 * a compaction job deletes its input objects right after swapping the catalog, so a scan that read the catalog
 * just before a swap can find an input gone. The scan then runs once more against the fresh catalog; an object
 * the catalog still lists and R2 still lacks throws MissingRunObjectError. An invalid domain, apex, limit or
 * cursor throws RangeError (the API's 400).
 *
 * Cursor: base64url of the last key on the page (keys are ASCII). The next page starts after it.
 */

import { SIBLING_PREFIX, decodeBlock, mergeSortedRuns, parseBlockIndex, rangeFor, siblingKey } from '../codec';
import type { Env } from '../index';
import type { BlockIndexEntry, IndexReader, NameObservation, RunRow, SiblingObservation } from '../types';
import { MissingRunObjectError, limiter, readRange } from './blocks';
import { CURRENT_GENERATION_SQL, DEFAULT_GENERATION } from './catalog';

export const READ_CONCURRENCY = 6;

interface ScanQuery {
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

/**
 * The rows of one run inside the query range, block by block. A plain function, not a generator, so the first
 * block is requested when the run is listed rather than when the merge first pulls from it.
 */
function runRows(
	bucket: R2Bucket,
	run: CatalogRun,
	blocks: BlockIndexEntry[],
	query: ScanQuery,
	slot: <T>(task: () => Promise<T>) => Promise<T>,
): AsyncGenerator<RunRow> {
	const fetchBlock = (entry: BlockIndexEntry) => slot(() => readRange(bucket, run.r2_key, entry.offset, entry.length));
	// Requested now, so the first blocks of every run download together; awaited in order below. The no-op catch
	// only keeps a prefetch that the merge never reaches from surfacing as an unhandled rejection.
	const first = fetchBlock(blocks[0]!);
	first.catch(() => undefined);
	return (async function* () {
		for (const [i, entry] of blocks.entries()) {
			for (const row of await decodeBlock(await (i === 0 ? first : fetchBlock(entry)))) {
				if (query.after === null ? row.key < query.lo : row.key <= query.after) continue;
				if (row.key > query.hi) return;
				yield row;
			}
		}
	})();
}

async function scanOnce(env: Env, query: ScanQuery): Promise<{ rows: RunRow[]; truncated: boolean }> {
	const start = query.after ?? query.lo;
	const { results } = await env.CURSORS.prepare(
		`SELECT r2_key, key_lo, block_index FROM runs WHERE generation = ${CURRENT_GENERATION_SQL} AND key_lo <= ?1 AND key_hi >= ?2`,
	)
		.bind(query.hi, start)
		.all<CatalogRun>();
	const slot = limiter(READ_CONCURRENCY);
	const inputs: AsyncGenerator<RunRow>[] = [];
	for (const run of results) {
		// A run holds one kind only, and name ranges never reach into the sibling keyspace.
		if (run.key_lo.startsWith(SIBLING_PREFIX) !== query.siblings) continue;
		const blocks = blocksFor(parseBlockIndex(run.block_index), start, query.hi);
		if (blocks.length > 0) inputs.push(runRows(env.INDEX, run, blocks, query, slot));
	}
	const rows: RunRow[] = [];
	for await (const row of mergeSortedRuns(inputs, query.now)) {
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
			const { results } = await env.CURSORS.prepare(
				"SELECT k, v FROM meta WHERE k IN ('current_generation', 'index_started_at', 'fresh_through')",
			).all<{ k: string; v: string }>();
			const meta = new Map(results.map((row) => [row.k, row.v]));
			return {
				indexStartedAt: meta.get('index_started_at') ?? null,
				freshThrough: meta.get('fresh_through') ?? null,
				generation: Number(meta.get('current_generation') ?? DEFAULT_GENERATION),
			};
		},
	};
}
