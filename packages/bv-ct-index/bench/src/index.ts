// SPDX-License-Identifier: BUSL-1.1
/**
 * bv-ct-index-bench: THROWAWAY benchmark Worker for US-12 (SQ-352). Operator-run from ../RUNBOOK.md.
 *
 *   POST /seed   synthetic NameObservations -> encodeRun -> runs in R2 + catalog rows in D1 (the real schema)
 *   GET  /query  n read-path queries: 1 D1 overlap SELECT + <=9 single-block R2 range GETs (<=6 in flight) + decode
 *   POST /merge  mergeSortedRuns over the seeded runs into createRunWriter, as a compaction job would
 *   POST /cleanup  deletes every bench object and catalog row, before the bucket and database are deleted
 *
 * CLOCK CAVEAT: a deployed Worker's clock only advances across I/O (a Spectre mitigation), so in-Worker times
 * count R2/D1 waits but not pure CPU. Query numbers are I/O-dominated and close; merge numbers are NOT CPU time.
 * The authoritative merge CPU is `cpuTime` in `wrangler tail --format json`, and its true wall time is the
 * client's `curl -w %{time_total}`. RUNBOOK.md captures both.
 */

import {
	createRunWriter,
	decodeBlock,
	encodeRun,
	mergeSortedRuns,
	parseBlockIndex,
	rangeFor,
	serializeBlockIndex,
	siblingKey,
	SIBLING_PREFIX,
} from '../../src/codec';
import type { BlockIndexEntry } from '../../src/types';
import { queryDomain, rng, runObservations } from './synth';

export interface Env {
	/** Scratch R2 bucket `bv-ct-index-bench`. */
	BENCH: R2Bucket;
	/** Scratch D1 `bv-ct-index-bench`, migrated with ../migrations (the real catalog schema). */
	BENCH_DB: D1Database;
	/** Bearer key for every route but /health. Unset means every route answers 503. */
	BENCH_KEY?: string;
}

/** The one catalog generation the bench writes and reads. */
const GENERATION = 1;
/** Seeded runs are compaction inputs, so they sit above T0. */
const TIER = 1;
const RUN_PREFIX = `runs/g${GENERATION}/`;
const MERGED_KEY = `merged/g${GENERATION}/out.run`;
/** Per-query read budget from the contract: at most 9 single-block range GETs, at most 6 in flight. */
const MAX_BLOCKS = 9;
const MAX_IN_FLIGHT = 6;
/** Decoded heap per row, measured by SQ-348 (story log #10). Used only to estimate bytes held, not measured here. */
const DECODED_ROW_HEAP_BYTES = 274;
const HISTOGRAM_MS = [50, 100, 200, 400, 600, 1000, 1500];

const json = (body: unknown, status = 200) => Response.json(body, { status });

function intParam(url: URL, name: string, fallback: number, min: number, max: number): number {
	const raw = url.searchParams.get(name);
	const value = raw === null ? fallback : Number(raw);
	if (!Number.isSafeInteger(value) || value < min || value > max) throw new RangeError(`${name} must be an integer in [${min}, ${max}]`);
	return value;
}

async function authorized(request: Request, key: string): Promise<boolean> {
	const given = new TextEncoder().encode(request.headers.get('authorization') ?? '');
	const wanted = new TextEncoder().encode(`Bearer ${key}`);
	return given.byteLength === wanted.byteLength && crypto.subtle.timingSafeEqual(given, wanted);
}

function percentile(sorted: readonly number[], p: number): number {
	if (sorted.length === 0) return NaN;
	return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)]!;
}

function summary(values: readonly number[]) {
	const sorted = [...values].sort((a, b) => a - b);
	const round = (v: number) => Math.round(v * 10) / 10;
	return {
		n: sorted.length,
		p50: round(percentile(sorted, 50)),
		p95: round(percentile(sorted, 95)),
		p99: round(percentile(sorted, 99)),
		max: round(sorted.at(-1) ?? NaN),
		mean: round(sorted.reduce((s, v) => s + v, 0) / (sorted.length || 1)),
	};
}

function histogram(values: readonly number[]): Record<string, number> {
	const out: Record<string, number> = {};
	let lo = 0;
	for (const hi of [...HISTOGRAM_MS, Infinity]) {
		out[hi === Infinity ? `>=${lo}ms` : `${lo}-${hi}ms`] = values.filter((v) => v >= lo && v < hi).length;
		lo = hi;
	}
	return out;
}

/** Runs `task` over `items` with at most `limit` in flight, results in input order. */
async function pool<T, R>(items: readonly T[], limit: number, task: (item: T) => Promise<R>): Promise<R[]> {
	const results = new Array<R>(items.length);
	let next = 0;
	const worker = async () => {
		while (next < items.length) {
			const at = next++;
			results[at] = await task(items[at]!);
		}
	};
	await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
	return results;
}

async function rangeGet(env: Env, r2Key: string, entry: BlockIndexEntry): Promise<Uint8Array> {
	const object = await env.BENCH.get(r2Key, { range: { offset: entry.offset, length: entry.length } });
	if (!object) throw new Error(`R2 object missing: ${r2Key}`);
	return new Uint8Array(await object.arrayBuffer());
}

async function deletePrefix(bucket: R2Bucket, prefix: string): Promise<number> {
	let deleted = 0;
	let cursor: string | undefined;
	do {
		const page = await bucket.list({ prefix, cursor });
		if (page.objects.length > 0) await bucket.delete(page.objects.map((o) => o.key));
		deleted += page.objects.length;
		cursor = page.truncated ? page.cursor : undefined;
	} while (cursor);
	return deleted;
}

/**
 * Confirms D1 keeps a '\x00' inside key_lo through bind, storage, read-back and a range comparison. Prod D1 NUL
 * handling was unverified after SQ-351 (story log #14), and sibling keys depend on it.
 */
async function d1NulCheck(db: D1Database): Promise<{ roundTrip: boolean; rangeMatch: boolean }> {
	const key = siblingKey('example.com', 'alpha.net');
	const lo = `${SIBLING_PREFIX}com\x01example\x00`;
	await db.prepare("DELETE FROM runs WHERE id = 'nul-check'").run();
	await db
		.prepare(
			"INSERT INTO runs (id, generation, tier, key_lo, key_hi, r2_key, rows, bytes, block_index, created_at) VALUES ('nul-check', -1, 0, ?, ?, '', 0, 0, NULL, ?)",
		)
		.bind(key, key, new Date().toISOString())
		.run();
	const row = await db.prepare("SELECT key_lo FROM runs WHERE id = 'nul-check'").first<{ key_lo: string }>();
	const match = await db
		.prepare('SELECT id FROM runs WHERE generation = -1 AND key_lo <= ? AND key_hi >= ?')
		.bind(`${lo}\uffff`, lo)
		.all<{ id: string }>();
	await db.prepare("DELETE FROM runs WHERE id = 'nul-check'").run();
	return { roundTrip: row?.key_lo === key, rangeMatch: match.results.length === 1 };
}

async function seed(env: Env, url: URL): Promise<Response> {
	const rows = intParam(url, 'rows', 800_000, 1_000, 2_000_000);
	const runs = intParam(url, 'runs', 4, 1, 16);
	const seedValue = intParam(url, 'seed', 1, 0, 2 ** 31 - 1);
	const now = Math.floor(Date.now() / 1000);
	const started = performance.now();

	const deletedObjects = (await deletePrefix(env.BENCH, RUN_PREFIX)) + (await deletePrefix(env.BENCH, 'merged/'));
	await env.BENCH_DB.prepare('DELETE FROM runs WHERE generation = ?').bind(GENERATION).run();

	const written = [];
	for (let run = 0; run < runs; run++) {
		// One run's rows at a time: encodeRun needs them in memory (~274 B/row decoded), so never hold two runs.
		const encoded = await encodeRun(runObservations(run, runs, rows, seedValue, now));
		const r2Key = `${RUN_PREFIX}r${String(run).padStart(2, '0')}.run`;
		const putStarted = performance.now();
		await env.BENCH.put(r2Key, encoded.bytes);
		const putMs = performance.now() - putStarted;
		const blockIndex = serializeBlockIndex(encoded.blockIndex);
		await env.BENCH_DB.prepare(
			'INSERT INTO runs (id, generation, tier, key_lo, key_hi, r2_key, rows, bytes, block_index, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
		)
			.bind(
				`bench-r${run}`,
				GENERATION,
				TIER,
				encoded.keyLo,
				encoded.keyHi,
				r2Key,
				encoded.rows,
				encoded.bytes.byteLength,
				blockIndex,
				new Date().toISOString(),
			)
			.run();
		written.push({
			r2Key,
			rows: encoded.rows,
			bytes: encoded.bytes.byteLength,
			blocks: encoded.blockIndex.length,
			blockIndexBytes: blockIndex.byteLength,
			putMs: Math.round(putMs),
		});
	}
	await env.BENCH_DB.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('current_generation', ?)").bind(String(GENERATION)).run();

	const totalRows = written.reduce((s, r) => s + r.rows, 0);
	const totalBytes = written.reduce((s, r) => s + r.bytes, 0);
	return json({
		requestedRows: rows,
		storedRows: totalRows,
		totalBytes,
		bytesPerRow: Math.round((totalBytes / totalRows) * 10) / 10,
		runs: written,
		deletedObjects,
		d1Nul: await d1NulCheck(env.BENCH_DB),
		wallMs: Math.round(performance.now() - started),
	});
}

interface CatalogRun {
	r2_key: string;
	block_index: ArrayBuffer | ArrayBufferView | number[];
}

/** The blocks of one run that can hold keys in [lo, hi]: from the last block starting at or before lo, while firstKey <= hi. */
function blocksFor(entries: readonly BlockIndexEntry[], lo: string, hi: string): BlockIndexEntry[] {
	let start = 0;
	let low = 0;
	let high = entries.length - 1;
	while (low <= high) {
		const mid = (low + high) >> 1;
		if (entries[mid]!.firstKey <= lo) {
			start = mid;
			low = mid + 1;
		} else high = mid - 1;
	}
	const out: BlockIndexEntry[] = [];
	for (let b = start; b < entries.length && entries[b]!.firstKey <= hi; b++) out.push(entries[b]!);
	return out;
}

async function oneQuery(env: Env, domain: string) {
	const started = performance.now();
	const { lo, hi } = rangeFor(domain);
	const { results } = await env.BENCH_DB.prepare(
		'SELECT r2_key, block_index FROM runs WHERE generation = ? AND key_lo <= ? AND key_hi >= ?',
	)
		.bind(GENERATION, hi, lo)
		.all<CatalogRun>();
	const d1Done = performance.now();

	// Round-robin across runs so every run gets its first block before any run gets a second, then cap at 9.
	const perRun = results.map((run) => blocksFor(parseBlockIndex(run.block_index), lo, hi).map((entry) => ({ r2Key: run.r2_key, entry })));
	const wanted: { r2Key: string; entry: BlockIndexEntry }[] = [];
	const candidates = perRun.reduce((s, blocks) => s + blocks.length, 0);
	for (let depth = 0; wanted.length < Math.min(MAX_BLOCKS, candidates); depth++) {
		for (const blocks of perRun) if (depth < blocks.length && wanted.length < MAX_BLOCKS) wanted.push(blocks[depth]!);
	}
	const matched = await pool(wanted, MAX_IN_FLIGHT, async ({ r2Key, entry }) => {
		const rows = await decodeBlock(await rangeGet(env, r2Key, entry));
		return rows.filter((row) => row.key >= lo && row.key <= hi).length;
	});
	const done = performance.now();
	return {
		ms: done - started,
		d1Ms: d1Done - started,
		r2Ms: done - d1Done,
		runs: results.length,
		blocks: wanted.length,
		truncated: candidates > wanted.length,
		rows: matched.reduce((s, n) => s + n, 0),
	};
}

async function query(env: Env, url: URL, request: Request): Promise<Response> {
	const n = intParam(url, 'n', 500, 1, 5_000);
	const rows = intParam(url, 'rows', 800_000, 1_000, 2_000_000);
	const seedValue = intParam(url, 'seed', 1, 0, 2 ** 31 - 1);
	const r = rng(intParam(url, 'qseed', Date.now() % 2 ** 31, 0, 2 ** 31 - 1));
	const samples: (Awaited<ReturnType<typeof oneQuery>> & { kind: string })[] = [];
	const errors: { domain: string; error: string }[] = [];
	// Sequential on purpose: this measures one query's latency, not throughput.
	for (let i = 0; i < n; i++) {
		const { domain, kind } = queryDomain(r, rows, seedValue);
		try {
			samples.push({ ...(await oneQuery(env, domain)), kind });
		} catch (error) {
			errors.push({ domain, error: String(error) });
		}
	}
	const ms = samples.map((s) => s.ms);
	const total = summary(ms);
	const byKind = Object.fromEntries(
		['apex', 'cold', 'suffix'].map((kind) => [kind, summary(samples.filter((s) => s.kind === kind).map((s) => s.ms))]),
	);
	return json(
		{
			colo: (request.cf as { colo?: string } | undefined)?.colo ?? null,
			ms: total,
			d1Ms: summary(samples.map((s) => s.d1Ms)),
			r2Ms: summary(samples.map((s) => s.r2Ms)),
			distribution: histogram(ms),
			byKind,
			blocks: summary(samples.map((s) => s.blocks)),
			runsPerQuery: summary(samples.map((s) => s.runs)),
			rowsMatched: summary(samples.map((s) => s.rows)),
			truncatedQueries: samples.filter((s) => s.truncated).length,
			errors: { count: errors.length, first: errors.slice(0, 5) },
			pass: { p95Under600ms: total.p95 < 600, p95UnderHardCeiling1500ms: total.p95 < 1500, noErrors: errors.length === 0 },
			raw: url.searchParams.get('raw') === '1' ? samples : undefined,
			clock: 'in-Worker; counts I/O waits, not pure CPU (see header)',
		},
		errors.length > 0 && samples.length === 0 ? 503 : 200,
	);
}

async function merge(env: Env, url: URL): Promise<Response> {
	const inputs = intParam(url, 'inputs', 4, 1, 16);
	const fetchMode = url.searchParams.get('fetch') ?? 'block';
	if (fetchMode !== 'block' && fetchMode !== 'object') throw new RangeError('fetch must be block or object');
	const write = url.searchParams.get('write') !== '0';
	const now = Math.floor(Date.now() / 1000);
	const started = performance.now();

	const { results: runs } = await env.BENCH_DB.prepare(
		'SELECT r2_key, rows, bytes, block_index FROM runs WHERE generation = ? AND tier = ? ORDER BY id LIMIT ?',
	)
		.bind(GENERATION, TIER, inputs)
		.all<CatalogRun & { rows: number; bytes: number }>();
	if (runs.length === 0) return json({ error: 'no seeded runs; POST /seed first' }, 409);

	// Accounted (not measured) bytes held by the inputs: the open compressed block, or the whole object in
	// fetch=object mode, plus the decoded block at DECODED_ROW_HEAP_BYTES per row.
	const held = runs.map(() => 0);
	let peakInputBytes = 0;
	let blockReads = 0;
	const account = (input: number, bytes: number) => {
		held[input] = bytes;
		peakInputBytes = Math.max(
			peakInputBytes,
			held.reduce((s, b) => s + b, 0),
		);
	};
	async function* input(run: CatalogRun, at: number) {
		const entries = parseBlockIndex(run.block_index);
		let whole: Uint8Array | undefined;
		if (fetchMode === 'object') {
			const object = await env.BENCH.get(run.r2_key);
			if (!object) throw new Error(`R2 object missing: ${run.r2_key}`);
			whole = new Uint8Array(await object.arrayBuffer());
		}
		for (const entry of entries) {
			const bytes = whole ? whole.subarray(entry.offset, entry.offset + entry.length) : await rangeGet(env, run.r2_key, entry);
			if (!whole) blockReads++;
			const rows = await decodeBlock(bytes);
			account(at, (whole ? whole.byteLength : bytes.byteLength) + rows.length * DECODED_ROW_HEAP_BYTES);
			yield* rows;
		}
		account(at, 0);
	}

	const writer = createRunWriter();
	let outRows = 0;
	for await (const row of mergeSortedRuns(
		runs.map((run, at) => input(run, at)),
		now,
	)) {
		await writer.add(row);
		outRows++;
	}
	const encoded = await writer.finish();
	const merged = performance.now();
	if (write) await env.BENCH.put(MERGED_KEY, encoded.bytes);
	const done = performance.now();

	const inputRows = runs.reduce((s, run) => s + run.rows, 0);
	// finish() concatenates the compressed blocks into one buffer, so the output is briefly held twice.
	const peakBytesEstimate = peakInputBytes + 2 * encoded.bytes.byteLength;
	return json({
		fetch: fetchMode,
		inputs: runs.length,
		inputRows,
		inputBytes: runs.reduce((s, run) => s + run.bytes, 0),
		outputRows: outRows,
		droppedOrFolded: inputRows - outRows,
		outputBytes: encoded.bytes.byteLength,
		blockReads,
		mergeWallMs: Math.round(merged - started),
		putMs: write ? Math.round(done - merged) : null,
		wallMs: Math.round(done - started),
		peakInputBytesAccounted: peakInputBytes,
		peakBytesEstimate,
		pass: { under100MB: peakBytesEstimate < 100 * 1024 * 1024, wallUnder30s: done - started < 30_000 },
		clock: 'in-Worker; NOT CPU time. Read cpuTime from wrangler tail and wall from curl (RUNBOOK.md)',
	});
}

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		if (request.method === 'GET' && url.pathname === '/health') return json({ ok: true, worker: 'bv-ct-index-bench' });
		if (!env.BENCH_KEY) return json({ error: 'BENCH_KEY is not set' }, 503);
		if (!(await authorized(request, env.BENCH_KEY))) return json({ error: 'unauthorized' }, 401);
		try {
			if (request.method === 'POST' && url.pathname === '/seed') return await seed(env, url);
			if (request.method === 'GET' && url.pathname === '/query') return await query(env, url, request);
			if (request.method === 'POST' && url.pathname === '/merge') return await merge(env, url);
			// Empties the bucket so `wrangler r2 bucket delete` (which refuses a non-empty bucket) can run.
			if (request.method === 'POST' && url.pathname === '/cleanup') {
				const deletedObjects = (await deletePrefix(env.BENCH, RUN_PREFIX)) + (await deletePrefix(env.BENCH, 'merged/'));
				await env.BENCH_DB.prepare('DELETE FROM runs WHERE generation = ?').bind(GENERATION).run();
				return json({ deletedObjects, remainingObjects: (await env.BENCH.list()).objects.length });
			}
			return json({ error: 'not_found' }, 404);
		} catch (error) {
			return json({ error: String(error) }, error instanceof RangeError ? 400 : 503);
		}
	},
} satisfies ExportedHandler<Env>;
