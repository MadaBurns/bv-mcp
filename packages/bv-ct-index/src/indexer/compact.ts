// SPDX-License-Identifier: BUSL-1.1
/**
 * Compaction jobs: the consumer of the `bv-ct-index-compact` queue (batch 1, see wrangler.jsonc). The planner
 * (plan.ts) decides what to merge; a job only executes one message.
 *
 * A job streams its input runs through `mergeSortedRuns` (which folds rows sharing a key and drops rows with
 * notAfter < job.now), reading each run in range GETs of whole blocks and holding one window plus one decoded
 * block per open run. Key-disjoint inputs are read one after another, so a merge holds one open run per
 * overlapping layer. Output goes through `createRunWriter`, closed into a new R2 object at every cut key, at
 * every change of row kind (a run holds one kind only), at ~TARGET_RAW_BYTES and, for T1 output, before its key filter
 * would pass KEY_FILTER_MAX_ENTRIES (SQ-518), so the job holds at most one output run's compressed blocks.
 *
 * Commit: ONE D1 batch inserts the output rows and deletes the input rows, every statement guarded by "all
 * inputs are still listed and job.generation is still current". THEN the input objects that no row of any
 * generation still references are deleted. A crash between the two loses nothing: the retry finds the swap done
 * and repeats only the deletes.
 *
 * Idempotent on retry: output keys are `runs/t<tier>/<job.id>/<part>.run`, and the output bytes depend only on
 * the job message (inputs, cuts and job.now are fixed in it), so a retry or a duplicate delivery rewrites the
 * same bytes under the same keys, and the guard lets exactly one swap through.
 */

import {
	KEY_FILTER_MAX_ENTRIES,
	createRunWriter,
	isSiblingRow,
	keyFilterEntries,
	mergeSortedRuns,
	parseBlockIndex,
	serializeBlockIndex,
	streamRun,
} from '../codec';
import type { RunWriter } from '../codec';
import type { Env } from '../index';
import type { BlockIndexEntry, RunDescriptor, RunRow } from '../types';
import { windowedBlockReader } from './blocks';
import {
	CURRENT_GENERATION_SQL,
	RUNS_PREFIX,
	deleteUnreferenced,
	isKilled,
	ledgerStatement,
	r2KeyOfRunId,
	runId,
	runsByIds,
} from './catalog';

export interface CompactionJob {
	/** A digest of every other field (plan.ts), so one plan's retries share output keys and different plans never do. */
	id: string;
	/** The generation the inputs were planned in; the swap is refused once another generation is current. */
	generation: number;
	/** Output tier. */
	tier: 1 | 2 | 3;
	/** Input run ids, sorted. Every input is consumed whole. */
	inputs: string[];
	/** Sorted keys no output run may span: a run closes before the first row whose key is >= a cut. */
	cuts: string[];
	/** Plan time, epoch seconds. Rows with notAfter < now are dropped. */
	now: number;
}

/** ~10 MB of compressed output per run (TSV rows deflate about 3.5x): halved from 72 MB raw after 00:17Z 2026-10-18 showed 1.4M-row jobs at the 128 MB edge (SQ-363). */
export const TARGET_RAW_BYTES = 36 * 1024 * 1024;
/** Read buffer shared by a job's open runs; each run's window is clamped to [MIN_WINDOW_BYTES, MAX_WINDOW_BYTES]. */
const READ_BUDGET_BYTES = 16 * 1024 * 1024;
const MIN_WINDOW_BYTES = 64 * 1024;
const MAX_WINDOW_BYTES = 1024 * 1024;

export interface CompactionLimits {
	targetRawBytes: number;
}

export type JobOutcome = 'applied' | 'already-applied' | 'stale' | 'killed';

/** Parses a queue body into a job, or null. The planner is the only producer, so a bad body is a bug, not data. */
export function parseCompactionJob(body: unknown): CompactionJob | null {
	if (typeof body !== 'object' || body === null) return null;
	const job = body as Record<string, unknown>;
	const strings = (value: unknown) => Array.isArray(value) && value.every((item) => typeof item === 'string');
	if (typeof job.id !== 'string' || !Number.isSafeInteger(job.generation) || !Number.isSafeInteger(job.now)) return null;
	if (job.tier !== 1 && job.tier !== 2 && job.tier !== 3) return null;
	if (!strings(job.inputs) || (job.inputs as string[]).length === 0 || !strings(job.cuts)) return null;
	return body as CompactionJob;
}

/** Approximate TSV bytes of a row (codec rowLine), for cutting outputs before the writer is finished. */
function rawSize(row: RunRow): number {
	const text = isSiblingRow(row) ? row.apex.length + row.sibling.length : row.name.length + row.apex.length + row.issuer.length + 2;
	return row.key.length + text + 30;
}

interface OutputRun {
	r2Key: string;
	keyLo: string;
	keyHi: string;
	rows: number;
	bytes: number;
	blockIndex: BlockIndexEntry[];
	keyFilter: Uint8Array | null;
	keySplit: string | null;
}

/**
 * Output puts in flight at once (SQ-402): a T1 job closed one small run (~17 KB) per cut range, ~480 of them, and
 * one put after another took most of its ~6 min (SQ-403). A T0 -> T1 job now closes about one run per coarse range,
 * at most plan.ts MAX_T1_RANGES of them (SQ-491), and a roll-up job one per cut range it covers. Six is the Workers
 * limit on open connections.
 */
export const PUT_CONCURRENCY = 6;
/**
 * Bytes those puts may hold. It is checked after a run is added, so held bytes can reach the budget plus one run. Past it
 * the job waits for puts to settle before it writes on, so a run bigger than this (a T3 output is ~10 MB) is put on its own,
 * as before, and a job never holds more than one such run.
 */
export const PUT_BUDGET_BYTES = 4 * 1024 * 1024;

/** What a job did, for its `ct_compaction_job_done` log line. */
export interface JobStats {
	outputs: number;
	/** Range GETs of input blocks. */
	gets: number;
	/** Summed duration of the output puts (they overlap, so this can exceed `ms`). */
	putMs: number;
	/** Job duration. */
	ms: number;
}

/**
 * The key filter entries an output run of `tier` may hold (SQ-518). Past KEY_FILTER_MAX_ENTRIES a run stores no
 * filter, so every read in its range opens it. A coarse T0 -> T1 run holds its coarse range's share of a job of up to
 * plan.ts MAX_JOB_ROWS rows, enough to get there, so T1 output closes at the limit instead. T2 and T3 runs are the
 * large runs the limit leaves unfiltered on purpose: a T3 shard holds ~10 MB, and range pruning confines a read to one
 * or two of them.
 */
const filterEntryLimit = (tier: number) => (tier === 1 ? KEY_FILTER_MAX_ENTRIES : Number.POSITIVE_INFINITY);

/** Writes a merge's output as a sequence of runs, closing one at each cut, kind change, size target or filter limit. */
class OutputSink {
	readonly outputs: OutputRun[] = [];
	/** Summed duration of the puts. */
	putMs = 0;
	private writer: RunWriter | null = null;
	private sibling = false;
	private rawBytes = 0;
	/** The open run's distinct key filter entries, counted as codec's KeyFilterBuilder counts them. */
	private filterEntries = 0;
	/** The open run's last filter entry at each depth: rows arrive in key order, so a repeat is always that one. */
	private lastEntries: string[] = [];
	private nextCut = 0;
	private readonly puts = new Set<Promise<void>>();
	private putBytes = 0;
	/** The first put rejection. A failed put leaves `puts` as soon as it settles, so a race or `all` never sees it. */
	private putError: unknown = null;
	private putFailed = false;

	constructor(
		private readonly bucket: R2Bucket,
		private readonly prefix: string,
		private readonly cuts: readonly string[],
		private readonly targetRawBytes: number,
		private readonly maxFilterEntries: number,
	) {}

	async add(row: RunRow): Promise<void> {
		this.throwIfPutFailed();
		let crossedCut = false;
		while (this.nextCut < this.cuts.length && this.cuts[this.nextCut]! <= row.key) {
			this.nextCut++;
			crossedCut = true;
		}
		const sibling = isSiblingRow(row);
		const entries = keyFilterEntries(row.key);
		if (this.writer && (crossedCut || sibling !== this.sibling || this.full(entries))) await this.close();
		if (!this.writer) {
			this.writer = createRunWriter();
			this.sibling = sibling;
			this.rawBytes = 0;
			this.filterEntries = 0;
			this.lastEntries = [];
		}
		await this.writer.add(row);
		this.rawBytes += rawSize(row);
		this.filterEntries += this.newEntries(entries);
		entries.forEach((entry, depth) => (this.lastEntries[depth] = entry));
	}

	/** True when the open run is at its size target, or a row with filter `entries` would take it past its filter limit. */
	private full(entries: readonly string[]): boolean {
		return this.rawBytes >= this.targetRawBytes || this.filterEntries + this.newEntries(entries) > this.maxFilterEntries;
	}

	/** How many of a row's filter `entries` the open run does not hold yet. */
	private newEntries(entries: readonly string[]): number {
		return entries.filter((entry, depth) => entry !== this.lastEntries[depth]).length;
	}

	/** Closes the last run and waits for every put: a failed put throws, so the job is retried. */
	async finish(): Promise<OutputRun[]> {
		if (this.writer) await this.close();
		await Promise.all(this.puts);
		this.throwIfPutFailed();
		return this.outputs;
	}

	private throwIfPutFailed(): void {
		if (this.putFailed) throw this.putError;
	}

	private async close(): Promise<void> {
		const run = await this.writer!.finish();
		this.writer = null;
		const r2Key = `${this.prefix}/${String(this.outputs.length).padStart(5, '0')}.run`;
		this.outputs.push({
			r2Key,
			keyLo: run.keyLo,
			keyHi: run.keyHi,
			rows: run.rows,
			bytes: run.bytes.byteLength,
			blockIndex: run.blockIndex,
			keyFilter: run.keyFilter,
			keySplit: run.keySplit,
		});
		this.startPut(r2Key, run.bytes);
		this.throwIfPutFailed();
		while (this.puts.size >= PUT_CONCURRENCY || this.putBytes > PUT_BUDGET_BYTES) {
			await Promise.race(this.puts);
			this.throwIfPutFailed();
		}
	}

	private startPut(r2Key: string, bytes: Uint8Array): void {
		const started = Date.now();
		const put: Promise<void> = this.bucket
			.put(r2Key, bytes)
			.then(() => {
				this.putMs += Date.now() - started;
			})
			// Stored, not thrown: this promise never rejects, so a put still running after another failed is never unhandled.
			// `add`, `close` and `finish` rethrow the first failure, before the job reaches its catalog swap.
			.catch((error: unknown) => {
				if (this.putFailed) return;
				this.putFailed = true;
				this.putError = error;
			})
			.finally(() => {
				this.puts.delete(put);
				this.putBytes -= bytes.byteLength;
			});
		this.puts.add(put);
		this.putBytes += bytes.byteLength;
	}
}

/** Groups key-disjoint runs into chains that are read one after another. */
function chainDisjoint(runs: readonly RunDescriptor[]): RunDescriptor[][] {
	const chains: RunDescriptor[][] = [];
	for (const run of [...runs].sort((a, b) => (a.key_lo < b.key_lo ? -1 : a.key_lo > b.key_lo ? 1 : 0))) {
		const chain = chains.find((candidate) => candidate.at(-1)!.key_hi < run.key_lo);
		if (chain) chain.push(run);
		else chains.push([run]);
	}
	return chains;
}

/** `stats` is filled in when the job merges; a job that stops early leaves it at zero. */
export async function runCompactionJob(
	env: Env,
	job: CompactionJob,
	limits: CompactionLimits = { targetRawBytes: TARGET_RAW_BYTES },
	nowMs = Date.now(),
	stats: JobStats = { outputs: 0, gets: 0, putMs: 0, ms: 0 },
): Promise<JobOutcome> {
	const startedMs = Date.now();
	const db = env.CURSORS;
	if (await isKilled(db)) return 'killed';
	const inputKeys = job.inputs.map(r2KeyOfRunId);
	const outputPrefix = `${RUNS_PREFIX}t${job.tier}/${job.id}`;

	const inputs = await runsByIds(db, job.inputs);
	if (inputs.length !== job.inputs.length || (await currentGenerationIs(db, job.generation)) === false) {
		// Either this job's swap already committed (a crash or lost ack before the deletes) or another job or a
		// snapshot overtook it. Either way the only work left is deleting input objects nothing references.
		const applied = await db
			.prepare('SELECT COUNT(*) AS n FROM runs WHERE r2_key >= ?1 AND r2_key < ?2')
			.bind(`${outputPrefix}/`, `${outputPrefix}0`)
			.first<{ n: number }>();
		await deleteUnreferenced(db, env.INDEX, inputKeys);
		return Number(applied?.n ?? 0) > 0 ? 'already-applied' : 'stale';
	}

	let gets = 0;
	const chains = chainDisjoint(inputs);
	const windowBytes = Math.min(MAX_WINDOW_BYTES, Math.max(MIN_WINDOW_BYTES, Math.floor(READ_BUDGET_BYTES / chains.length)));
	const layers = chains.map(async function* (chain) {
		for (const run of chain) {
			const blockIndex = parseBlockIndex(run.block_index);
			yield* streamRun(
				blockIndex,
				windowedBlockReader(env.INDEX, run.r2_key, blockIndex, windowBytes, () => gets++),
			);
		}
	});
	const sink = new OutputSink(env.INDEX, outputPrefix, job.cuts, limits.targetRawBytes, filterEntryLimit(job.tier));
	for await (const row of mergeSortedRuns(layers, job.now)) await sink.add(row);
	const outputs = await sink.finish();

	const createdAt = new Date(job.now * 1000).toISOString();
	const guard = `(SELECT COUNT(*) FROM runs WHERE id IN (SELECT value FROM json_each(?1))) = ?2 AND ${CURRENT_GENERATION_SQL} = ?3`;
	const guardArgs = [JSON.stringify(job.inputs), job.inputs.length, job.generation] as const;
	const statements = outputs.map((out) =>
		db
			.prepare(
				`INSERT INTO runs (id, generation, tier, key_lo, key_hi, r2_key, rows, bytes, block_index, created_at, key_filter, key_split)
				 SELECT ?4, CAST(?3 AS INTEGER), ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14 WHERE ${guard}`,
			)
			.bind(
				...guardArgs,
				runId(job.generation, out.r2Key),
				job.tier,
				out.keyLo,
				out.keyHi,
				out.r2Key,
				out.rows,
				out.bytes,
				serializeBlockIndex(out.blockIndex),
				createdAt,
				out.keyFilter,
				out.keySplit,
			),
	);
	// Last data statement: its guard still sees every input, because SQLite evaluates the uncorrelated subquery once.
	statements.push(db.prepare(`DELETE FROM runs WHERE id IN (SELECT value FROM json_each(?1)) AND ${guard}`).bind(...guardArgs));
	statements.push(ledgerStatement(db, nowMs, { r2ClassA: outputs.length, r2ClassB: gets, d1Rows: outputs.length + inputs.length + 1 }));
	const results = await db.batch(statements);
	const swapped = results[outputs.length]!.meta.changes === job.inputs.length;
	Object.assign(stats, { outputs: outputs.length, gets, putMs: sink.putMs, ms: Date.now() - startedMs });

	// Swapped: the inputs are garbage unless a retained generation still lists them. Not swapped: a concurrent run
	// of the same job won (its outputs are ours, byte for byte) or another job consumed an input; this attempt's
	// outputs, if unreferenced, are left to the weekly garbage sweep.
	await deleteUnreferenced(db, env.INDEX, inputKeys);
	return swapped ? 'applied' : 'stale';
}

async function currentGenerationIs(db: D1Database, generation: number): Promise<boolean> {
	const row = await db.prepare(`SELECT ${CURRENT_GENERATION_SQL} = ?1 AS current`).bind(generation).first<{ current: number }>();
	return Number(row?.current) === 1;
}

/** Consumes a `bv-ct-index-compact` batch. A throw leaves the message unacked, so the queue retries it. */
export async function runCompactionBatch(batch: MessageBatch<unknown>, env: Env): Promise<void> {
	for (const message of batch.messages) {
		const job = parseCompactionJob(message.body);
		if (job === null) {
			console.error(`bv-ct-index compaction: dropping malformed job message ${message.id}`);
		} else {
			// Logged before the work, so an invocation that dies on a CPU or memory limit still names its job.
			console.log(JSON.stringify({ event: 'ct_compaction_job', id: job.id, tier: job.tier, inputs: job.inputs.length }));
			const stats: JobStats = { outputs: 0, gets: 0, putMs: 0, ms: 0 };
			const outcome = await runCompactionJob(env, job, undefined, undefined, stats);
			// After the work: output count and put time say where a job's wall time goes (SQ-402).
			console.log(JSON.stringify({ event: 'ct_compaction_job_done', id: job.id, tier: job.tier, outcome, ...stats }));
			if (outcome !== 'applied') console.log(`bv-ct-index compaction: job ${job.id} (tier ${job.tier}) ${outcome}`);
		}
		message.ack();
	}
}
