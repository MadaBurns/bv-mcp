// SPDX-License-Identifier: BUSL-1.1
/**
 * The `17 * * * *` cron: the weekly generation snapshot (generations.ts), then the compaction planner, which
 * reads the catalog of the current generation and enqueues jobs (compact.ts) to `COMPACT`:
 *
 * - T0 -> T1: every T0 run created in an hour that ended at least ~10 min ago, in jobs of at most
 *   MAX_JOB_INPUTS runs and MAX_JOB_ROWS rows (`boundedChunks`).
 * - T1 -> T2: every T1 run created on a UTC day that has ended, per day and key range, in the same bounded jobs.
 * - T2 + T3 -> T3: per key range, the range's T3 shards with its oldest T2 runs, in one job per range of at most
 *   MAX_T3_JOB_ROWS rows; T2 runs past the budget wait for the next cron (SQ-363).
 * - T2 -> T2 re-cut: a T2 run that spans a cut is rewritten at the current cuts first, in the same bounded jobs.
 *
 * Key ranges come from "cuts": keys every job closes its output runs at. The cuts are T3 shard boundaries
 * chosen by content (a shard's first key is a cut when its hash is 0 mod GROUP_SHARDS, or after
 * GROUP_MAX_SHARDS shards without one), plus the edges of the sibling keyspace. Because T1 and T2 outputs are
 * cut at the same keys, each later job reads only the runs of its own range, and a T3 job rewrites about
 * GROUP_SHARDS shards (~160 MB) however big the index grows. Its output is closed every ~20 MB, which splits a
 * grown shard and merges shrunken neighbours. A boundary that moves only moves the cuts next to it, and a run
 * planned against older cuts that now straddles one simply joins the neighbouring range's job (`components`),
 * so jobs never share an input.
 *
 * Job size (SQ-362): every T0 run spans the whole keyspace, so a T1 job opens all of its inputs at once, each
 * holding a read window and a decoded block. One job per clock hour (~235 runs, ~3.4M rows at the 2026-10-17
 * ingest rate) does not fit a 128 MB isolate: the same merge in V8 runs out of a 96 MB heap and takes ~34 s
 * CPU, while the go-live hour's job (~50 runs, ~0.8M rows) fit. So T1 and T2 jobs are capped; an hour or a day
 * becomes several jobs, whose outputs overlap the way T0 runs do until the next tier merges them.
 *
 * T3 job size (SQ-363): a T3 job must take every T3 shard of its range, or its output would overlap the shards it
 * left out, so the bound works on both sides. `cutsFor` also cuts once a range's shards reach MAX_T3_RANGE_ROWS,
 * and the job takes T2 runs, oldest first, only while the total stays within MAX_T3_JOB_ROWS (always at least
 * one, so every range progresses). On the first day there are no shards and only the fixed cuts, so one range
 * held a whole day of T2: ~10M rows, measured at ~134 s CPU in V8 for 9.6M rows (~14 us a row), inside the
 * 300 s limit but without a 2x margin. Memory, not CPU, binds first: at 00:17Z 2026-10-18 the ~1.4M-row T2 jobs ran out of the 128 MB isolate on 1-2 of their attempts, so jobs are capped at 1.5M (T3) and 750k (T1/T2) rows.
 * Deferring is safe: reads merge every tier with the commutative `mergeObservations`, so a row in T2 or in T3
 * reads the same, and a re-planned job over the same inputs only repeats a swap the guard refuses.
 *
 * Re-cut (SQ-363): a T2 run is cut at the cuts of its plan time. The first day's T2 runs saw only the fixed cuts, so
 * each spans about half the name keyspace; once T3 shards add cuts, those runs straddle them and `components` joins
 * every range they touch into one T3 job, which then rewrites all of that keyspace's shards for about one T2 run a
 * cron (rehearsed on the 2026-10-17 data: ~17 crons of ~7M rows). So a straddling T2 run never goes to T3: a bounded
 * T2 -> T2 job rewrites it closed at today's cuts, and the next cron merges each range's pieces in parallel. Cuts
 * that move later can make a run straddle again; it is simply re-cut again.
 */

import { SIBLING_PREFIX } from '../codec';
import type { Env } from '../index';
import { DAY_MS, HOUR_MS, currentGeneration, isKilled } from './catalog';
import type { CompactionJob } from './compact';
import { maybeSnapshot } from './generations';

export const COMPACTION_CRON = '17 * * * *';
/** A T0 run is compacted once its hour has been over for this long. */
export const T0_MIN_AGE_MS = 10 * 60_000;
export const GROUP_SHARDS = 8;
export const GROUP_MAX_SHARDS = 24;
/** The sibling keyspace is ['s\x00', 's\x01'): no output run spans its edges, so every run holds one kind. */
const FIXED_CUTS = [SIBLING_PREFIX, 's\x01'];
/** Queues: at most 100 messages and 256 KB per sendBatch. */
const SEND_BATCH_MESSAGES = 100;
const SEND_BATCH_BYTES = 200 * 1024;
/** At most this many input runs per T1 or T2 job: bounds the merge's open inputs, and so its memory. */
export const MAX_JOB_INPUTS = 32;
/**
 * At most this many input rows per T1 or T2 job (catalog `rows`): bounds its CPU. The merge measured ~9 us per
 * input row in Node on a loaded workstation, so a full job stays well inside even the 30 s default CPU limit.
 */
export const MAX_JOB_ROWS = 750_000;
/** At most this many input rows (T3 shards plus T2 runs) per T3 job, unless one T2 run alone exceeds it. */
export const MAX_T3_JOB_ROWS = 1_500_000;
/** A range closes once its T3 shards hold this many rows, leaving at least half of a T3 job for T2 runs. */
export const MAX_T3_RANGE_ROWS = MAX_T3_JOB_ROWS / 2;

export interface PlanLimits {
	maxInputs: number;
	maxRows: number;
	/** MAX_T3_JOB_ROWS; ranges close at half of it. */
	maxT3Rows: number;
}

export const DEFAULT_PLAN_LIMITS: PlanLimits = { maxInputs: MAX_JOB_INPUTS, maxRows: MAX_JOB_ROWS, maxT3Rows: MAX_T3_JOB_ROWS };

interface PlanRun {
	id: string;
	tier: number;
	key_lo: string;
	key_hi: string;
	rows: number;
	created_at: string;
}

const compareText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** FNV-1a over UTF-16 code units: a stable, runtime-independent hash for picking cuts. */
function fnv1a(text: string): number {
	let hash = 0x811c9dc5;
	for (let i = 0; i < text.length; i++) hash = Math.imul(hash ^ text.charCodeAt(i), 0x01000193);
	return hash >>> 0;
}

/** The cut keys for the current T3 shards, sorted. A range also closes before its shards pass `maxRangeRows`. */
export function cutsFor(t3: ReadonlyArray<{ key_lo: string; rows?: number }>, maxRangeRows = MAX_T3_RANGE_ROWS): string[] {
	const cuts = new Set(FIXED_CUTS);
	const shards = [...t3].sort((a, b) => compareText(a.key_lo, b.key_lo));
	const rowsOf = (shard: { rows?: number }) => Number(shard.rows) || 0;
	let sinceCut = 0;
	let rangeRows = shards.length > 0 ? rowsOf(shards[0]!) : 0;
	for (const shard of shards.slice(1)) {
		sinceCut++;
		if (fnv1a(shard.key_lo) % GROUP_SHARDS === 0 || sinceCut >= GROUP_MAX_SHARDS || rangeRows + rowsOf(shard) > maxRangeRows) {
			cuts.add(shard.key_lo);
			sinceCut = 0;
			rangeRows = 0;
		}
		rangeRows += rowsOf(shard);
	}
	return [...cuts].sort(compareText);
}

/** True when a run spans more than one cut range. */
function straddles(run: { key_lo: string; key_hi: string }, cuts: readonly string[]): boolean {
	return rangeIndex(cuts, run.key_lo) !== rangeIndex(cuts, run.key_hi);
}

/** The index of the cut range holding `key`: the number of cuts <= key. */
function rangeIndex(cuts: readonly string[], key: string): number {
	let lo = 0;
	let hi = cuts.length;
	while (lo < hi) {
		const mid = (lo + hi) >>> 1;
		if (cuts[mid]! <= key) lo = mid + 1;
		else hi = mid;
	}
	return lo;
}

/**
 * Groups runs into sets that share a cut range, joined transitively through runs that straddle a cut. Each set
 * comes with the cuts strictly inside its span, which its job's output must respect.
 */
export function components<T extends { key_lo: string; key_hi: string }>(
	runs: readonly T[],
	cuts: readonly string[],
): Array<{ runs: T[]; cuts: string[] }> {
	const spans = runs
		.map((run) => ({ run, first: rangeIndex(cuts, run.key_lo), last: rangeIndex(cuts, run.key_hi) }))
		.sort((a, b) => a.first - b.first);
	const out: Array<{ runs: T[]; cuts: string[] }> = [];
	let current: { runs: T[]; first: number; last: number } | null = null;
	const flush = () => {
		if (current) out.push({ runs: current.runs, cuts: cuts.slice(current.first, current.last) });
	};
	for (const span of spans) {
		if (current && span.first <= current.last) {
			current.runs.push(span.run);
			current.last = Math.max(current.last, span.last);
		} else {
			flush();
			current = { runs: [span.run], first: span.first, last: span.last };
		}
	}
	flush();
	return out;
}

/**
 * Splits runs, oldest first, into consecutive chunks of at most `maxInputs` runs and `maxRows` rows. A run over
 * `maxRows` on its own still gets a chunk, so nothing is left unplanned.
 */
export function boundedChunks<T extends { id: string; rows: number; created_at: string }>(runs: readonly T[], limits: PlanLimits): T[][] {
	const sorted = [...runs].sort((a, b) => compareText(a.created_at, b.created_at) || compareText(a.id, b.id));
	const chunks: T[][] = [];
	let chunk: T[] = [];
	let rows = 0;
	for (const run of sorted) {
		const size = Number(run.rows) || 0;
		if (chunk.length > 0 && (chunk.length >= limits.maxInputs || rows + size > limits.maxRows)) {
			chunks.push(chunk);
			chunk = [];
			rows = 0;
		}
		chunk.push(run);
		rows += size;
	}
	if (chunk.length > 0) chunks.push(chunk);
	return chunks;
}

/**
 * The inputs of one range's T3 job: every T3 shard (the output must replace them all to stay disjoint from the
 * rest of tier 3), then T2 runs oldest first while the total stays within `limits.maxT3Rows` rows and
 * `limits.maxInputs` T2 runs. At least one T2 run is taken, so a range always progresses.
 */
export function t3JobInputs<T extends { id: string; tier: number; rows: number; created_at: string }>(
	runs: readonly T[],
	limits: PlanLimits,
): T[] {
	const shards = runs.filter((run) => Number(run.tier) === 3);
	const t2 = runs.filter((run) => Number(run.tier) === 2);
	let rows = shards.reduce((sum, run) => sum + (Number(run.rows) || 0), 0);
	const taken: T[] = [];
	for (const run of [...t2].sort((a, b) => compareText(a.created_at, b.created_at) || compareText(a.id, b.id))) {
		const size = Number(run.rows) || 0;
		if (taken.length > 0 && (taken.length >= limits.maxInputs || rows + size > limits.maxT3Rows)) break;
		taken.push(run);
		rows += size;
	}
	return taken.length > 0 ? [...shards, ...taken] : [];
}

function groupBy<T>(items: readonly T[], keyOf: (item: T) => string): Map<string, T[]> {
	const groups = new Map<string, T[]>();
	for (const item of items) {
		const key = keyOf(item);
		const group = groups.get(key);
		if (group) group.push(item);
		else groups.set(key, [item]);
	}
	return groups;
}

async function makeJob(generation: number, tier: 1 | 2 | 3, runs: readonly PlanRun[], cuts: string[], now: number): Promise<CompactionJob> {
	const inputs = runs.map((run) => run.id).sort(compareText);
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify({ generation, tier, inputs, cuts, now })));
	const id = [...new Uint8Array(digest).slice(0, 16)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
	return { id, generation, tier, inputs, cuts, now };
}

/** Plans every compaction job that is due at `nowMs` in the current generation. Pure catalog reads. */
export async function planCompactions(db: D1Database, nowMs: number, limits: PlanLimits = DEFAULT_PLAN_LIMITS): Promise<CompactionJob[]> {
	const generation = await currentGeneration(db);
	const { results } = await db
		.prepare('SELECT id, tier, key_lo, key_hi, rows, created_at FROM runs WHERE generation = ?1')
		.bind(generation)
		.all<PlanRun>();
	const now = Math.floor(nowMs / 1000);
	const tier = (n: number) => results.filter((run) => Number(run.tier) === n);
	const cuts = cutsFor(tier(3), limits.maxT3Rows / 2);
	const jobs: CompactionJob[] = [];

	const hourEnd = Math.floor((nowMs - T0_MIN_AGE_MS) / HOUR_MS) * HOUR_MS;
	const dueT0 = tier(0).filter((run) => Date.parse(run.created_at) < hourEnd);
	// T0 runs span the whole keyspace, so a T1 job takes every cut (a few hundred keys at full size).
	for (const runs of groupBy(dueT0, (run) => run.created_at.slice(0, 13)).values()) {
		for (const chunk of boundedChunks(runs, limits)) jobs.push(await makeJob(generation, 1, chunk, cuts, now));
	}

	const dayEnd = Math.floor(nowMs / DAY_MS) * DAY_MS;
	const dueT1 = tier(1).filter((run) => Date.parse(run.created_at) < dayEnd);
	for (const runs of groupBy(dueT1, (run) => run.created_at.slice(0, 10)).values()) {
		for (const component of components(runs, cuts)) {
			for (const chunk of boundedChunks(component.runs, limits)) jobs.push(await makeJob(generation, 2, chunk, component.cuts, now));
		}
	}

	const straddling = tier(2).filter((run) => straddles(run, cuts));
	for (const component of components(straddling, cuts)) {
		for (const chunk of boundedChunks(component.runs, limits)) jobs.push(await makeJob(generation, 2, chunk, component.cuts, now));
	}
	const settled = tier(2).filter((run) => !straddles(run, cuts));
	for (const component of components([...settled, ...tier(3)], cuts)) {
		const inputs = t3JobInputs(component.runs, limits);
		if (inputs.length > 0) jobs.push(await makeJob(generation, 3, inputs, component.cuts, now));
	}
	return jobs;
}

/** Sends jobs in batches within the Queues per-call limits. */
export async function sendJobs(queue: Queue<CompactionJob>, jobs: readonly CompactionJob[]): Promise<void> {
	let chunk: CompactionJob[] = [];
	let bytes = 0;
	for (const job of jobs) {
		const size = JSON.stringify(job).length;
		if (chunk.length > 0 && (chunk.length === SEND_BATCH_MESSAGES || bytes + size > SEND_BATCH_BYTES)) {
			await queue.sendBatch(chunk.map((body) => ({ body })));
			chunk = [];
			bytes = 0;
		}
		chunk.push(job);
		bytes += size;
	}
	if (chunk.length > 0) await queue.sendBatch(chunk.map((body) => ({ body })));
}

export interface CronOutcome {
	killed: boolean;
	/** The new generation, when this run took the weekly snapshot. */
	snapshot: number | null;
	jobs: CompactionJob[];
}

/** The `17 * * * *` branch of `scheduled`. */
export async function runCompactionCron(env: Env, nowMs: number, limits: PlanLimits = DEFAULT_PLAN_LIMITS): Promise<CronOutcome> {
	if (await isKilled(env.CURSORS)) return { killed: true, snapshot: null, jobs: [] };
	const snapshot = await maybeSnapshot(env, nowMs);
	const jobs = await planCompactions(env.CURSORS, nowMs, limits);
	await sendJobs(env.COMPACT, jobs);
	return { killed: false, snapshot, jobs };
}
