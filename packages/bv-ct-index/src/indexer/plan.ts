// SPDX-License-Identifier: BUSL-1.1
/**
 * The `17 * * * *` cron: the weekly generation snapshot (generations.ts), then the compaction planner, which
 * reads the catalog of the current generation and enqueues jobs (compact.ts) to `COMPACT`:
 *
 * - T0 -> T1: every T0 run created in an hour that ended at least ~10 min ago, one job per hour.
 * - T1 -> T2: every T1 run created on a UTC day that has ended, one job per day and key range.
 * - T2 + T3 -> T3: every T2 run, with the T3 shards of the key ranges it touches, one job per key range.
 *
 * Key ranges come from "cuts": keys every job closes its output runs at. The cuts are T3 shard boundaries
 * chosen by content (a shard's first key is a cut when its hash is 0 mod GROUP_SHARDS, or after
 * GROUP_MAX_SHARDS shards without one), plus the edges of the sibling keyspace. Because T1 and T2 outputs are
 * cut at the same keys, each later job reads only the runs of its own range, and a T3 job rewrites about
 * GROUP_SHARDS shards (~160 MB) however big the index grows. Its output is closed every ~20 MB, which splits a
 * grown shard and merges shrunken neighbours. A boundary that moves only moves the cuts next to it, and a run
 * planned against older cuts that now straddles one simply joins the neighbouring range's job (`components`),
 * so jobs never share an input.
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

interface PlanRun {
	id: string;
	tier: number;
	key_lo: string;
	key_hi: string;
	created_at: string;
}

const compareText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/** FNV-1a over UTF-16 code units: a stable, runtime-independent hash for picking cuts. */
function fnv1a(text: string): number {
	let hash = 0x811c9dc5;
	for (let i = 0; i < text.length; i++) hash = Math.imul(hash ^ text.charCodeAt(i), 0x01000193);
	return hash >>> 0;
}

/** The cut keys for the current T3 shards, sorted. */
export function cutsFor(t3: ReadonlyArray<{ key_lo: string }>): string[] {
	const cuts = new Set(FIXED_CUTS);
	const shards = [...t3].sort((a, b) => compareText(a.key_lo, b.key_lo));
	let sinceCut = 0;
	for (const shard of shards.slice(1)) {
		sinceCut++;
		if (fnv1a(shard.key_lo) % GROUP_SHARDS === 0 || sinceCut >= GROUP_MAX_SHARDS) {
			cuts.add(shard.key_lo);
			sinceCut = 0;
		}
	}
	return [...cuts].sort(compareText);
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
export async function planCompactions(db: D1Database, nowMs: number): Promise<CompactionJob[]> {
	const generation = await currentGeneration(db);
	const { results } = await db
		.prepare('SELECT id, tier, key_lo, key_hi, created_at FROM runs WHERE generation = ?1')
		.bind(generation)
		.all<PlanRun>();
	const now = Math.floor(nowMs / 1000);
	const tier = (n: number) => results.filter((run) => Number(run.tier) === n);
	const cuts = cutsFor(tier(3));
	const jobs: CompactionJob[] = [];

	const hourEnd = Math.floor((nowMs - T0_MIN_AGE_MS) / HOUR_MS) * HOUR_MS;
	const dueT0 = tier(0).filter((run) => Date.parse(run.created_at) < hourEnd);
	// T0 runs span the whole keyspace, so a T1 job takes every cut (a few hundred keys at full size).
	for (const runs of groupBy(dueT0, (run) => run.created_at.slice(0, 13)).values())
		jobs.push(await makeJob(generation, 1, runs, cuts, now));

	const dayEnd = Math.floor(nowMs / DAY_MS) * DAY_MS;
	const dueT1 = tier(1).filter((run) => Date.parse(run.created_at) < dayEnd);
	for (const runs of groupBy(dueT1, (run) => run.created_at.slice(0, 10)).values()) {
		for (const component of components(runs, cuts)) jobs.push(await makeJob(generation, 2, component.runs, component.cuts, now));
	}

	for (const component of components([...tier(2), ...tier(3)], cuts)) {
		if (component.runs.some((run) => Number(run.tier) === 2)) jobs.push(await makeJob(generation, 3, component.runs, component.cuts, now));
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
export async function runCompactionCron(env: Env, nowMs: number): Promise<CronOutcome> {
	if (await isKilled(env.CURSORS)) return { killed: true, snapshot: null, jobs: [] };
	const snapshot = await maybeSnapshot(env, nowMs);
	const jobs = await planCompactions(env.CURSORS, nowMs);
	await sendJobs(env.COMPACT, jobs);
	return { killed: false, snapshot, jobs };
}
