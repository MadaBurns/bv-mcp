// SPDX-License-Identifier: BUSL-1.1
/**
 * T0 -> T1 output at a coarse subset of the cuts (SQ-491): a job writes at most MAX_T1_RANGES runs, reads match the
 * full-cut path, and the roll-up and T1 -> T2 still write their output at every cut.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { SIBLING_PREFIX } from '../codec';
import { runCompactionJob } from '../indexer/compact';
import type { CompactionJob } from '../indexer/compact';
import { DEFAULT_PLAN_LIMITS, MAX_T1_RANGES, coarseCuts, cutsFor, runCompactionCron } from '../indexer/plan';
import type { PlanLimits } from '../indexer/plan';
import { createReader } from '../indexer/read';
import type { NameObservation } from '../types';
import { DAY_MS, DAY_S, HOUR_MS, T, T_S, applyCatalog, catalog, expectedRows, ingest, obs, testEnv } from './indexer-harness';
import type { CatalogRow, TestEnv } from './indexer-harness';

beforeEach(applyCatalog);

/** Day `day` (0 = the day of T) at hh:mm UTC. */
const at = (day: number, hh: number, mm: number) => Math.floor(T / DAY_MS) * DAY_MS + day * DAY_MS + hh * HOUR_MS + mm * 60_000;
const FIXED = [SIBLING_PREFIX, 's\x01'];
const TLDS = ['com', 'org', 'se', 'uk'];
/** Rows per seeded T3 shard. With SEED_LIMITS a range closes past PER_SHARD rows, so every shard boundary is a cut. */
const PER_SHARD = 3;
const SEED_LIMITS: PlanLimits = { ...DEFAULT_PLAN_LIMITS, maxT3Rows: 2 * PER_SHARD };

const byKey = (a: { key: string }, b: { key: string }) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0);

/** `count` distinct names on both sides of the sibling keyspace, sorted by key. */
function names(count: number, host = 'host'): NameObservation[] {
	return Array.from({ length: count }, (_, i) => obs(`${host}${i}.zone${i % 11}.example${i % 13}.${TLDS[i % 4]}`)).sort(byKey);
}

/** The same keys seen again later, so every row folds with its T3 row. */
const seenAgain = (rows: NameObservation[]) =>
	rows.map((row) => ({ ...row, firstSeen: row.firstSeen - DAY_S, notAfter: row.notAfter + DAY_S }));

/** Seeds tier 3 with one shard per PER_SHARD rows of `base` and returns the planner's cuts over it. */
async function seedShards(env: TestEnv, base: NameObservation[]): Promise<string[]> {
	await ingest(env, at(0, 0, 5), base);
	const inputs = (await runsOf(0)).map((run) => run.id).sort();
	const shardCuts = base.map((row) => row.key).filter((_, i) => i > 0 && i % PER_SHARD === 0);
	const job: CompactionJob = { id: 'seed', generation: 1, tier: 3, inputs, cuts: [...FIXED, ...shardCuts].sort(), now: T_S };
	expect(await runCompactionJob(env, job)).toBe('applied');
	return cutsFor(await runsOf(3), SEED_LIMITS.maxT3Rows / 2);
}

const runsOf = async (tier: number) => (await catalog()).filter((run) => run.tier === tier);

/** What a binding wrapped by `wrap` did. */
interface Metered {
	/** R2 puts. */
	puts: number;
	/** D1 `meta.rows_written` summed over batches: rows plus index entries, what D1 bills. */
	rowsWritten: number;
}

/** Wraps `target` so that `method` runs `spy` around the real call. */
function wrap<T extends object>(target: T, method: string, spy: (call: () => Promise<unknown>) => Promise<unknown>): T {
	return new Proxy(target, {
		get(object, property) {
			const value = Reflect.get(object, property);
			if (typeof value !== 'function') return value;
			const bound = value.bind(object);
			return property === method ? (...args: unknown[]) => spy(() => bound(...args)) : bound;
		},
	});
}

/** Runs the cron at `nowMs` with `limits`, then every job it enqueued, metering the jobs' R2 puts and D1 writes. */
async function planAndDrain(env: TestEnv, nowMs: number, limits: PlanLimits): Promise<{ jobs: CompactionJob[] } & Metered> {
	const before = env.queue.sent.length;
	await runCompactionCron(env, nowMs, limits);
	const jobs = env.queue.sent.slice(before);
	const metered: Metered = { puts: 0, rowsWritten: 0 };
	const INDEX = wrap(env.INDEX, 'put', (call) => (metered.puts++, call()));
	const CURSORS = wrap(env.CURSORS, 'batch', async (call) => {
		const results = (await call()) as D1Result[];
		for (const result of results) metered.rowsWritten += result.meta.rows_written;
		return results;
	});
	for (const job of jobs) expect(await runCompactionJob({ ...env, INDEX, CURSORS }, job, undefined, nowMs)).toBe('applied');
	return { jobs, ...metered };
}

async function readAll(env: TestEnv, nowMs: number): Promise<NameObservation[]> {
	const reader = createReader(env, () => nowMs);
	return (await Promise.all(TLDS.map((tld) => reader.scan(tld, { limit: 100_000 })))).flatMap((page) => page.names);
}

/** The index of the cut range holding `key`, as plan.ts counts it: the number of cuts <= key. */
const rangeOf = (cuts: readonly string[], key: string) => cuts.filter((cut) => cut <= key).length;
const withinOneRange = (run: CatalogRow, cuts: readonly string[]) => rangeOf(cuts, run.key_lo) === rangeOf(cuts, run.key_hi);

describe('coarseCuts', () => {
	const cuts = [...FIXED, ...Array.from({ length: 938 }, (_, i) => `com\x01cut${String(i).padStart(4, '0')}`)].sort();

	it('keeps at most maxRanges - 1 cuts in order, always the fixed ones, and every cut when they fit', () => {
		const coarse = coarseCuts(cuts, MAX_T1_RANGES);
		expect(coarse.length).toBeLessThanOrEqual(MAX_T1_RANGES - 1);
		expect(coarse.length).toBeGreaterThan(MAX_T1_RANGES / 4);
		expect(coarse).toEqual(cuts.filter((cut) => coarse.includes(cut)));
		expect(coarse).toEqual(expect.arrayContaining(FIXED));
		expect(coarseCuts(cuts.slice(0, MAX_T1_RANGES - 1), MAX_T1_RANGES)).toEqual(cuts.slice(0, MAX_T1_RANGES - 1));
		expect(coarseCuts(cuts, 1)).toEqual(FIXED);
	});

	it('is chosen by content: a cut that comes or goes moves no other coarse cut while the level holds, and smaller subsets nest', () => {
		const coarse = coarseCuts(cuts, MAX_T1_RANGES);
		const without = (cut: string) => cuts.filter((other) => other !== cut);
		const plain = cuts.find((cut) => !coarse.includes(cut))!;
		const kept = coarse.find((cut) => !FIXED.includes(cut))!;
		expect(coarseCuts(without(plain), MAX_T1_RANGES)).toEqual(coarse);
		expect(coarseCuts(without(kept), MAX_T1_RANGES)).toEqual(coarse.filter((cut) => cut !== kept));
		const added = 'com\x01cut0500a';
		expect(coarseCuts([...cuts, added].sort(), MAX_T1_RANGES).filter((cut) => cut !== added)).toEqual(coarse);
		const half = coarseCuts(cuts, MAX_T1_RANGES / 2);
		expect(half.length).toBeLessThan(coarse.length);
		expect(half.every((cut) => coarse.includes(cut))).toBe(true);
	});
});

describe('T0 -> T1 at coarse cuts (SQ-491)', () => {
	/**
	 * One T0 -> T1 job over the seeded ~940 cuts, closed at at most `maxT1Ranges` ranges (Infinity: every cut, the
	 * path before SQ-491). Every row is seen again, so every cut range of the base rows holds T0 rows.
	 */
	async function oneT1Job(base: NameObservation[], maxT1Ranges: number) {
		await applyCatalog();
		const env = testEnv();
		const cuts = await seedShards(env, base);
		expect(cuts.length).toBeGreaterThanOrEqual(930);
		await ingest(env, at(0, 2, 5), seenAgain(base));
		// 02:32: the window [02:00, 02:15) is due, and nothing else is planned.
		const { jobs, puts, rowsWritten } = await planAndDrain(env, at(0, 2, 32), { ...SEED_LIMITS, maxT1Ranges });
		expect(jobs.map((job) => [job.tier, job.inputs.length])).toEqual([[1, 1]]);
		const jobCuts = jobs[0]!.cuts;
		expect(jobCuts).toEqual(coarseCuts(cuts, maxT1Ranges));
		const t1 = await runsOf(1);
		for (const run of t1) expect(withinOneRange(run, jobCuts), run.r2_key).toBe(true);
		// One run per range that holds rows; the sibling keyspace holds none.
		expect(t1.length).toBe(new Set(base.map((row) => rangeOf(jobCuts, row.key))).size);
		return { cuts: cuts.length, runs: t1.length, puts, rowsWritten, reads: await readAll(env, at(0, 2, 32)) };
	}

	it('closes one T0 -> T1 job over ~940 cuts into at most MAX_T1_RANGES runs, and reads match the full-cut path', async ({ task }) => {
		const base = names(941 * PER_SHARD);
		const full = await oneT1Job(base, Number.POSITIVE_INFINITY);
		const coarse = await oneT1Job(base, MAX_T1_RANGES);
		// Kept in the reporter's JSON (`meta`), so a run records the cost of each path.
		Object.assign(task.meta, { full: { ...full, reads: full.reads.length }, coarse: { ...coarse, reads: coarse.reads.length } });
		expect(full.runs).toBeGreaterThanOrEqual(930);
		expect(coarse.runs).toBeLessThanOrEqual(MAX_T1_RANGES);
		expect([full.puts, coarse.puts]).toEqual([full.runs, coarse.runs]);
		// D1 writes fall with the runs: one insert, and its index entries, per output run.
		expect(coarse.rowsWritten).toBeGreaterThan(0);
		expect(coarse.rowsWritten).toBeLessThan(full.rowsWritten / 4);
		expect(coarse.reads).toEqual(full.reads);
		expect(coarse.reads).toEqual(expectedRows([...base, ...seenAgain(base)], Math.floor(at(0, 2, 32) / 1000)));
	});

	it('puts a key at a coarse cut in the range it opens, writes no run for a coarse range without T0 rows, and lookups match', async () => {
		const env = testEnv();
		const base = names(200 * PER_SHARD);
		const cuts = await seedShards(env, base);
		const limits = { ...SEED_LIMITS, maxT1Ranges: 16 };
		const coarse = coarseCuts(cuts, limits.maxT1Ranges);
		const inner = coarse.filter((cut) => !FIXED.includes(cut));
		expect(inner.length).toBeGreaterThanOrEqual(3);
		// A row exactly at one coarse cut, and none in the coarse range that starts at the next one.
		const boundary = base.find((row) => row.key === inner[0])!;
		const emptyLo = inner[1]!;
		const emptyHi = coarse[coarse.indexOf(emptyLo) + 1] ?? '\uffff';
		const inEmpty = (key: string) => key >= emptyLo && key < emptyHi;
		const update = seenAgain(base.filter((row) => !inEmpty(row.key)));
		expect(update.some((row) => row.key === boundary.key)).toBe(true);
		const reader = createReader(env, () => at(0, 2, 32));
		const lookups = [boundary.name, base.find((row) => inEmpty(row.key))!.name, base.find((row) => row.key < boundary.key)!.name];
		await ingest(env, at(0, 2, 5), update);
		const before = await Promise.all(lookups.map((name) => reader.scan(name, { limit: 100 })));

		const { jobs } = await planAndDrain(env, at(0, 2, 32), limits);
		expect(jobs.map((job) => job.cuts)).toEqual([coarse]);
		const t1 = await runsOf(1);
		expect(t1.length).toBeLessThanOrEqual(limits.maxT1Ranges);
		// One run per coarse range that has T0 rows, none spanning a coarse cut, and none empty.
		expect(t1.length).toBe(new Set(update.map((row) => rangeOf(coarse, row.key))).size);
		expect(t1.every((run) => withinOneRange(run, coarse) && run.rows > 0)).toBe(true);
		expect(t1.some((run) => inEmpty(run.key_lo) || inEmpty(run.key_hi))).toBe(false);
		expect(t1.find((run) => run.key_lo <= boundary.key && boundary.key <= run.key_hi)!.key_lo).toBe(boundary.key);
		const now = Math.floor(at(0, 2, 32) / 1000);
		const after = await Promise.all(lookups.map((name) => reader.scan(name, { limit: 100 })));
		expect(after).toEqual(before);
		expect(after.map((page) => page.names)).toEqual(
			lookups.map((name) =>
				expectedRows(
					[...base, ...update].filter((row) => row.name === name),
					now,
				),
			),
		);
		expect(await readAll(env, at(0, 2, 32))).toEqual(expectedRows([...base, ...update], now));
	});

	it('the roll-up and T1 -> T2 write coarse T1 runs back at every cut, and T2 needs no re-cut', async () => {
		const env = testEnv();
		const base = names(100 * PER_SHARD);
		const cuts = await seedShards(env, base);
		const limits = { ...SEED_LIMITS, maxT1Ranges: 8 };
		const all = [...base];
		for (const [mm, tag] of [
			[5, 'a'],
			[20, 'b'],
		] as const) {
			const batch = [...seenAgain(base.filter((_, i) => i % 2 === 0)), ...names(60, tag)];
			all.push(...batch);
			await ingest(env, at(0, 2, mm), batch);
		}
		await planAndDrain(env, at(0, 2, 32), limits);
		await planAndDrain(env, at(0, 2, 47), limits);
		const coarseRuns = await runsOf(1);
		expect(coarseRuns.some((run) => !withinOneRange(run, cuts))).toBe(true);

		// 03:17 rolls up hour 02: each coarse range in one job, written back closed at every cut inside it.
		const rollUp = await planAndDrain(env, at(0, 3, 17), limits);
		expect(rollUp.jobs.length).toBeGreaterThan(0);
		expect(rollUp.jobs.every((job) => job.tier === 1)).toBe(true);
		expect(rollUp.jobs.some((job) => job.cuts.length > 0)).toBe(true);
		const rolled = await runsOf(1);
		expect(rolled.every((run) => withinOneRange(run, cuts))).toBe(true);
		expect(await readAll(env, at(0, 3, 17))).toEqual(expectedRows(all, Math.floor(at(0, 3, 17) / 1000)));

		// Day 1, 00:17: T1 -> T2 at every cut; 01:17: T3 merges with no T2 -> T2 re-cut.
		const t2 = await planAndDrain(env, at(1, 0, 17), limits);
		expect(t2.jobs.every((job) => job.tier === 2)).toBe(true);
		expect((await runsOf(2)).every((run) => withinOneRange(run, cuts))).toBe(true);
		const t3 = await planAndDrain(env, at(1, 1, 17), limits);
		expect(t3.jobs.length).toBeGreaterThan(0);
		expect(t3.jobs.every((job) => job.tier === 3)).toBe(true);
		expect(await runsOf(2)).toEqual([]);
		expect(await readAll(env, at(1, 1, 17))).toEqual(expectedRows(all, Math.floor(at(1, 1, 17) / 1000)));
	});
});
