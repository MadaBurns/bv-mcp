// SPDX-License-Identifier: BUSL-1.1
/**
 * T0 -> T1 output at a coarse subset of the cuts (SQ-491): a job writes at most MAX_T1_RANGES runs, reads match the
 * full-cut path, and the roll-up and T1 -> T2 still write their output at every cut.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { KEY_FILTER_MAX_ENTRIES, SIBLING_PREFIX } from '../codec';
import { runCompactionJob } from '../indexer/compact';
import type { CompactionJob } from '../indexer/compact';
import { DEFAULT_PLAN_LIMITS, MAX_T1_RANGES, coarseCuts, components, cutLevel, cutsFor, runCompactionCron } from '../indexer/plan';
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

	/** `count` cut keys at exactly `level`, found by trying `${prefix}${i}`. */
	const atLevel = (level: number, count: number, prefix: string) => {
		const found: string[] = [];
		for (let i = 0; found.length < count; i++) if (cutLevel(`${prefix}${i}`) === level) found.push(`${prefix}${i}`);
		return found;
	};

	it('closes into at most maxRanges ranges however many cuts tie at a level, and at least the fixed three (SQ-518)', () => {
		// 200 cuts at level 1 and 300 at level 0: the 128th highest level is a tie of 200, so all of them go.
		const tied = [...FIXED, ...atLevel(1, 200, 'com\x01a'), ...atLevel(0, 300, 'com\x01b')].sort();
		expect(coarseCuts(tied, MAX_T1_RANGES)).toEqual(FIXED);
		const spread = [...FIXED, ...[5, 4, 3, 2, 1, 0].flatMap((level) => atLevel(level, 40 << (5 - level), `org\x01l${level}x`))].sort();
		for (const maxRanges of [3, 8, 64, 128, 129, 1000]) {
			for (const set of [tied, spread, cuts]) expect(coarseCuts(set, maxRanges).length + 1).toBeLessThanOrEqual(maxRanges);
		}
		for (const maxRanges of [0, 1, 2]) expect(coarseCuts(spread, maxRanges)).toEqual(FIXED);
	});

	it('spreads coarse cuts over keys that differ only near their end: no coarse range holds 8x the mean (SQ-518)', ({ task }) => {
		const families = { sequential: cuts, names: [...FIXED, ...names(941 * PER_SHARD).map((row) => row.key)].sort() };
		for (const [family, set] of Object.entries(families)) {
			const coarse = coarseCuts(set, MAX_T1_RANGES);
			// Fine ranges per coarse range: the cuts at and after each coarse cut, up to the next one.
			const at = [-1, ...coarse.map((cut) => set.indexOf(cut)), set.length];
			const widths = at.slice(1).map((index, i) => index - at[i]!);
			const mean = (set.length + 1) / (coarse.length + 1);
			Object.assign(task.meta, { [family]: { cuts: set.length, ranges: coarse.length + 1, mean, widest: Math.max(...widths) } });
			expect(Math.max(...widths), family).toBeLessThan(8 * mean);
		}
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

	it('closes a T1 run before its key filter passes KEY_FILTER_MAX_ENTRIES, so every T1 run keeps a filter (SQ-518)', async () => {
		const env = testEnv();
		// One filter entry per row ('com\x01apex<i>'), all in one coarse range: no T3 shards, so only the fixed cuts.
		const count = KEY_FILTER_MAX_ENTRIES + 500;
		const rows = Array.from({ length: count }, (_, i) => obs(`n${i}.apex${i}.com`)).sort(byKey);
		await ingest(env, at(0, 2, 5), rows);
		await planAndDrain(env, at(0, 2, 32), SEED_LIMITS);
		const { results } = await env.CURSORS.prepare(
			'SELECT rows, key_filter IS NOT NULL AS filtered FROM runs WHERE tier = 1 ORDER BY key_lo',
		).all<{ rows: number; filtered: number }>();
		expect(results.map((run) => [Number(run.rows), Number(run.filtered)])).toEqual([
			[KEY_FILTER_MAX_ENTRIES, 1],
			[500, 1],
		]);
		const reader = createReader(env, () => at(0, 2, 32));
		for (const i of [0, count - 1]) {
			const row = rows.find((candidate) => candidate.name === `n${i}.apex${i}.com`)!;
			expect((await reader.scan(`apex${i}.com`, { limit: 10 })).names).toEqual(expectedRows([row], Math.floor(at(0, 2, 32) / 1000)));
		}
	});
});

/** True when two of `runs` share a key. Sorted by key_lo, any overlap shows between neighbours. */
const overlapping = (runs: ReadonlyArray<{ key_lo: string; key_hi: string }>) =>
	[...runs].sort((a, b) => (a.key_lo < b.key_lo ? -1 : 1)).some((run, i, sorted) => i > 0 && run.key_lo <= sorted[i - 1]!.key_hi);

describe('the T1 roll-up of a coarse range wider than a job (SQ-518)', () => {
	interface Tick {
		/** The T1 runs the roll-up planned from, with created_at. */
		before: Array<CatalogRow & { created_at: string }>;
		jobs: CompactionJob[];
		puts: number;
		/** T1 runs after its jobs. */
		after: number;
	}

	/**
	 * Simulated hours from 02:00 over ~100 cuts. In hour 02 + h, a T0 batch at each minute of `schedule[h]`, of rows seen
	 * again and new names, then the next :17 roll-up. Returns each roll-up, and checks that reads match the merge rule
	 * at the end.
	 */
	async function simulate(maxT1Ranges: number, schedule: ReadonlyArray<readonly number[]>): Promise<{ cuts: string[]; ticks: Tick[] }> {
		await applyCatalog();
		const env = testEnv();
		const base = names(100 * PER_SHARD);
		const cuts = await seedShards(env, base);
		const limits = { ...SEED_LIMITS, maxT1Ranges };
		const all = [...base];
		const ticks: Tick[] = [];
		for (const [h, minutes] of schedule.entries()) {
			const hour = 2 + h;
			for (const mm of minutes) {
				const batch = [...seenAgain(base.filter((_, i) => (i + hour + mm) % 3 === 0)), ...names(30, `h${hour}m${mm}x`)];
				all.push(...batch);
				await ingest(env, at(0, hour, mm), batch);
				await planAndDrain(env, at(0, hour, mm + 27), limits);
			}
			const { results: before } = await env.CURSORS.prepare(
				'SELECT id, generation, tier, key_lo, key_hi, r2_key, rows, created_at FROM runs WHERE tier = 1',
			).all<CatalogRow & { created_at: string }>();
			const { jobs, puts } = await planAndDrain(env, at(0, hour + 1, 17), limits);
			ticks.push({ before, jobs, puts, after: (await runsOf(1)).length });
		}
		const end = at(0, 2 + schedule.length, 17);
		expect(await readAll(env, end)).toEqual(expectedRows(all, Math.floor(end / 1000)));
		return { cuts, ticks };
	}

	it('plans no job of key-disjoint runs, and the range stops gaining runs and jobs', async ({ task }) => {
		// maxT1Ranges 2 keeps only the fixed cuts: the names below the sibling keyspace are one coarse range of ~50 cuts.
		const { ticks } = await simulate(
			2,
			Array.from({ length: 6 }, () => [5, 20]),
		);
		Object.assign(task.meta, { ticks: ticks.map((tick) => ({ jobs: tick.jobs.length, outputs: tick.puts, t1Runs: tick.after })) });
		// Before the second roll-up the range holds the first one's output, one run per cut range, and two new coarse runs.
		const range = ticks[1]!.before.filter((run) => run.key_hi < SIBLING_PREFIX);
		const oldest = [...range].sort((a, b) => (a.created_at < b.created_at ? -1 : 1)).slice(0, DEFAULT_PLAN_LIMITS.maxInputs);
		expect(range.length).toBeGreaterThan(DEFAULT_PLAN_LIMITS.maxInputs);
		expect(overlapping(oldest)).toBe(false);
		expect(range.filter((run) => run.created_at > oldest.at(-1)!.created_at).every((run) => overlapping([run, ...oldest]))).toBe(true);
		for (const tick of ticks) {
			const byId = new Map(tick.before.map((run) => [run.id, run]));
			for (const job of tick.jobs) expect(overlapping(job.inputs.map((id) => byId.get(id)!)), job.id).toBe(true);
		}
		// The first roll-up writes one run per cut range. Later ones keep at most two, and the last hour adds no run or job.
		for (const tick of ticks) expect(tick.after).toBeLessThanOrEqual(2 * ticks[0]!.after);
		const [previous, last] = ticks.slice(-2) as [Tick, Tick];
		expect(last.after).toBeLessThanOrEqual(previous.after);
		expect(last.jobs.length).toBeLessThanOrEqual(previous.jobs.length);
	}, 120_000);

	it('rolls a coarse range that fits one job into one job of all its runs, as before', async () => {
		// 32 coarse ranges over ~100 cuts: each holds a few cut ranges, so the last roll-up's output and the new runs fit.
		// Hour 02's two coarse runs roll up at 03:17; hour 03 adds one more, which 04:17 rolls up with that output.
		const { cuts, ticks } = await simulate(32, [[5, 20], [5]]);
		// The second roll-up: each component holds the first one's output for its cut ranges and one new coarse run.
		const tick = ticks[1]!;
		const parts = components(tick.before, cuts);
		expect(parts.every((part) => part.runs.length <= DEFAULT_PLAN_LIMITS.maxInputs)).toBe(true);
		expect(parts.some((part) => part.runs.length > 2)).toBe(true);
		// Before SQ-518: one job per component whose runs overlap, holding all of them, closed at the cuts inside it.
		const expected = parts.filter((part) => overlapping(part.runs)).map((part) => [part.runs.map((run) => run.id).sort(), part.cuts]);
		expect(tick.jobs.map((job) => [job.inputs, job.cuts]).sort()).toEqual(expected.sort());
	}, 60_000);
});
