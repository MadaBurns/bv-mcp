// SPDX-License-Identifier: BUSL-1.1
/**
 * Fewer live runs for a read to open (SQ-402): T0 -> T1 every 15 min, the hourly T1 roll-up, and compaction
 * output puts that run in parallel.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runCompactionBatch, runCompactionJob, PUT_CONCURRENCY } from '../indexer/compact';
import type { JobStats } from '../indexer/compact';
import worker from '../index';
import { currentGeneration } from '../indexer/catalog';
import {
	COMPACTION_CRON,
	TRANSITIONAL_COMPACTION_CRON,
	T0_MIN_AGE_MS,
	T0_WINDOW_MS,
	T0_WINDOW_PHASE_MS,
	runCompactionCron,
	t0WindowEnd,
} from '../indexer/plan';
import { createReader } from '../indexer/read';
import type { NameObservation } from '../types';
import {
	DAY_MS,
	HOUR_MS,
	T,
	applyCatalog,
	catalog,
	cronAndDrain,
	expectedRows,
	fakeBatch,
	ingest,
	obs,
	testEnv,
	withFault,
} from './indexer-harness';
import type { TestEnv } from './indexer-harness';

beforeEach(applyCatalog);
afterEach(() => {
	vi.restoreAllMocks();
});

/** Day `day` (0 = the day of T) at hh:mm UTC. */
const at = (day: number, hh: number, mm: number) => Math.floor(T / DAY_MS) * DAY_MS + day * DAY_MS + hh * HOUR_MS + mm * 60_000;
/** Small output runs, so a job writes several parts per key range. */
const SMALL = { targetRawBytes: 8 * 1024 };

const batchAt = (tag: string, count = 3) => Array.from({ length: count }, (_, i) => obs(`${tag}-${i}.zone${i % 5}.example.com`));

async function readAll(env: TestEnv, nowMs: number): Promise<NameObservation[]> {
	return (await createReader(env, () => nowMs).scan('com', { limit: 100_000 })).names;
}

describe('T0 -> T1 every 15 minutes', () => {
	it('keeps the age floor and adjacent windows across 96 UTC ticks and scheduler seconds/milliseconds', () => {
		const midnight = Date.UTC(2026, 10, 1);
		for (const jitter of [-1, 0, 1, 1_000, 55_548, 59_999]) {
			let previousEnd: number | undefined;
			for (let tick = 0; tick < 96; tick++) {
				const scheduled = midnight + (2 + tick * 15) * 60_000;
				const now = scheduled + jitter;
				const end = t0WindowEnd(now);
				expect(now - end).toBeGreaterThanOrEqual(10 * 60_000);
				expect(now - end).toBeLessThan(25 * 60_000);
				if (jitter >= 0) {
					expect(now - end).toBe(10 * 60_000 + jitter);
					// The old epoch-aligned cutoff at a nominal tick had age seventeen minutes.
					expect(end).toBe(scheduled - 17 * 60_000 + 7 * 60_000);
				}
				if (previousEnd !== undefined) expect(end - T0_WINDOW_MS).toBe(previousEnd);
				previousEnd = end;
			}
		}
		expect(t0WindowEnd(midnight + 2 * 60_000)).toBe(midnight - 8 * 60_000);
		expect(t0WindowEnd(midnight + DAY_MS + 2 * 60_000)).toBe(midnight + DAY_MS - 8 * 60_000);
	});

	it('plans a twelve-minute-old T0 run at :32 while preserving the ten-minute age floor', async () => {
		const env = testEnv();
		await ingest(env, at(0, 1, 20), batchAt('newly-due'));
		await ingest(env, at(0, 1, 22) + 1, batchAt('too-young'));
		const due = (await catalog()).find((run) => run.r2_key.includes(`/${at(0, 1, 20)}-`))!;
		const result = await cronAndDrain(env, at(0, 1, 32));
		expect(result.jobs.map((job) => [job.tier, job.inputs])).toEqual([[1, [due.id]]]);
		expect(result.outcomes).toEqual(['applied']);
		expect(result.snapshot).toBeNull();
		expect((await catalog()).filter((run) => run.tier === 0).map((run) => run.r2_key)).toEqual([
			expect.stringContaining(`/${at(0, 1, 22) + 1}-`),
		]);
	});

	it('selects exact half-open phase boundaries through the planner', async () => {
		const env = testEnv();
		const start = at(0, 1, 7);
		const end = at(0, 1, 22);
		const stamps = [start - 1, start, end - 1, end];
		for (const [i, stamp] of stamps.entries()) await ingest(env, stamp, batchAt(`edge-${i}`));
		const runs = await catalog();
		const idsAt = (selected: number[]) => selected.map((stamp) => runs.find((run) => run.r2_key.includes(`/${stamp}-`))!.id).sort();
		const result = await cronAndDrain(env, at(0, 1, 32));
		expect(result.jobs.map((job) => [job.tier, job.inputs])).toEqual([[1, idsAt([start, end - 1])]]);
		expect(result.outcomes).toEqual(['applied']);
		expect((await catalog()).filter((run) => run.tier === 0).map((run) => run.id).sort()).toEqual(idsAt([start - 1, end]));
	});

	it('keeps a legacy-phase handoff fragment readable until the first verified full :17 recovers it', async () => {
		const env = testEnv();
		const names: NameObservation[] = [];
		// The old 00:17 full tick ended at 00:00; the first new ordinary 00:32 tick starts at 00:07.
		for (const [i, stamp] of [at(0, 0, 0), at(0, 0, 3) + 30_000, at(0, 0, 7) - 1].entries()) {
			const batch = batchAt(`handoff-${i}`);
			names.push(...batch);
			await ingest(env, stamp, batch);
		}
		const stranded = (await catalog()).map((run) => run.id).sort();
		for (const tick of [at(0, 0, 32), at(0, 0, 47), at(0, 1, 2)]) {
			const ordinary = await cronAndDrain(env, tick);
			expect(ordinary.jobs).toEqual([]);
			expect(ordinary.snapshot).toBeNull();
		}
		expect(await readAll(env, at(0, 1, 2))).toEqual(expectedRows(names, Math.floor(at(0, 1, 2) / 1000)));
		const recovery = await cronAndDrain(env, at(0, 1, 17));
		expect(recovery.jobs.map((job) => [job.tier, job.inputs])).toEqual([[1, stranded]]);
		expect(recovery.outcomes).toEqual(['applied']);
		expect((await catalog()).filter((run) => run.tier === 0)).toEqual([]);
		expect(await readAll(env, at(0, 1, 17))).toEqual(expectedRows(names, Math.floor(at(0, 1, 17) / 1000)));
	});

	it('accepts the previous fast :32 tick as older-window T0-only recovery during trigger propagation', async () => {
		const env = testEnv();
		await ingest(env, at(0, 0, 12), batchAt('old-a'));
		await cronAndDrain(env, at(0, 0, 32));
		await ingest(env, at(0, 0, 27), batchAt('old-b'));
		await cronAndDrain(env, at(0, 0, 47));
		const oldT1 = (await catalog()).filter((run) => run.tier === 1).map((run) => run.id);
		expect(oldT1).toHaveLength(2);
		await ingest(env, at(0, 0, 50), batchAt('missed-previous-hour'));
		for (const minute of [1, 6, 11, 25]) await ingest(env, at(0, 1, minute), batchAt(`transition-${minute}`));
		await env.CURSORS.prepare("INSERT INTO meta (k, v) VALUES ('generation_started_at', ?1)")
			.bind(new Date(at(-8, 0, 0)).toISOString()).run();
		const before = env.queue.sent.length;
		const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
		await worker.scheduled({ cron: TRANSITIONAL_COMPACTION_CRON, scheduledTime: at(0, 1, 32), noRetry: () => undefined }, env);
		const jobs = env.queue.sent.slice(before);
		expect(jobs.map((job) => [job.tier, job.inputs.length])).toEqual([[1, 4]]);
		expect(jobs.flatMap((job) => job.inputs).some((id) => oldT1.includes(id))).toBe(false);
		expect(jobs[0]!.now).toBe(Math.floor(at(0, 1, 32) / 1000));
		expect(await currentGeneration(env.CURSORS)).toBe(1);
		const lines = log.mock.calls.map(([line]) => JSON.parse(String(line)) as Record<string, unknown>);
		expect(lines.some((line) => line.event === 'ct_compaction_transition' && line.cron === TRANSITIONAL_COMPACTION_CRON)).toBe(true);
		expect(lines.some((line) => line.event === 'ct_cron_unmatched')).toBe(false);
		for (const job of jobs) expect(await runCompactionJob(env, job, undefined, at(0, 1, 32))).toBe('applied');
		expect((await catalog()).filter((run) => run.tier === 0).map((run) => run.r2_key)).toEqual([
			expect.stringContaining(`/${at(0, 1, 25)}-`),
		]);
	});

	it('keeps previous fast :17 full recovery, all-tier planning, and the due generation snapshot', async () => {
		const env = testEnv();
		await ingest(env, at(0, 0, 12), batchAt('old-a'));
		await cronAndDrain(env, at(0, 0, 32));
		await ingest(env, at(0, 0, 27), batchAt('old-b'));
		await cronAndDrain(env, at(0, 0, 47));
		for (const minute of [45, 55]) await ingest(env, at(0, 0, minute), batchAt(`missed-${minute}`));
		await env.CURSORS.prepare("INSERT INTO meta (k, v) VALUES ('generation_started_at', ?1)")
			.bind(new Date(at(-8, 0, 0)).toISOString()).run();
		const before = env.queue.sent.length;
		vi.spyOn(console, 'log').mockImplementation(() => undefined);
		await worker.scheduled({ cron: TRANSITIONAL_COMPACTION_CRON, scheduledTime: at(1, 1, 17), noRetry: () => undefined }, env);
		const jobs = env.queue.sent.slice(before);
		expect(jobs.map((job) => [job.tier, job.inputs.length])).toEqual([[1, 2], [2, 2]]);
		expect(jobs.every((job) => job.generation === 2)).toBe(true);
		expect(await env.CURSORS.prepare("SELECT v FROM meta WHERE k = 'current_generation'").first('v')).toBe('2');
	});

	it('pairs the unchanged quarter-hour schedule and width with a derived phase and the same age floor', () => {
		expect(COMPACTION_CRON).toBe('2,17,32,47 * * * *');
		expect(TRANSITIONAL_COMPACTION_CRON).toBe('2,7,12,17,22,27,32,37,42,47,52,57 * * * *');
		expect(T0_WINDOW_MS).toBe(15 * 60_000);
		expect(T0_MIN_AGE_MS).toBe(10 * 60_000);
		expect(T0_WINDOW_PHASE_MS).toBe(7 * 60_000);
	});

	it('plans only the window that just came due between :17 ticks, and every tier and any older T0 run at :17', async () => {
		const env = testEnv();
		const names: NameObservation[] = [];
		const add = async (nowMs: number, tag: string) => {
			const batch = batchAt(tag);
			names.push(...batch);
			await ingest(env, nowMs, batch);
		};
		await add(at(0, 1, 12), 'a');
		await add(at(0, 1, 27), 'b');
		await add(at(0, 1, 42), 'c');
		await add(at(0, 1, 57), 'd');
		const t0 = new Map((await catalog()).map((run) => [run.r2_key.split('/')[2]!.split('-')[0]!, run.id]));
		const id = (nowMs: number) => t0.get(String(nowMs))!;

		// 01:32: the window [01:07, 01:22) ended exactly 10 min ago, and nothing else is planned.
		const first = await cronAndDrain(env, at(0, 1, 32));
		expect(first.jobs.map((job) => [job.tier, job.inputs])).toEqual([[1, [id(at(0, 1, 12))]]]);
		expect(first.outcomes).toEqual(['applied']);
		expect(first.snapshot).toBeNull();
		// A late T0 run in a window already planned waits for the next :17 tick.
		await add(at(0, 1, 17), 'late');
		const late = (await catalog()).find((run) => run.tier === 0 && run.r2_key.includes(`/${at(0, 1, 17)}-`))!.id;
		expect((await cronAndDrain(env, at(0, 1, 47))).jobs.map((job) => job.inputs)).toEqual([[id(at(0, 1, 27))]]);
		expect((await cronAndDrain(env, at(0, 2, 2))).jobs.map((job) => job.inputs)).toEqual([[id(at(0, 1, 42))]]);

		// 02:17 plans the window [01:52, 02:07) with the late run, and rolls up the T1 runs of 01:32 and 01:47 (the
		// 02:02 one belongs to this hour). Every T1 run here spans the name range below the sibling keyspace.
		const full = await cronAndDrain(env, at(0, 2, 17));
		expect(full.jobs.map((job) => [job.tier, job.inputs.length])).toEqual([
			[1, 2],
			[1, 2],
		]);
		expect(full.jobs[0]!.inputs).toEqual([id(at(0, 1, 57)), late].sort());
		expect(full.outcomes).toEqual(['applied', 'applied']);
		expect((await catalog()).map((run) => run.tier)).toEqual([1, 1, 1]);
		expect(await readAll(env, at(0, 2, 17))).toEqual(expectedRows(names, Math.floor(at(0, 2, 17) / 1000)));

		// 03:17 rolls the three into one; a tick between :17s with no T0 plans nothing.
		expect((await cronAndDrain(env, at(0, 3, 2))).jobs).toEqual([]);
		const rolled = await cronAndDrain(env, at(0, 3, 17));
		expect(rolled.jobs.map((job) => [job.tier, job.inputs.length])).toEqual([[1, 3]]);
		expect((await catalog()).map((run) => run.tier)).toEqual([1]);
		expect((await cronAndDrain(env, at(0, 4, 17))).jobs).toEqual([]);
		expect(await readAll(env, at(0, 4, 17))).toEqual(expectedRows(names, Math.floor(at(0, 4, 17) / 1000)));

		// T1 -> T2 waits for the day to end; a weekly snapshot waits for a :17 tick.
		expect((await cronAndDrain(env, at(1, 0, 17))).jobs.map((job) => job.tier)).toEqual([2]);
		expect((await cronAndDrain(env, at(8, 0, 2))).snapshot).toBeNull();
		expect((await cronAndDrain(env, at(8, 0, 17))).snapshot).toBe(2);
	});

	it('does not roll up the key-disjoint parts of one job, nor T1 runs from this hour', async () => {
		const env = testEnv();
		await ingest(env, at(0, 1, 12), batchAt('a', 300));
		await ingest(env, at(0, 1, 13), batchAt('b', 300));
		expect((await cronAndDrain(env, at(0, 1, 32), SMALL)).outcomes).toEqual(['applied']);
		const parts = (await catalog()).filter((run) => run.tier === 1);
		expect(parts.length).toBeGreaterThan(2);
		expect((await cronAndDrain(env, at(0, 2, 17), SMALL)).jobs).toEqual([]);

		await ingest(env, at(0, 2, 27), batchAt('c', 300));
		expect((await cronAndDrain(env, at(0, 2, 47), SMALL)).outcomes).toEqual(['applied']);
		// 02:47's output belongs to hour 02, so the 03:17 roll-up takes it with the 01:32 parts it overlaps.
		const next = await cronAndDrain(env, at(0, 3, 17), SMALL);
		expect(next.jobs.map((job) => job.tier)).toEqual([1]);
		expect(next.jobs[0]!.inputs.length).toBeGreaterThan(parts.length);
		expect(next.jobs[0]!.inputs).toEqual(expect.arrayContaining(parts.map((run) => run.id)));
	});
});

describe('compaction output puts', () => {
	/** An INDEX binding whose puts take a few ms, counting how many run at once; put number `failAt` rejects. */
	function slowPuts(bucket: R2Bucket, failAt = 0) {
		const stats = { active: 0, max: 0, count: 0 };
		const wrapped = withFault(bucket, 'put', async (...args: unknown[]) => {
			const n = ++stats.count;
			stats.active++;
			stats.max = Math.max(stats.max, stats.active);
			try {
				await new Promise((resolve) => setTimeout(resolve, 5));
				if (n === failAt) throw new Error('injected put failure');
				return await bucket.put(...(args as [string, Uint8Array]));
			} finally {
				stats.active--;
			}
		});
		return { bucket: wrapped, stats };
	}

	async function plannedJob(env: TestEnv) {
		await ingest(env, at(0, 1, 5), batchAt('a', 400));
		await ingest(env, at(0, 1, 6), batchAt('b', 400));
		const { jobs } = await runCompactionCron(env, at(0, 2, 17));
		expect(jobs).toHaveLength(1);
		return jobs[0]!;
	}

	it('runs at most PUT_CONCURRENCY puts at once, writes every output and reports them', async () => {
		const env = testEnv();
		const job = await plannedJob(env);
		const puts = slowPuts(env.INDEX);
		const stats: JobStats = { outputs: 0, gets: 0, putMs: 0, ms: 0 };
		expect(await runCompactionJob(testEnv({ INDEX: puts.bucket }), job, SMALL, at(0, 2, 17), stats)).toBe('applied');
		const t1 = (await catalog()).filter((run) => run.tier === 1);
		expect(t1.length).toBeGreaterThan(PUT_CONCURRENCY);
		expect(puts.stats.count).toBe(t1.length);
		expect(puts.stats.max).toBeGreaterThan(1);
		expect(puts.stats.max).toBeLessThanOrEqual(PUT_CONCURRENCY);
		expect(stats).toMatchObject({ outputs: t1.length, gets: 2 });
		expect(stats.putMs).toBeGreaterThanOrEqual(0);
	});

	it('fails the job, leaving the catalog untouched, when any output put fails', async () => {
		const env = testEnv();
		const job = await plannedJob(env);
		const before = await catalog();
		const puts = slowPuts(env.INDEX, 3);
		await expect(runCompactionJob(testEnv({ INDEX: puts.bucket }), job, SMALL, at(0, 2, 17))).rejects.toThrow('injected put failure');
		expect(await catalog()).toEqual(before);
		expect(await runCompactionJob(env, job, SMALL, at(0, 2, 17))).toBe('applied');
	});

	// SQ-412 (B1): a put that rejects at once leaves the in-flight set before anything waits on it, so only a
	// stored error can fail the job. Without one the job swapped the catalog while an output was never written.
	it.each([1, 2, 3])('fails a 9-output job, before any swap, when output put %i rejects with no delay', async (failAt) => {
		const env = testEnv();
		const job = await plannedJob(env);
		const before = await catalog();
		let calls = 0;
		const immediate = withFault(env.INDEX, 'put', (...args: unknown[]) =>
			++calls === failAt ? Promise.reject(new Error('immediate put failure')) : env.INDEX.put(...(args as [string, Uint8Array])),
		);
		await expect(runCompactionJob(testEnv({ INDEX: immediate }), job, SMALL, at(0, 2, 17))).rejects.toThrow('immediate put failure');
		expect(await catalog()).toEqual(before);
		for (const run of before) expect(await env.INDEX.head(run.r2_key)).not.toBeNull();
		// The same job then applies on its retry, and it is the 9-output shape this test claims.
		expect(await runCompactionJob(env, job, SMALL, at(0, 2, 17))).toBe('applied');
		expect((await catalog()).filter((run) => run.tier === 1)).toHaveLength(9);
	});

	// SQ-412 rework: the last output is closed by finish(), and add() and close() have nothing left to run after it.
	// Only the rethrow after finish()'s Promise.all can fail the job when that one put rejects, with no delay or a short one.
	it.each([0, 5])('fails the job, before any swap, when only the LAST of 9 output puts rejects after %i ms', async (delayMs) => {
		const env = testEnv();
		const job = await plannedJob(env);
		const before = await catalog();
		const rowsBefore = await readAll(env, at(0, 2, 17));
		let calls = 0;
		const lastOnly = withFault(env.INDEX, 'put', (...args: unknown[]) => {
			if (++calls !== 9) return env.INDEX.put(...(args as [string, Uint8Array]));
			if (delayMs === 0) return Promise.reject(new Error('last put failure'));
			return new Promise((_, reject) => setTimeout(() => reject(new Error('last put failure')), delayMs));
		});
		await expect(runCompactionJob(testEnv({ INDEX: lastOnly }), job, SMALL, at(0, 2, 17))).rejects.toThrow('last put failure');
		// The job wrote all nine outputs, so the failing put really was the final one.
		expect(calls).toBe(9);
		expect(await catalog()).toEqual(before);
		for (const run of before) expect(await env.INDEX.head(run.r2_key)).not.toBeNull();
		expect(await readAll(env, at(0, 2, 17))).toEqual(rowsBefore);
		// The retry applies and writes the same nine outputs.
		expect(await runCompactionJob(env, job, SMALL, at(0, 2, 17))).toBe('applied');
		expect((await catalog()).filter((run) => run.tier === 1)).toHaveLength(9);
	});

	it('throws the first put failure when several puts in flight reject', async () => {
		const env = testEnv();
		const job = await plannedJob(env);
		const before = await catalog();
		let calls = 0;
		// Each put rejects after a delay, so the later ones are already running when the first fails.
		const failing = withFault(env.INDEX, 'put', () => {
			const n = ++calls;
			return new Promise((_, reject) => setTimeout(() => reject(new Error(`put failure ${n}`)), 5));
		});
		await expect(runCompactionJob(testEnv({ INDEX: failing }), job, SMALL, at(0, 2, 17))).rejects.toThrow(/^put failure 1$/);
		expect(await catalog()).toEqual(before);
	});

	it('logs each job with its output count and put time once it is done', async () => {
		const env = testEnv();
		const job = await plannedJob(env);
		const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
		const batch = fakeBatch('bv-ct-index-compact', [job]);
		await runCompactionBatch(batch, env);
		expect(batch.acked).toEqual(['m0']);
		const done = log.mock.calls.map(([line]) => String(line)).find((line) => line.includes('"ct_compaction_job_done"'));
		const t1 = (await catalog()).filter((run) => run.tier === 1);
		expect(done).toBeDefined();
		expect(JSON.parse(done!)).toMatchObject({
			event: 'ct_compaction_job_done',
			id: job.id,
			tier: 1,
			outcome: 'applied',
			outputs: t1.length,
		});
	});
});
