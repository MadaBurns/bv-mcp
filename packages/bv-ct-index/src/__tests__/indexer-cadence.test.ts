// SPDX-License-Identifier: BUSL-1.1
/**
 * Fewer live runs for a read to open (SQ-402): T0 -> T1 every 15 min, the hourly T1 roll-up, and compaction
 * output puts that run in parallel.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runCompactionBatch, runCompactionJob, PUT_CONCURRENCY } from '../indexer/compact';
import type { JobStats } from '../indexer/compact';
import { runCompactionCron } from '../indexer/plan';
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
	it('plans only the window that just came due between :17 ticks, and every tier and any older T0 run at :17', async () => {
		const env = testEnv();
		const names: NameObservation[] = [];
		const add = async (nowMs: number, tag: string) => {
			const batch = batchAt(tag);
			names.push(...batch);
			await ingest(env, nowMs, batch);
		};
		await add(at(0, 1, 5), 'a');
		await add(at(0, 1, 20), 'b');
		await add(at(0, 1, 35), 'c');
		await add(at(0, 1, 50), 'd');
		const t0 = new Map((await catalog()).map((run) => [run.r2_key.split('/')[2]!.split('-')[0]!, run.id]));
		const id = (nowMs: number) => t0.get(String(nowMs))!;

		// 01:32: the window [01:00, 01:15) has been over for 10 min, and nothing else is planned.
		const first = await cronAndDrain(env, at(0, 1, 32));
		expect(first.jobs.map((job) => [job.tier, job.inputs])).toEqual([[1, [id(at(0, 1, 5))]]]);
		expect(first.outcomes).toEqual(['applied']);
		expect(first.snapshot).toBeNull();
		// A late T0 run in a window already planned waits for the next :17 tick.
		await add(at(0, 1, 10), 'late');
		const late = (await catalog()).find((run) => run.tier === 0 && run.r2_key.includes(`/${at(0, 1, 10)}-`))!.id;
		expect((await cronAndDrain(env, at(0, 1, 47))).jobs.map((job) => job.inputs)).toEqual([[id(at(0, 1, 20))]]);
		expect((await cronAndDrain(env, at(0, 2, 2))).jobs.map((job) => job.inputs)).toEqual([[id(at(0, 1, 35))]]);

		// 02:17 plans the window [01:45, 02:00) with the late run, and rolls up the T1 runs of 01:32 and 01:47 (the
		// 02:02 one belongs to this hour). Every T1 run here spans the name range below the sibling keyspace.
		const full = await cronAndDrain(env, at(0, 2, 17));
		expect(full.jobs.map((job) => [job.tier, job.inputs.length])).toEqual([
			[1, 2],
			[1, 2],
		]);
		expect(full.jobs[0]!.inputs).toEqual([id(at(0, 1, 50)), late].sort());
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
		await ingest(env, at(0, 1, 5), batchAt('a', 300));
		await ingest(env, at(0, 1, 6), batchAt('b', 300));
		expect((await cronAndDrain(env, at(0, 1, 32), SMALL)).outcomes).toEqual(['applied']);
		const parts = (await catalog()).filter((run) => run.tier === 1);
		expect(parts.length).toBeGreaterThan(2);
		expect((await cronAndDrain(env, at(0, 2, 17), SMALL)).jobs).toEqual([]);

		await ingest(env, at(0, 2, 20), batchAt('c', 300));
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
