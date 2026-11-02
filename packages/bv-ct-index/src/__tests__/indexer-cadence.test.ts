// SPDX-License-Identifier: BUSL-1.1
/**
 * Fewer live runs for a read to open (SQ-402): T0 -> T1 every 5 min, the hourly T1 roll-up, and compaction
 * output puts that run in parallel.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { runCompactionBatch, runCompactionJob, PUT_CONCURRENCY } from '../indexer/compact';
import type { JobStats } from '../indexer/compact';
import worker from '../index';
import { currentGeneration } from '../indexer/catalog';
import { COMPACTION_CRON, TRANSITIONAL_COMPACTION_CRON, T0_MIN_AGE_MS, T0_WINDOW_MS, runCompactionCron, planCompactions, DEFAULT_PLAN_LIMITS } from '../indexer/plan';
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
	scanAll,
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

describe('size-aware five-minute T0 planning', () => {
	it('pairs the canonical trigger and window, retaining only the quarter-hour transition', () => {
		expect(COMPACTION_CRON).toBe('2,7,12,17,22,27,32,37,42,47,52,57 * * * *');
		expect(TRANSITIONAL_COMPACTION_CRON).toBe('2,17,32,47 * * * *');
		expect(T0_WINDOW_MS).toBe(5 * 60_000);
		expect(T0_MIN_AGE_MS).toBe(2 * 60_000);
	});

	it.each([1, 2, 3, 4, 5, 6, 7])('defers %i inputs across ordinary windows, but full recovery never starves them', async (count) => {
		const env = testEnv();
		for (let i = 0; i < count; i++) await ingest(env, at(0, 0, i), batchAt(`held-${i}`));
		for (const minute of [22, 27, 32, 37, 42, 47, 52, 57]) expect((await cronAndDrain(env, at(0, 0, minute))).jobs).toEqual([]);
		const full = await cronAndDrain(env, at(0, 1, 17));
		expect(full.jobs.map((job) => job.inputs.length)).toEqual([count]);
		expect(full.outcomes).toEqual(['applied']);
		expect((await catalog()).filter((run) => run.tier === 0)).toEqual([]);
	});

	it('combines eight old windows within one UTC creation hour, preserving pages and cursors', async () => {
		const env = testEnv();
		const names: NameObservation[] = [];
		for (let i = 0; i < 8; i++) {
			const rows = batchAt(`batch-${i}`);
			names.push(...rows);
			await ingest(env, at(0, 0, i * 5), rows);
		}
		const result = await cronAndDrain(env, at(0, 1, 2));
		expect(result.jobs.map((job) => [job.tier, job.inputs.length])).toEqual([[1, 8]]);
		expect(result.snapshot).toBeNull();
		expect(await scanAll(createReader(env, () => at(0, 1, 2)), 'com', 7)).toEqual(expectedRows(names, at(0, 1, 2) / 1000));
		// Ordinary ticks do not roll up the previous hour's T1, even though it is due.
		expect((await cronAndDrain(env, at(0, 1, 7))).jobs).toEqual([]);
	});

	it('keeps small old-hour remnants separate until full recovery', async () => {
		const env = testEnv();
		for (let i = 0; i < 4; i++) {
			await ingest(env, at(0, 0, i), batchAt(`old-${i}`));
			await ingest(env, at(0, 1, i), batchAt(`new-${i}`));
		}
		expect((await cronAndDrain(env, at(0, 1, 12))).jobs).toEqual([]);
		const full = await cronAndDrain(env, at(0, 1, 17));
		expect(full.jobs.map((job) => job.inputs.length)).toEqual([4, 4]);
	});

	it('progresses row-closed chunks and an oversized singleton while deferring the small tail', async () => {
		const env = testEnv();
		for (let i = 0; i < 3; i++) await ingest(env, at(0, 0, i), batchAt(`rows-${i}`, 3));
		const limits = { ...DEFAULT_PLAN_LIMITS, maxRows: 5 };
		const planned = await planCompactions(env.CURSORS, at(0, 0, 12), limits, false);
		expect(planned.map((job) => job.inputs.length)).toEqual([1, 1]);
		await env.CURSORS.prepare('DELETE FROM runs').run();
		await ingest(env, at(0, 0, 0), batchAt('oversized', 6));
		expect((await planCompactions(env.CURSORS, at(0, 0, 12), limits, false)).map((job) => job.inputs.length)).toEqual([1]);
	});

	it('progresses an input-bound chunk below eight without raising its configured cap', async () => {
		const env = testEnv();
		for (let i = 0; i < 5; i++) await ingest(env, at(0, 0, i), batchAt(`input-${i}`));
		const jobs = await planCompactions(env.CURSORS, at(0, 0, 12), { ...DEFAULT_PLAN_LIMITS, maxInputs: 4 }, false);
		expect(jobs.map((job) => job.inputs.length)).toEqual([4]);
	});

	it('accepts quarter-hour propagation as T0-only recovery without threshold or generation snapshot', async () => {
		const env = testEnv();
		await ingest(env, at(0, 0, 1), batchAt('old'));
		await env.CURSORS.prepare("INSERT INTO meta (k, v) VALUES ('generation_started_at', ?1)").bind(new Date(at(-8, 0, 0)).toISOString()).run();
		const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
		await worker.scheduled({ cron: TRANSITIONAL_COMPACTION_CRON, scheduledTime: at(0, 1, 32), noRetry: () => undefined }, env);
		expect(env.queue.sent.map((job) => [job.tier, job.inputs.length])).toEqual([[1, 1]]);
		expect(await currentGeneration(env.CURSORS)).toBe(1);
		expect(log.mock.calls.some(([line]) => String(line).includes('ct_compaction_transition'))).toBe(true);
	});

	it('keeps full :17 generation snapshots and downstream day-tier planning', async () => {
		const env = testEnv();
		await ingest(env, at(0, 0, 1), batchAt('old'));
		await cronAndDrain(env, at(0, 0, 17));
		await env.CURSORS.prepare("INSERT INTO meta (k, v) VALUES ('generation_started_at', ?1)").bind(new Date(at(-8, 0, 0)).toISOString()).run();
		await worker.scheduled({ cron: TRANSITIONAL_COMPACTION_CRON, scheduledTime: at(1, 0, 17), noRetry: () => undefined }, env);
		expect(await currentGeneration(env.CURSORS)).toBe(2);
		expect(env.queue.sent.at(-1)!.tier).toBe(2);
	});

	it('does not plan due overlapping higher-tier work at an ordinary tick, with a full-plan positive control', async () => {
		const env = testEnv();
		await ingest(env, at(0, 0, 1), batchAt('first'));
		await cronAndDrain(env, at(0, 0, 17));
		await ingest(env, at(0, 0, 20), batchAt('second'));
		await cronAndDrain(env, at(0, 1, 17));
		const now = at(0, 2, 2);
		const full = await planCompactions(env.CURSORS, now, DEFAULT_PLAN_LIMITS, true);
		expect(full.map((job) => [job.tier, job.inputs.length])).toEqual([[1, 2]]);
		expect((await cronAndDrain(env, now)).jobs).toEqual([]);
	});

	it('does not roll up key-disjoint parts or current-hour T1 outputs, but later overlapping outputs roll up', async () => {
		const env = testEnv();
		await ingest(env, at(0, 1, 5), batchAt('a', 300));
		await ingest(env, at(0, 1, 6), batchAt('b', 300));
		expect((await cronAndDrain(env, at(0, 1, 17), SMALL)).outcomes).toEqual(['applied']);
		const parts = (await catalog()).filter((run) => run.tier === 1);
		expect(parts.length).toBeGreaterThan(2);
		expect((await cronAndDrain(env, at(0, 2, 17), SMALL)).jobs).toEqual([]);
		await ingest(env, at(0, 2, 20), batchAt('c', 300));
		const recovery = await runCompactionCron(env, at(0, 2, 47), DEFAULT_PLAN_LIMITS, true);
		expect(recovery.jobs).toHaveLength(1);
		for (const job of recovery.jobs) expect(await runCompactionJob(env, job, SMALL, at(0, 2, 47))).toBe('applied');
		// A full plan in the same hour still excludes the new T1 outputs from its roll-up.
		expect(await planCompactions(env.CURSORS, at(0, 2, 52), DEFAULT_PLAN_LIMITS, true)).toEqual([]);
		const next = await cronAndDrain(env, at(0, 3, 17), SMALL);
		expect(next.jobs.map((job) => job.tier)).toEqual([1]);
		expect(next.jobs[0]!.inputs.length).toBeGreaterThan(parts.length);
		expect(next.jobs[0]!.inputs).toEqual(expect.arrayContaining(parts.map((run) => run.id)));
	});

	it('keeps canonical eligibility half-open across all 288 UTC five-minute ticks and jitter', async () => {
		const env = testEnv();
		for (const jitter of [-1, 0, 1, 55_548]) for (let tick = 0; tick < 288; tick++) {
			const nominal = at(0, 0, 2) + tick * T0_WINDOW_MS;
			const end = Math.floor((nominal + jitter - T0_MIN_AGE_MS) / T0_WINDOW_MS) * T0_WINDOW_MS;
			await env.CURSORS.prepare('DELETE FROM runs').run();
			await env.CURSORS.batch([end - 1, end].map((stamp, i) => env.CURSORS.prepare('INSERT INTO runs (id, generation, tier, key_lo, key_hi, rows, created_at) VALUES (?1, 1, 0, ?2, ?2, 1, ?3)').bind(`edge-${i}`, 'com\x01example\x01host', new Date(stamp).toISOString())));
			const jobs = await planCompactions(env.CURSORS, nominal + jitter, DEFAULT_PLAN_LIMITS, false, true);
			expect(jobs.flatMap((job) => job.inputs)).toEqual(['edge-0']);
		}
	}, 60_000);
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
