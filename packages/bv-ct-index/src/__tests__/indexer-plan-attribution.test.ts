// SPDX-License-Identifier: BUSL-1.1
/** Scheduler attribution is additive: semantic jobs and legacy execution remain unchanged. */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { parseCompactionJob, runCompactionBatch } from '../indexer/compact';
import type { CompactionJob } from '../indexer/compact';
import { planCompactions, runCompactionCron, sendJobs } from '../indexer/plan';
import worker from '../index';
import { COMPACTION_CRON } from '../indexer/plan';
import { applyCatalog, catalog, fakeBatch, ingest, obs, testEnv, T, DAY_MS, HOUR_MS } from './indexer-harness';

beforeEach(applyCatalog);
afterEach(() => vi.restoreAllMocks());
const PLAN = '00000000-0000-4000-8000-000000000001';
const at = (minute: number) => Math.floor(T / DAY_MS) * DAY_MS + HOUR_MS + minute * 60_000;
const legacy: CompactionJob = { id: 'semantic-id', generation: 1, tier: 1, inputs: ['input'], cuts: [], now: 1 };

describe('compaction plan attribution', () => {
	it('accepts legacy jobs and valid UUID tags, but refuses malformed optional tags', () => {
		expect(parseCompactionJob(legacy)).toBe(legacy);
		const tagged = { ...legacy, planId: PLAN };
		expect(parseCompactionJob(tagged)).toBe(tagged);
		for (const planId of [undefined, null, 1, '', 'not-a-uuid', PLAN + 'suffix']) {
			expect(parseCompactionJob({ ...legacy, planId })).toBeNull();
		}
	});

	it('assigns one invocation UUID without changing semantic IDs, including same-second transitional full planning', async () => {
		const env = testEnv();
		await ingest(env, at(1), [obs('api.example.com')]);
		const semantic = await planCompactions(env.CURSORS, at(17));
		const full = await runCompactionCron(env, at(17));
		const transitional = await runCompactionCron(env, at(17), undefined, true);
		expect(full.planId).not.toBe(transitional.planId);
		expect(full.jobs).toHaveLength(1);
		expect(full.jobs[0]).toEqual({ ...semantic[0], planId: full.planId });
		expect(transitional.jobs[0]).toEqual({ ...semantic[0], planId: transitional.planId });
		expect(full.jobs[0]!.id).toBe(transitional.jobs[0]!.id);
	});

	it('keeps full and ordinary job logs attributable without mixing their completion counts', async () => {
		const env = testEnv();
		for (let i = 0; i < 8; i++) await ingest(env, at(i), [obs(`host-${i}.example.com`)]);
		const full = await runCompactionCron(env, at(17));
		const ordinary = await runCompactionCron(env, at(22));
		const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
		await runCompactionBatch(fakeBatch('bv-ct-index-compact', [...full.jobs, ...ordinary.jobs]), env);
		const lines = log.mock.calls.map(([line]) => String(line)).filter((line) => line.startsWith('{')).map((line) => JSON.parse(line));
		for (const plan of [full, ordinary]) {
			const tagged = lines.filter((line) => line.planId === plan.planId);
			expect(tagged.filter((line) => line.event === 'ct_compaction_job')).toHaveLength(plan.jobs.length);
			expect(tagged.filter((line) => line.event === 'ct_compaction_job_done')).toHaveLength(plan.jobs.length);
			expect(tagged.every((line) => line.now === plan.jobs[0]!.now)).toBe(true);
		}
		expect(lines.find((line) => line.planId === ordinary.planId && line.event === 'ct_compaction_job_done').outcome).toBe('stale');
		expect((await catalog()).filter((run) => run.tier === 1).every((run) => run.r2_key.startsWith(`runs/t1/${full.jobs[0]!.id}/`))).toBe(true);
	});

	it('emits the invocation tag in the scheduled plan log, including empty plans', async () => {
		const env = testEnv();
		const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
		await worker.scheduled({ cron: COMPACTION_CRON, scheduledTime: at(22), noRetry: () => undefined }, env);
		const plan = log.mock.calls.map(([line]) => JSON.parse(String(line))).find((line) => line.event === 'ct_compaction_plan');
		expect(plan).toMatchObject({ planId: expect.stringMatching(/^[0-9a-f-]{36}$/), jobs: 0, killed: false });
	});

	it('includes optional metadata and UTF-8 bytes in actual sendBatch limits', async () => {
		const batches: CompactionJob[][] = [];
		const queue = { sendBatch: async (messages: Iterable<{ body: CompactionJob }>) => { batches.push([...messages].map((message) => message.body)); } };
		const jobs = Array.from({ length: 250 }, (_, i) => ({ ...legacy, id: `job-${i}`, planId: PLAN, cuts: ['é'.repeat(1100)] }));
		await sendJobs(queue as unknown as Queue<CompactionJob>, jobs);
		expect(batches.flat()).toEqual(jobs);
		expect(batches).toHaveLength(3);
		expect(batches[0]!.length).toBeLessThan(100);
		for (const batch of batches) {
			expect(batch.length).toBeLessThanOrEqual(100);
			expect(batch.reduce((sum, job) => sum + new TextEncoder().encode(JSON.stringify(job)).byteLength, 0)).toBeLessThanOrEqual(200 * 1024);
		}
	});
});
