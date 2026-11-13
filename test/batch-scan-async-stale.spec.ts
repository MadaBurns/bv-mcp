// SPDX-License-Identifier: BUSL-1.1

// SQ-564 — a job whose consumer died on every delivery must read as failed, not running forever.

import { describe, expect, it, vi } from 'vitest';
import {
	ASYNC_BATCH_ABANDONED_ERROR,
	ASYNC_BATCH_MAX_ATTEMPTS,
	ASYNC_BATCH_STALE_AFTER_MS,
	getAsyncBatchJob,
	getAsyncBatchJobForRead,
	startAsyncBatchScan,
	type AsyncBatchJob,
	type AsyncBatchStatus,
} from '../src/tools/batch-scan-async';

function memoryKv(): KVNamespace & { values: Map<string, string> } {
	const values = new Map<string, string>();
	return {
		values,
		get: vi.fn(async (key: string, type?: string) => {
			const value = values.get(key) ?? null;
			return type === 'json' && value ? JSON.parse(value) : value;
		}),
		put: vi.fn(async (key: string, value: string) => {
			values.set(key, value);
		}),
	} as unknown as KVNamespace & { values: Map<string, string> };
}

/** Start a job at t=1_000, then rewrite its stored status/updatedAt to simulate a dead consumer. */
async function seedJob(kv: KVNamespace & { values: Map<string, string> }, status: AsyncBatchStatus, updatedAt: number) {
	const started = await startAsyncBatchScan({ domains: ['example.com'], idempotencyKey: 'stale-key-1' }, 'principal-a', {
		kv,
		queue: { send: async () => undefined },
		now: () => 1_000,
	});
	const key = `async-batch:v1:${started.jobId}`;
	const stored = JSON.parse(kv.values.get(key) as string) as AsyncBatchJob;
	kv.values.set(key, JSON.stringify({ ...stored, status, updatedAt }));
	return { jobId: started.jobId, key };
}

describe('SQ-564 async batch scan — read-path deadline for abandoned jobs', () => {
	it('bound covers every delivery attempt plus its retry delay with margin', () => {
		expect(ASYNC_BATCH_STALE_AFTER_MS).toBeGreaterThan(ASYNC_BATCH_MAX_ATTEMPTS * 2 * 60 * 1000);
	});

	it.each(['running', 'queued'] as const)('reports a %s job past the bound as failed and persists it', async (status) => {
		const kv = memoryKv();
		const { jobId, key } = await seedJob(kv, status, 1_000);
		const now = () => 1_000 + ASYNC_BATCH_STALE_AFTER_MS + 1;

		const first = await getAsyncBatchJobForRead(jobId, 'principal-a', kv, now);
		expect(first).toMatchObject({ jobId, status: 'failed', error: ASYNC_BATCH_ABANDONED_ERROR, updatedAt: 1_000 });

		// Persisted: the raw read (what the queue consumer sees) agrees, and a second poll is identical.
		expect(JSON.parse(kv.values.get(key) as string)).toMatchObject({ status: 'failed', error: ASYNC_BATCH_ABANDONED_ERROR });
		expect(await getAsyncBatchJob(jobId, 'principal-a', kv)).toMatchObject({ status: 'failed' });
		expect(await getAsyncBatchJobForRead(jobId, 'principal-a', kv, now)).toEqual(first);
	});

	it('returns a running job inside the bound unchanged and writes nothing', async () => {
		const kv = memoryKv();
		const { jobId } = await seedJob(kv, 'running', 1_000);
		const putsBefore = (kv.put as ReturnType<typeof vi.fn>).mock.calls.length;

		const job = await getAsyncBatchJobForRead(jobId, 'principal-a', kv, () => 1_000 + ASYNC_BATCH_STALE_AFTER_MS);

		expect(job).toMatchObject({ status: 'running', updatedAt: 1_000 });
		expect(job?.error).toBeUndefined();
		expect((kv.put as ReturnType<typeof vi.fn>).mock.calls.length).toBe(putsBefore);
	});

	it.each(['completed', 'failed'] as const)('leaves a %s job untouched however old it is', async (status) => {
		const kv = memoryKv();
		const { jobId, key } = await seedJob(kv, status, 1_000);
		const before = kv.values.get(key);

		const job = await getAsyncBatchJobForRead(jobId, 'principal-a', kv, () => 1_000 + ASYNC_BATCH_STALE_AFTER_MS * 10);

		expect(job?.status).toBe(status);
		expect(job?.error).toBeUndefined();
		expect(kv.values.get(key)).toBe(before);
	});

	it('still reports failed when persisting the terminal state throws', async () => {
		const kv = memoryKv();
		const { jobId } = await seedJob(kv, 'running', 1_000);
		(kv.put as ReturnType<typeof vi.fn>).mockRejectedValueOnce(new Error('kv write refused'));

		const job = await getAsyncBatchJobForRead(jobId, 'principal-a', kv, () => 1_000 + ASYNC_BATCH_STALE_AFTER_MS + 1);

		expect(job).toMatchObject({ status: 'failed', error: ASYNC_BATCH_ABANDONED_ERROR });
	});

	it('does not disclose or rewrite a stale job to a different principal', async () => {
		const kv = memoryKv();
		const { jobId, key } = await seedJob(kv, 'running', 1_000);
		const before = kv.values.get(key);

		expect(await getAsyncBatchJobForRead(jobId, 'principal-b', kv, () => 1_000 + ASYNC_BATCH_STALE_AFTER_MS + 1)).toBeNull();
		expect(kv.values.get(key)).toBe(before);
	});

	describe('SQ-577 batch_scan_start with a reused idempotency key', () => {
		const startInput = { domains: ['example.com'], idempotencyKey: 'stale-key-1' };
		const makeDeps = (kv: KVNamespace, now: () => number) => ({ kv, queue: { send: vi.fn(async () => undefined) }, now });

		it.each(['running', 'queued'] as const)('starts a new job over a %s job past the bound that was never polled', async (status) => {
			const kv = memoryKv();
			const { jobId, key } = await seedJob(kv, status, 1_000);
			const deps = makeDeps(kv, () => 1_000 + ASYNC_BATCH_STALE_AFTER_MS + 1);

			const restarted = await startAsyncBatchScan(startInput, 'principal-a', deps);

			expect(restarted).toMatchObject({ jobId, status: 'queued', createdAt: 1_000 + ASYNC_BATCH_STALE_AFTER_MS + 1 });
			expect(deps.queue.send).toHaveBeenCalledTimes(1);
			expect(JSON.parse(kv.values.get(key) as string)).toMatchObject({ status: 'queued', updatedAt: restarted.createdAt });
		});

		it.each(['running', 'queued'] as const)('replays a %s job still inside the bound without a second queue message', async (status) => {
			const kv = memoryKv();
			const { jobId } = await seedJob(kv, status, 1_000);
			const deps = makeDeps(kv, () => 1_000 + ASYNC_BATCH_STALE_AFTER_MS);

			const replayed = await startAsyncBatchScan(startInput, 'principal-a', deps);

			expect(replayed).toMatchObject({ jobId, status, updatedAt: 1_000 });
			expect(deps.queue.send).not.toHaveBeenCalled();
		});

		it('replays a completed job however old it is', async () => {
			const kv = memoryKv();
			const { jobId } = await seedJob(kv, 'completed', 1_000);
			const deps = makeDeps(kv, () => 1_000 + ASYNC_BATCH_STALE_AFTER_MS * 10);

			expect(await startAsyncBatchScan(startInput, 'principal-a', deps)).toMatchObject({ jobId, status: 'completed' });
			expect(deps.queue.send).not.toHaveBeenCalled();
		});
	});

	describe('through the batch_scan_status / batch_scan_findings tools', () => {
		async function call(name: string, kv: KVNamespace, jobId: string, principalId = 'principal-a') {
			const { handleToolsCall } = await import('../src/handlers/tools');
			return handleToolsCall({ name, arguments: { job_id: jobId } }, undefined, {
				principalId,
				asyncBatchKv: kv,
				authTier: 'owner',
			} as never);
		}

		it('batch_scan_status returns failed with the abandoned reason for a stale running job, twice', async () => {
			const kv = memoryKv();
			const { jobId } = await seedJob(kv, 'running', Date.now() - ASYNC_BATCH_STALE_AFTER_MS - 60_000);

			const first = (await call('batch_scan_status', kv, jobId)).structuredContent as { status: string; error?: string };
			const second = (await call('batch_scan_status', kv, jobId)).structuredContent as { status: string; error?: string };

			expect(first).toMatchObject({ status: 'failed', error: ASYNC_BATCH_ABANDONED_ERROR });
			expect(second).toEqual(first);
			const findings = (await call('batch_scan_findings', kv, jobId)).structuredContent as { status: string; result?: unknown };
			expect(findings.status).toBe('failed');
			expect(findings.result).toBeUndefined();
		});

		it('batch_scan_status returns a running job inside the bound unchanged', async () => {
			const kv = memoryKv();
			const { jobId } = await seedJob(kv, 'running', Date.now() - 60_000);

			const payload = (await call('batch_scan_status', kv, jobId)).structuredContent as { status: string; error?: string };

			expect(payload.status).toBe('running');
			expect(payload.error).toBeUndefined();
		});

		it('a different principal polling a stale job id gets the same not-found result', async () => {
			const kv = memoryKv();
			const { jobId } = await seedJob(kv, 'running', Date.now() - ASYNC_BATCH_STALE_AFTER_MS - 60_000);

			const result = await call('batch_scan_status', kv, jobId, 'principal-b');

			expect(result.isError).toBe(true);
			expect(JSON.stringify(result.content)).toContain('Batch scan job not found');
		});
	});
});
