// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { getAsyncBatchJob, processAsyncBatchMessage, startAsyncBatchScan } from '../src/tools/batch-scan-async';

function memoryKv(): KVNamespace {
	const values = new Map<string, string>();
	return {
		get: vi.fn(async (key: string, type?: string) => {
			const value = values.get(key) ?? null;
			return type === 'json' && value ? JSON.parse(value) : value;
		}),
		put: vi.fn(async (key: string, value: string) => {
			values.set(key, value);
		}),
	} as unknown as KVNamespace;
}

describe('asynchronous batch scans', () => {
	it('binds a stable idempotent job to principal, normalized inputs, and scoring versions', async () => {
		const kv = memoryKv();
		const queue = { send: vi.fn(async () => undefined) };
		const input = { domains: ['B.EXAMPLE.COM', 'a.example.com'], forceRefresh: true, idempotencyKey: 'replay-key-1' };
		const first = await startAsyncBatchScan(input, 'principal-a', { kv, queue, now: () => 1_000 });
		const replay = await startAsyncBatchScan({ ...input, domains: [...input.domains].reverse() }, 'principal-a', {
			kv,
			queue,
			now: () => 2_000,
		});

		expect(replay.jobId).toBe(first.jobId);
		expect(queue.send).toHaveBeenCalledTimes(1);
		expect((queue.send as ReturnType<typeof vi.fn>).mock.calls[0]?.[0]).toMatchObject({
			version: 1,
			jobId: first.jobId,
			principalId: 'principal-a',
		});
	});

	it('does not disclose a job across principals', async () => {
		const kv = memoryKv();
		const job = await startAsyncBatchScan({ domains: ['example.com'], idempotencyKey: 'replay-key-2' }, 'principal-a', {
			kv,
			queue: { send: async () => undefined },
		});
		expect(await getAsyncBatchJob(job.jobId, 'principal-b', kv)).toBeNull();
		expect(await getAsyncBatchJob(job.jobId, 'principal-a', kv)).toMatchObject({ status: 'queued' });
	});

	it('changes the job id when the principal or replay key changes', async () => {
		const kv = memoryKv();
		const queue = { send: async () => undefined };
		const a = await startAsyncBatchScan({ domains: ['example.com'], idempotencyKey: 'replay-key-a' }, 'principal-a', { kv, queue });
		const b = await startAsyncBatchScan({ domains: ['example.com'], idempotencyKey: 'replay-key-a' }, 'principal-b', { kv, queue });
		const c = await startAsyncBatchScan({ domains: ['example.com'], idempotencyKey: 'replay-key-b' }, 'principal-a', { kv, queue });
		expect(new Set([a.jobId, b.jobId, c.jobId])).toHaveLength(3);
	});

	it('persists terminal results and acks duplicate deliveries without rerunning', async () => {
		const kv = memoryKv();
		const queue = { send: async () => undefined };
		const job = await startAsyncBatchScan({ domains: ['example.com'], idempotencyKey: 'replay-key-result' }, 'principal-a', {
			kv,
			queue,
		});
		const runBatchScan = vi.fn(async () => []);
		const message = { version: 1 as const, jobId: job.jobId, principalId: 'principal-a' };
		expect(await processAsyncBatchMessage(message, { kv, runBatchScan })).toBe('ack');
		expect(await processAsyncBatchMessage(message, { kv, runBatchScan })).toBe('ack');
		expect(runBatchScan).toHaveBeenCalledTimes(1);
		expect(await getAsyncBatchJob(job.jobId, 'principal-a', kv)).toMatchObject({ status: 'completed', result: { results: [] } });
	});

	it('requests a bounded platform retry and leaves the job resumable when execution fails', async () => {
		const kv = memoryKv();
		const job = await startAsyncBatchScan({ domains: ['example.com'], idempotencyKey: 'replay-key-retry' }, 'principal-a', {
			kv,
			queue: { send: async () => undefined },
		});
		const runBatchScan = vi.fn(async () => {
			throw new Error('transient upstream failure');
		});
		expect(await processAsyncBatchMessage({ version: 1, jobId: job.jobId, principalId: 'principal-a' }, { kv, runBatchScan })).toBe(
			'retry',
		);
		expect(await getAsyncBatchJob(job.jobId, 'principal-a', kv)).toMatchObject({ status: 'queued', error: 'transient upstream failure' });
	});

	it('defers duplicate work under a fresh execution lease and reclaims a stale lease', async () => {
		const kv = memoryKv();
		const job = await startAsyncBatchScan({ domains: ['example.com'], idempotencyKey: 'replay-key-lease' }, 'principal-a', {
			kv,
			queue: { send: async () => undefined },
			now: () => 1_000,
		});
		const stored = await getAsyncBatchJob(job.jobId, 'principal-a', kv);
		expect(stored).not.toBeNull();
		stored!.status = 'running';
		stored!.updatedAt = 1_000;
		await kv.put(`async-batch:v1:${job.jobId}`, JSON.stringify(stored));
		const runBatchScan = vi.fn(async () => []);
		const message = { version: 1 as const, jobId: job.jobId, principalId: 'principal-a' };

		expect(await processAsyncBatchMessage(message, { kv, runBatchScan, now: () => 60_000 })).toBe('retry');
		expect(runBatchScan).not.toHaveBeenCalled();
		expect(await processAsyncBatchMessage(message, { kv, runBatchScan, now: () => 122_000 })).toBe('ack');
		expect(runBatchScan).toHaveBeenCalledTimes(1);
	});
});
