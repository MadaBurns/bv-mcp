// SPDX-License-Identifier: BUSL-1.1

// SQ-291 item 5 — an async batch job must not report an unscanned tail as a clean completion.

import { describe, expect, it, vi } from 'vitest';
import { getAsyncBatchJob, processAsyncBatchMessage, startAsyncBatchScan } from '../src/tools/batch-scan-async';
import type { BatchScanResultItem } from '../src/tools/batch-scan';

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

function item(domain: string, error?: string): BatchScanResultItem {
	return {
		domain,
		score: error ? null : 90,
		grade: error ? null : 'A',
		measured: !error,
		findingCounts: { critical: 0, high: 0, medium: 0, low: 0 },
		categoryScores: {},
		scoringProfile: null,
		evidence: { attempted: 0, completed: 0, ratio: 0 },
		scoringModelVersion: '1',
		dnsChecksPackageVersion: '1',
		scoringConfigHash: 'h',
		...(error ? { error } : {}),
	} as unknown as BatchScanResultItem;
}

async function startJob(kv: KVNamespace, domains: string[]) {
	const job = await startAsyncBatchScan({ domains, idempotencyKey: 'incomplete-key-1' }, 'principal-a', {
		kv,
		queue: { send: async () => undefined },
	});
	return { jobId: job.jobId, message: { version: 1, jobId: job.jobId, principalId: 'principal-a' } };
}

describe('SQ-291 async batch scan — unscanned tail is recorded, not reported as clean', () => {
	it('records incomplete + the unscanned list on the job when the batch budget cut the tail', async () => {
		const kv = memoryKv();
		const { jobId, message } = await startJob(kv, ['a.example.com', 'b.example.com', 'c.example.com']);
		const runBatchScan = vi.fn(async () => [
			item('a.example.com'),
			item('b.example.com', 'batch_budget_exceeded'),
			item('c.example.com', 'batch_budget_exceeded'),
		]);

		expect(await processAsyncBatchMessage(message, { kv, runBatchScan })).toBe('ack');

		const job = await getAsyncBatchJob(jobId, 'principal-a', kv);
		expect(job?.status).toBe('completed');
		expect(job?.incomplete).toBe(true);
		expect(job?.unscanned).toEqual(['b.example.com', 'c.example.com']);
	});

	it('control: a fully scanned batch is recorded as complete with an empty unscanned list', async () => {
		const kv = memoryKv();
		const { jobId, message } = await startJob(kv, ['a.example.com', 'b.example.com']);
		const runBatchScan = vi.fn(async () => [item('a.example.com'), item('b.example.com')]);

		await processAsyncBatchMessage(message, { kv, runBatchScan });

		const job = await getAsyncBatchJob(jobId, 'principal-a', kv);
		expect(job?.incomplete).toBe(false);
		expect(job?.unscanned).toEqual([]);
	});

	it('batch_scan_status surfaces incomplete + unscanned for a completed-but-cut job', async () => {
		const kv = memoryKv();
		const { jobId, message } = await startJob(kv, ['a.example.com', 'b.example.com']);
		const runBatchScan = vi.fn(async () => [item('a.example.com'), item('b.example.com', 'batch_budget_exceeded')]);
		await processAsyncBatchMessage(message, { kv, runBatchScan });

		const { handleToolsCall } = await import('../src/handlers/tools');
		const result = await handleToolsCall({ name: 'batch_scan_status', arguments: { job_id: jobId } }, undefined, {
			principalId: 'principal-a',
			asyncBatchKv: kv,
			authTier: 'owner',
		} as never);
		const payload = result.structuredContent as { status: string; incomplete?: boolean; unscanned?: string[] };
		expect(payload.status).toBe('completed');
		expect(payload.incomplete).toBe(true);
		expect(payload.unscanned).toEqual(['b.example.com']);
	});

	it('gives the queue job its own, larger budget than the 25s synchronous default', async () => {
		const kv = memoryKv();
		const { message } = await startJob(kv, ['a.example.com']);
		const runBatchScan = vi.fn(async (_domains: string[], _options?: { budgetMs?: number }) => [item('a.example.com')]);

		await processAsyncBatchMessage(message, { kv, runBatchScan });

		const options = runBatchScan.mock.calls[0]?.[1];
		expect(options?.budgetMs).toBeGreaterThan(25_000);
	});
});
