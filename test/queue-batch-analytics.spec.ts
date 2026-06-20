// SPDX-License-Identifier: BUSL-1.1

/**
 * R4 — async-path Analytics Engine counter.
 *
 * The queue-consumer dispatch (`worker.queue` in src/index.ts) wraps every
 * branch in a timed try/catch/finally that emits a single fail-open
 * `queue_batch` AE event. This makes a whole-batch throw — which Cloudflare
 * silently retries — queryable + alertable, instead of being structurally
 * invisible to `queryRecentAnomalies` (which only sees `index1='tool_call'`).
 *
 * Invariants pinned:
 *   1. A clean brand-audit batch emits `queue_batch` with outcome='ok' and
 *      failureCount=0, handler=batch.queue, doubles carrying message count.
 *   2. A brand-audit batch whose consumer THROWS still emits `queue_batch`
 *      (finally), with outcome='error' and failureCount=messageCount, and the
 *      error is re-thrown so Cloudflare's retry semantics are unchanged.
 *   3. Fail-open: emit never blocks the dispatch (no MCP_ANALYTICS → no throw).
 */

import { describe, it, expect, vi, afterEach } from 'vitest';

// Mock the brand-audit consumer so we control success vs. throw at the dispatch
// boundary. worker (src/index.ts) statically imports handleBrandAuditQueue, so
// the mock must be registered before the dynamic import of '../src' below.
vi.mock('../src/queue/brand-audit-consumer', () => ({
	handleBrandAuditQueue: vi.fn(),
	// Re-export the symbols index.ts imports as types/values; only the function
	// is used at runtime by the dispatch.
}));

afterEach(() => vi.restoreAllMocks());

interface CapturedPoint {
	indexes?: string[];
	blobs?: string[];
	doubles?: number[];
}

/** Minimal MessageBatch stub. Each message tracks ack/retry for assertions. */
function makeBatch(queue: string, count: number): MessageBatch<unknown> {
	const messages = Array.from({ length: count }, (_, i) => ({
		id: `m${i}`,
		body: { auditId: `a${i}`, target: 'example.com', format: 'json' },
		ack: vi.fn(),
		retry: vi.fn(),
	}));
	return { queue, messages } as unknown as MessageBatch<unknown>;
}

function makeCtx(): ExecutionContext {
	return { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext;
}

describe('R4 queue-batch analytics counter', () => {
	it('emits queue_batch with outcome=ok and failureCount=0 on a clean batch', async () => {
		const captured: CapturedPoint[] = [];
		const MCP_ANALYTICS = { writeDataPoint: (p: CapturedPoint) => captured.push(p) };

		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		vi.mocked(handleBrandAuditQueue).mockResolvedValue(undefined);

		const worker = (await import('../src')).default;
		const batch = makeBatch('brand-audit-queue', 3);
		// BRAND_AUDIT_DB present so the dispatch runs the consumer (not the
		// ack-and-return missing-binding short-circuit).
		const env = { MCP_ANALYTICS, BRAND_AUDIT_DB: {} } as unknown as Record<string, unknown>;

		await worker.queue!(batch, env, makeCtx());

		const point = captured.find((p) => p.indexes?.[0] === 'queue_batch');
		expect(point).toBeDefined();
		expect(point!.blobs?.[0]).toBe('brand-audit-queue');
		expect(point!.blobs?.[1]).toBe('ok');
		// doubles: [durationMs, failureCount, messageCount]
		expect(point!.doubles?.[1]).toBe(0);
		expect(point!.doubles?.[2]).toBe(3);
	});

	it('emits queue_batch with outcome=error + failureCount=messageCount when the consumer throws, and re-throws', async () => {
		const captured: CapturedPoint[] = [];
		const MCP_ANALYTICS = { writeDataPoint: (p: CapturedPoint) => captured.push(p) };

		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		vi.mocked(handleBrandAuditQueue).mockRejectedValue(new Error('consumer blew up'));

		const worker = (await import('../src')).default;
		const batch = makeBatch('brand-audit-queue', 4);
		const env = { MCP_ANALYTICS, BRAND_AUDIT_DB: {} } as unknown as Record<string, unknown>;

		// The error must propagate so Cloudflare redelivers the batch.
		await expect(worker.queue!(batch, env, makeCtx())).rejects.toThrow('consumer blew up');

		const point = captured.find((p) => p.indexes?.[0] === 'queue_batch');
		expect(point).toBeDefined();
		expect(point!.blobs?.[0]).toBe('brand-audit-queue');
		expect(point!.blobs?.[1]).toBe('error');
		expect(point!.doubles?.[1]).toBe(4); // failureCount = batch size
		expect(point!.doubles?.[2]).toBe(4); // messageCount
	});

	it('is fail-open: a clean batch with no MCP_ANALYTICS binding does not throw', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		vi.mocked(handleBrandAuditQueue).mockResolvedValue(undefined);

		const worker = (await import('../src')).default;
		const batch = makeBatch('brand-audit-queue', 1);
		const env = { BRAND_AUDIT_DB: {} } as unknown as Record<string, unknown>;

		await expect(worker.queue!(batch, env, makeCtx())).resolves.toBeUndefined();
	});
});
