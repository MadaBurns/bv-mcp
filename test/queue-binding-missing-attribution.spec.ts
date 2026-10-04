// SPDX-License-Identifier: BUSL-1.1

/**
 * Bug-hunt: the queue dispatch in src/index.ts ack-and-returns when a binding
 * a queue needs is unprovisioned. Acking is unavoidable (a retry loop would
 * burn the queue), but doing it SILENTLY is not: the batch is destroyed, the
 * audits/PDFs never exist, and the only telemetry written for the invocation
 * is a `queue_batch` row saying `outcome='ok', failureCount=0`.
 *
 * `queryQueueFailures` (src/lib/analytics-queries.ts) is the alertable channel
 * for exactly this async path — its `HAVING error_batch_count > 0 OR
 * failure_count > 0` is what surfaces a queue problem at all, because
 * `queryRecentAnomalies` filters on `index1='tool_call'` and never sees a
 * queue invocation. SQ-196 already routes scanner-queue poison acks through
 * `failureCount` for this reason, so a binding-missing drop belongs in the same
 * field: acked-without-processing is the definition of a failed message.
 *
 * Distinction pinned here: a branch that RETRIES the batch (async-batch-scan
 * without SCAN_CACHE) loses nothing, so it gets the attribution log but must
 * NOT report failures — counting redeliveries as losses would train operators
 * to ignore the alert.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import type { Mock } from 'vitest';

// Static imports in src/index.ts — the mocks must be registered before the
// dynamic `import('../src')` in each test.
vi.mock('../src/queue/brand-audit-consumer', () => ({
	handleBrandAuditQueue: vi.fn(),
	brandWebhookPeerSecretsFromEnv: vi.fn(() => []),
}));
vi.mock('../src/queue/brand-audit-pdf-consumer', () => ({
	handleBrandAuditPdfQueue: vi.fn(),
}));
vi.mock('../src/tools/batch-scan-async', () => ({
	processAsyncBatchMessage: vi.fn(),
}));

afterEach(() => vi.restoreAllMocks());

interface CapturedPoint {
	indexes?: string[];
	blobs?: string[];
	doubles?: number[];
}

interface BatchHarness {
	batch: MessageBatch<unknown>;
	/**
	 * The per-message `ack` spies, held by reference. `MessageBatch` types `ack` as the plain
	 * `() => void` the runtime gives a real message, so reaching `.mock` back through
	 * `batch.messages` is a type error — and a cast there would silence the check on the wrong
	 * object. These are the same function objects the batch carries, so counting calls here
	 * asserts exactly what reaching through the batch did.
	 */
	acks: Mock<() => void>[];
	retryAll: Mock<() => void>;
}

function makeBatch(queue: string, count: number): BatchHarness {
	const acks: Mock<() => void>[] = [];
	const messages = Array.from({ length: count }, (_, i) => {
		const ack: Mock<() => void> = vi.fn();
		acks.push(ack);
		return {
			id: `m${i}`,
			body: { auditId: `a${i}`, target: 'example.com', format: 'json' },
			ack,
			retry: vi.fn(),
		};
	});
	const retryAll: Mock<() => void> = vi.fn();
	return { batch: { queue, messages, retryAll } as unknown as MessageBatch<unknown>, acks, retryAll };
}

function makeCtx(): ExecutionContext {
	return { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext;
}

/** Runs the queue entrypoint, returning the AE `queue_batch` row and the joined console output. */
async function dispatch(queue: string, count: number, env: Record<string, unknown>) {
	const captured: CapturedPoint[] = [];
	const logs = vi.spyOn(console, 'log').mockImplementation(() => {});
	const worker = (await import('../src')).default;
	const harness = makeBatch(queue, count);
	// The handler's parameter is `BvMcpEnv`, which src/index.ts keeps module-private, so the
	// assertion goes through the generated global `Env` (as `freemium-model.spec.ts` does)
	// rather than inventing an export to satisfy one spec. The extra hop through `unknown` is
	// the fake's `writeDataPoint` parameter: it accepts the narrower `CapturedPoint` instead of
	// the generated `AETypes`, which makes the two object types non-overlapping for TS2352.
	const envArg = { MCP_ANALYTICS: { writeDataPoint: (p: CapturedPoint) => captured.push(p) }, ...env } as unknown as Env;

	let thrown: unknown;
	try {
		await worker.queue!(harness.batch, envArg, makeCtx());
	} catch (err) {
		thrown = err;
	}

	return {
		thrown,
		harness,
		point: captured.find((p) => p.indexes?.[0] === 'queue_batch'),
		logged: logs.mock.calls.map((c) => String(c[0])).join('\n'),
	};
}

describe('brand-audit-queue without BRAND_AUDIT_DB', () => {
	it('acks the batch without running the consumer', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const r = await dispatch('brand-audit-queue', 3, {});

		expect(r.thrown).toBeUndefined();
		expect(handleBrandAuditQueue).not.toHaveBeenCalled();
		expect(r.harness.acks.every((ack) => ack.mock.calls.length === 1)).toBe(true);
		expect(r.harness.retryAll).not.toHaveBeenCalled();
	});

	it('reports the destroyed messages in the alertable failureCount instead of a clean batch', async () => {
		const r = await dispatch('brand-audit-queue', 3, {});

		expect(r.point).toBeDefined();
		// doubles: [durationMs, failureCount, messageCount]
		expect(r.point!.doubles?.[1]).toBe(3);
		expect(r.point!.doubles?.[2]).toBe(3);
		// `outcome` stays 'ok': nothing threw, so Cloudflare will not redeliver.
		// The loss is carried by failureCount, which is what queryQueueFailures filters on.
		expect(r.point!.blobs?.[1]).toBe('ok');
	});

	it('names the queue, the missing binding and the drop in the log', async () => {
		const r = await dispatch('brand-audit-queue', 3, {});

		expect(r.logged).toContain('binding_missing');
		expect(r.logged).toContain('BRAND_AUDIT_DB');
		expect(r.logged).toContain('brand-audit-queue');
	});
});

describe('brand-audit-pdf-queue without BRAND_REPORTS', () => {
	it('acks, reports the loss, and attributes it to the bucket binding', async () => {
		const { handleBrandAuditPdfQueue } = await import('../src/queue/brand-audit-pdf-consumer');
		const r = await dispatch('brand-audit-pdf-queue', 2, { BRAND_AUDIT_DB: {} });

		expect(handleBrandAuditPdfQueue).not.toHaveBeenCalled();
		expect(r.harness.acks.every((ack) => ack.mock.calls.length === 1)).toBe(true);
		expect(r.point!.doubles?.[1]).toBe(2);
		expect(r.logged).toContain('binding_missing');
		expect(r.logged).toContain('BRAND_REPORTS');
	});

	it('names BOTH bindings when both are missing, so provisioning is not serialised', async () => {
		const r = await dispatch('brand-audit-pdf-queue', 1, {});

		expect(r.logged).toContain('BRAND_AUDIT_DB+BRAND_REPORTS');
	});
});

describe('async-batch-scan-queue without SCAN_CACHE', () => {
	it('retries rather than dropping, and does not report the batch as lost', async () => {
		const { processAsyncBatchMessage } = await import('../src/tools/batch-scan-async');
		const r = await dispatch('async-batch-scan-queue', 4, {});

		expect(processAsyncBatchMessage).not.toHaveBeenCalled();
		expect(r.harness.retryAll).toHaveBeenCalledTimes(1);
		expect(r.harness.acks.some((ack) => ack.mock.calls.length > 0)).toBe(false);
		// Nothing was destroyed, so the alertable counter must stay clean.
		expect(r.point!.doubles?.[1]).toBe(0);
		// …but the invocation must still be attributable.
		expect(r.logged).toContain('binding_missing');
		expect(r.logged).toContain('SCAN_CACHE');
	});
});

describe('control: a provisioned brand-audit batch', () => {
	it('reports failureCount=0 and emits no binding_missing line', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		vi.mocked(handleBrandAuditQueue).mockResolvedValue(undefined);

		const r = await dispatch('brand-audit-queue', 3, { BRAND_AUDIT_DB: {} });

		expect(handleBrandAuditQueue).toHaveBeenCalledTimes(1);
		expect(r.point!.doubles?.[1]).toBe(0);
		expect(r.point!.blobs?.[1]).toBe('ok');
		expect(r.logged).not.toContain('binding_missing');
	});
});
