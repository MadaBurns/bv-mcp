// SPDX-License-Identifier: BUSL-1.1
//
// handleBrandAuditQueue — per-message routing and ack/retry mapping (US-13 / SQ-373).
//
// Pins, with the REAL processors and stub D1 only:
//   - phase detection happens before Zod parse (deep_scan / discover_only), anything
//     else (including non-object bodies) goes to the brand-audit processor;
//   - deep_scan is acked unconditionally (malformed payload, no internalCall);
//   - a processor 'retry' verdict calls message.retry(), 'ack' calls message.ack(),
//     exactly one of the two per message, in batch order.
// The deep_scan error containment itself is covered by
// brand-audit-queue-consumer.integration.test.ts.

import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => vi.restoreAllMocks());

/** D1 whose idempotency SELECT finds no row → the processors ack ("producer never inserted it"). */
function emptyD1(): D1Database {
	const stmt = {
		bind() {
			return this;
		},
		async first() {
			return null;
		},
		async run() {
			return { meta: { changes: 0 } };
		},
		async all() {
			return { results: [] };
		},
	};
	return { prepare: () => stmt } as unknown as D1Database;
}

/** D1 whose idempotency SELECT throws → the processors return 'retry'. */
function failingD1(): D1Database {
	const stmt = {
		bind() {
			return this;
		},
		async first(): Promise<never> {
			throw new Error('D1_BUSY');
		},
		async run() {
			return { meta: { changes: 0 } };
		},
		async all() {
			return { results: [] };
		},
	};
	return { prepare: () => stmt } as unknown as D1Database;
}

function makeBatch(bodies: unknown[]) {
	const log: string[] = [];
	const messages = bodies.map((body, i) => ({
		body,
		id: `m${i}`,
		timestamp: new Date(),
		attempts: 1,
		ack: vi.fn(() => log.push(`ack:${i}`)),
		retry: vi.fn(() => log.push(`retry:${i}`)),
	}));
	const batch = { messages, queue: 'brand-audit-queue', retryAll: vi.fn(), ackAll: vi.fn() } as unknown as MessageBatch<unknown>;
	return { batch, messages, log };
}

const DISCOVER = { auditId: 'a1', target: 'contoso.com', phase: 'discover_only' };
const AUDIT = { auditId: 'a1', target: 'contoso.com', format: 'json' };

describe('handleBrandAuditQueue — routing', () => {
	it('discover_only: a processor retry verdict retries the message (never acks it)', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const { batch, messages } = makeBatch([DISCOVER]);
		await handleBrandAuditQueue(batch, { db: failingD1() });
		expect(messages[0].retry).toHaveBeenCalledOnce();
		expect(messages[0].ack).not.toHaveBeenCalled();
	});

	it('discover_only: an ack verdict (no target row) acks the message', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const { batch, messages } = makeBatch([DISCOVER]);
		await handleBrandAuditQueue(batch, { db: emptyD1() });
		expect(messages[0].ack).toHaveBeenCalledOnce();
		expect(messages[0].retry).not.toHaveBeenCalled();
	});

	it('discover_only with a malformed payload is acked (never retried)', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const { batch, messages } = makeBatch([{ phase: 'discover_only' }]);
		await handleBrandAuditQueue(batch, { db: failingD1() });
		expect(messages[0].ack).toHaveBeenCalledOnce();
		expect(messages[0].retry).not.toHaveBeenCalled();
	});

	it('a phase-less audit message goes to the brand-audit processor: retry on D1 failure, ack when no row', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const failing = makeBatch([AUDIT]);
		await handleBrandAuditQueue(failing.batch, { db: failingD1() });
		expect(failing.messages[0].retry).toHaveBeenCalledOnce();
		expect(failing.messages[0].ack).not.toHaveBeenCalled();

		const empty = makeBatch([AUDIT]);
		await handleBrandAuditQueue(empty.batch, { db: emptyD1() });
		expect(empty.messages[0].ack).toHaveBeenCalledOnce();
		expect(empty.messages[0].retry).not.toHaveBeenCalled();
	});

	it('an unknown phase is NOT special-cased: it falls through to the brand-audit processor', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const { batch, messages } = makeBatch([{ ...AUDIT, phase: 'something_else' }]);
		await handleBrandAuditQueue(batch, { db: failingD1() });
		expect(messages[0].retry).toHaveBeenCalledOnce();
	});

	it.each([
		['null', null],
		['a string', 'not-an-object'],
		['a number', 42],
		['an empty object', {}],
	])('%s body is malformed → acked, never retried, no throw', async (_label, body) => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const { batch, messages } = makeBatch([body]);
		await expect(handleBrandAuditQueue(batch, { db: failingD1() })).resolves.toBeUndefined();
		expect(messages[0].ack).toHaveBeenCalledOnce();
		expect(messages[0].retry).not.toHaveBeenCalled();
	});
});

describe('handleBrandAuditQueue — deep_scan is always acked', () => {
	it.each([
		['missing target', { auditId: 'a1', phase: 'deep_scan' }],
		['missing auditId', { target: 'contoso.com', phase: 'deep_scan' }],
		['non-string auditId', { auditId: 7, target: 'contoso.com', phase: 'deep_scan' }],
	])('%s: acked and internalCall never invoked', async (_label, body) => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const internalCall = vi.fn();
		const { batch, messages } = makeBatch([body]);
		await handleBrandAuditQueue(batch, { db: failingD1(), internalCall });
		expect(messages[0].ack).toHaveBeenCalledOnce();
		expect(messages[0].retry).not.toHaveBeenCalled();
		expect(internalCall).not.toHaveBeenCalled();
	});

	it('a valid payload without an internalCall binding is acked (D1 is never touched)', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const prepare = vi.fn();
		const { batch, messages } = makeBatch([{ auditId: 'a1', target: 'contoso.com', phase: 'deep_scan' }]);
		await handleBrandAuditQueue(batch, { db: { prepare } as unknown as D1Database });
		expect(messages[0].ack).toHaveBeenCalledOnce();
		expect(prepare).not.toHaveBeenCalled();
	});
});

describe('handleBrandAuditQueue — batch behaviour', () => {
	it('settles every message exactly once, in order, independently of its neighbours', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const { batch, messages, log } = makeBatch([
			DISCOVER, // failing D1 → retry
			{ auditId: 'a1', target: 'contoso.com', phase: 'deep_scan' }, // ack
			AUDIT, // failing D1 → retry
			'garbage', // ack
		]);
		await handleBrandAuditQueue(batch, { db: failingD1() });
		expect(log).toEqual(['retry:0', 'ack:1', 'retry:2', 'ack:3']);
		for (const m of messages) expect(m.ack.mock.calls.length + m.retry.mock.calls.length).toBe(1);
	});

	it('an empty batch is a no-op', async () => {
		const { handleBrandAuditQueue } = await import('../src/queue/brand-audit-consumer');
		const { batch } = makeBatch([]);
		await expect(handleBrandAuditQueue(batch, { db: failingD1() })).resolves.toBeUndefined();
	});
});
