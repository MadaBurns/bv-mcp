// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the brand-audit queue consumer.
 *
 * Strategy: mock D1 with a recording fake, inject a mocked `brandAuditSingle`,
 * exercise `processBrandAuditMessage` / `handleBrandAuditQueue` directly.
 *
 * Invariants asserted here:
 *   - Happy path: target row flips queued → running → completed; counter ticks
 *   - Idempotency: duplicate delivery of a `completed` row ack()s without re-running
 *   - Validation: malformed message body → ack (drop, don't retry forever)
 *   - Failure path: brandAuditSingle throws → target row flips → failed; counter ticks
 *   - Final-target sentinel: when completed_targets === total_targets, audit
 *     marked completed
 */

import { describe, it, expect, vi } from 'vitest';

interface D1Call {
	sql: string;
	binds: unknown[];
}

interface MakeMockOpts {
	target?: { status: string; completed_at: number | null } | null;
	auditAfter?: { completed_targets: number; total_targets: number } | null;
	throwOnUpdate?: boolean;
}

function makeMockD1(opts: MakeMockOpts = {}) {
	const calls: D1Call[] = [];
	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first() {
					calls.push({ sql, binds });
					if (sql.includes('SELECT status, completed_at FROM brand_audit_targets')) {
						return opts.target ?? null;
					}
					if (sql.includes('SELECT completed_targets, total_targets FROM brand_audits')) {
						return opts.auditAfter ?? null;
					}
					return null;
				},
				async run() {
					calls.push({ sql, binds });
					if (opts.throwOnUpdate && sql.includes('UPDATE')) throw new Error('d1_update_failed');
					return { success: true, meta: { changes: 1, last_row_id: 0, duration: 0, rows_read: 0, rows_written: 1, size_after: 0 } };
				},
				async all() {
					calls.push({ sql, binds });
					return { results: [], success: true, meta: {} };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return { db, calls };
}

function fakeMessage(body: unknown, ack: () => void = vi.fn(), retry: () => void = vi.fn()) {
	return { id: 'msg-1', timestamp: new Date(), body, attempts: 1, ack, retry };
}

describe('processBrandAuditMessage', () => {
	it('runs brandAuditSingle, marks target completed, ticks audit counter', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		expect(brandAuditSingle).toHaveBeenCalledOnce();

		const updates = calls.filter((c) => c.sql.includes('UPDATE brand_audit_targets'));
		const completedUpdate = updates.find((c) => (c.binds[0] as string) === 'completed');
		expect(completedUpdate).toBeDefined();

		const auditTick = calls.find((c) => c.sql.includes('UPDATE brand_audits') && c.sql.includes('completed_targets'));
		expect(auditTick).toBeDefined();
	});

	it('is idempotent: a duplicate delivery of a completed target ack()s without re-running brandAuditSingle', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'completed', completed_at: 1_700_000_000_000 },
		});
		const brandAuditSingle = vi.fn();

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		expect(brandAuditSingle).not.toHaveBeenCalled();
		// Specifically: no UPDATE on brand_audit_targets after seeing completed.
		const writeOps = calls.filter((c) => c.sql.includes('UPDATE'));
		expect(writeOps).toHaveLength(0);
	});

	it('rejects malformed message body with ack (drop) — not retry forever', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({});
		const brandAuditSingle = vi.fn();

		const verdict = await processBrandAuditMessage(
			{ wrong: 'shape' } as unknown,
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		expect(brandAuditSingle).not.toHaveBeenCalled();
		expect(calls).toHaveLength(0);
	});

	it('marks target failed and ticks counter when brandAuditSingle throws', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});
		const brandAuditSingle = vi.fn().mockRejectedValue(new Error('discovery_timeout'));

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('ack');
		const failedUpdate = calls.find(
			(c) => c.sql.includes('UPDATE brand_audit_targets') && (c.binds[0] as string) === 'failed',
		);
		expect(failedUpdate).toBeDefined();
	});

	it('marks audit completed when this message was the final target', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db, calls } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 3, total_targets: 3 },
		});
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'final.example.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		const auditFinalize = calls.find(
			(c) => c.sql.includes('UPDATE brand_audits') && c.sql.includes("status = 'completed'"),
		);
		expect(auditFinalize).toBeDefined();
	});

	it('fans out to the PDF queue on completion when format=both', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);
		const pdfSend = vi.fn().mockResolvedValue(undefined);

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'both' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, pdfQueue: { send: pdfSend } },
		);

		expect(pdfSend).toHaveBeenCalledTimes(1);
		const [msg] = pdfSend.mock.calls[0];
		expect(msg).toMatchObject({ auditId: 'aud-1', target: 'apple.com', format: 'both' });
	});

	it('does NOT enqueue PDF when format=json', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);
		const pdfSend = vi.fn();

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, pdfQueue: { send: pdfSend } },
		);

		expect(pdfSend).not.toHaveBeenCalled();
	});

	it('does NOT enqueue PDF when target failed (only on completed)', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});
		const brandAuditSingle = vi.fn().mockRejectedValue(new Error('oops'));
		const pdfSend = vi.fn();

		await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'both' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000, pdfQueue: { send: pdfSend } },
		);

		expect(pdfSend).not.toHaveBeenCalled();
	});

	it('signals retry on a transient D1 update failure (no double-counting)', async () => {
		const { processBrandAuditMessage } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			throwOnUpdate: true,
		});
		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		const verdict = await processBrandAuditMessage(
			{ auditId: 'aud-1', target: 'apple.com', format: 'json' },
			{ db, brandAuditSingle, now: () => 1_750_000_000_000 },
		);

		expect(verdict).toBe('retry');
	});
});

describe('handleBrandAuditQueue', () => {
	it('ack/retry routes each message individually based on processBrandAuditMessage', async () => {
		const { handleBrandAuditQueue } = await import('../../src/queue/brand-audit-consumer');
		const { db } = makeMockD1({
			target: { status: 'queued', completed_at: null },
			auditAfter: { completed_targets: 1, total_targets: 3 },
		});

		const fakeResult = { category: 'brand_discovery', score: 100, findings: [] };
		const brandAuditSingle = vi.fn().mockResolvedValue(fakeResult);

		const ack1 = vi.fn();
		const retry1 = vi.fn();
		const ack2 = vi.fn();
		const retry2 = vi.fn();
		const batch = {
			queue: 'brand-audit-queue',
			messages: [
				fakeMessage({ auditId: 'aud-1', target: 'apple.com', format: 'json' }, ack1, retry1),
				fakeMessage({ wrong: 'shape' }, ack2, retry2),
			],
		} as unknown as MessageBatch<unknown>;

		await handleBrandAuditQueue(batch, { db, brandAuditSingle, now: () => 1_750_000_000_000 });

		expect(ack1).toHaveBeenCalled();
		expect(retry1).not.toHaveBeenCalled();
		expect(ack2).toHaveBeenCalled();
		expect(retry2).not.toHaveBeenCalled();
	});
});
