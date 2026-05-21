// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the brand_audit_batch_start MCP tool.
 *
 * Producer-side of the async brand-audit flow:
 *   1. Validate the domain list (max 50, deduplicate, non-empty)
 *   2. Consume `domains.length` units from the per-tier monthly quota
 *      (atomic at enqueue — not per-target as messages drain)
 *   3. Write the parent `brand_audits` row to D1 (status='queued')
 *   4. Enqueue one `{ auditId, target }` message per target
 *   5. Return `{ auditId, queuedAt, targetCount, etaSeconds }` to the caller
 *
 * All side effects (D1, queue, quota) are injected as deps so tests stay offline.
 */

import { describe, it, expect, vi } from 'vitest';
import type { BrandAuditBatchStartDeps } from '../src/tools/brand-audit-batch-start';

interface D1Call {
	sql: string;
	binds: unknown[];
}

function makeMockD1(opts: { throwOnRun?: boolean } = {}) {
	const calls: D1Call[] = [];
	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async run() {
					calls.push({ sql, binds });
					if (opts.throwOnRun) throw new Error('d1_run_failed');
					return { success: true, meta: { changes: 1, last_row_id: 0, duration: 0, rows_read: 0, rows_written: 1, size_after: 0 } };
				},
				async first() {
					calls.push({ sql, binds });
					return null;
				},
				async all() {
					calls.push({ sql, binds });
					return { results: [], success: true, meta: {} };
				},
			};
			return stmt;
		},
		async batch(stmts: Array<{ run: () => Promise<unknown> }>) {
			const out = [];
			for (const s of stmts) out.push(await s.run());
			return out;
		},
	} as unknown as D1Database;
	return { db, calls };
}

function makeDeps(overrides: Partial<BrandAuditBatchStartDeps> = {}): BrandAuditBatchStartDeps {
	const { db } = makeMockD1();
	return {
		db,
		queue: { send: vi.fn().mockResolvedValue(undefined) },
		enforceQuota: vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 }),
		generateId: () => 'audit-test-id',
		now: () => 1_750_000_000_000,
		...overrides,
	};
}

describe('brandAuditBatchStart', () => {
	it('writes parent row, enqueues one message per target, returns audit metadata', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const { db, calls } = makeMockD1();
		const queueSend = vi.fn().mockResolvedValue(undefined);
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: true, remaining: 47, limit: 50 });
		const deps = makeDeps({ db, queue: { send: queueSend }, enforceQuota });

		const result = await brandAuditBatchStart(
			['apple.com', 'microsoft.com', 'brand-zeta.example.com'],
			{},
			'principal-key-hash-abc',
			deps,
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.auditId).toBe('audit-test-id');
		expect(summary?.metadata?.targetCount).toBe(3);
		expect(summary?.metadata?.queuedAt).toBe(1_750_000_000_000);
		expect(typeof summary?.metadata?.etaSeconds).toBe('number');

		// Quota consumed once with count=3.
		expect(enforceQuota).toHaveBeenCalledTimes(1);
		expect(enforceQuota).toHaveBeenCalledWith(3);

		// Parent + 3 child rows written to D1.
		const inserts = calls.filter((c) => c.sql.includes('INSERT INTO brand_audit'));
		expect(inserts.length).toBeGreaterThanOrEqual(4);

		// 3 queue messages, one per target.
		expect(queueSend).toHaveBeenCalledTimes(3);
		const sentTargets = queueSend.mock.calls.map((c) => (c[0] as { target: string }).target).sort();
		expect(sentTargets).toEqual(['apple.com', 'brand-zeta.example.com', 'microsoft.com']);
	});

	it('refuses when quota is exceeded — no D1 write, no queue send', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const { db, calls } = makeMockD1();
		const queueSend = vi.fn();
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: false, remaining: 0, limit: 50, retryAfterMs: 86_400_000 });
		const deps = makeDeps({ db, queue: { send: queueSend }, enforceQuota });

		const result = await brandAuditBatchStart(['apple.com'], {}, 'pk', deps);

		const errorFinding = result.findings.find((f) => f.metadata?.quotaExceeded === true);
		expect(errorFinding).toBeDefined();
		expect(errorFinding?.severity).toBe('high');
		expect(calls.length).toBe(0);
		expect(queueSend).not.toHaveBeenCalled();
	});

	it('caps batch size at 50 — rejects 51+ without consuming quota', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const enforceQuota = vi.fn();
		const queueSend = vi.fn();
		const deps = makeDeps({ enforceQuota, queue: { send: queueSend } });

		const overSized = Array.from({ length: 51 }, (_, i) => `d${i}.example.com`);
		const result = await brandAuditBatchStart(overSized, {}, 'pk', deps);

		const errorFinding = result.findings.find((f) => f.metadata?.batchTooLarge === true);
		expect(errorFinding).toBeDefined();
		expect(enforceQuota).not.toHaveBeenCalled();
		expect(queueSend).not.toHaveBeenCalled();
	});

	it('rejects empty domain list with a validation error', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const enforceQuota = vi.fn();
		const deps = makeDeps({ enforceQuota });
		const result = await brandAuditBatchStart([], {}, 'pk', deps);

		const errorFinding = result.findings.find((f) => f.metadata?.invalidInput === true);
		expect(errorFinding).toBeDefined();
		expect(enforceQuota).not.toHaveBeenCalled();
	});

	it('deduplicates domains before quota check + enqueue', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const queueSend = vi.fn().mockResolvedValue(undefined);
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 });
		const deps = makeDeps({ queue: { send: queueSend }, enforceQuota });

		await brandAuditBatchStart(['apple.com', 'Apple.com', 'apple.com', 'brand-zeta.example.com'], {}, 'pk', deps);

		// Dedup + lowercase: 2 unique targets.
		expect(enforceQuota).toHaveBeenCalledWith(2);
		expect(queueSend).toHaveBeenCalledTimes(2);
	});

	it('stops short of any queue.send if the D1 parent insert fails', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const { db } = makeMockD1({ throwOnRun: true });
		const queueSend = vi.fn();
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 });
		const deps = makeDeps({ db, queue: { send: queueSend }, enforceQuota });

		const result = await brandAuditBatchStart(['apple.com'], {}, 'pk', deps);

		const errorFinding = result.findings.find((f) => f.metadata?.persistenceFailure === true);
		expect(errorFinding).toBeDefined();
		expect(queueSend).not.toHaveBeenCalled();
	});

	it('on partial enqueue failure: flips audit to failed, returns partialEnqueue summary listing failed targets', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const { db, calls } = makeMockD1();
		let callCount = 0;
		const queueSend = vi.fn().mockImplementation(async () => {
			callCount++;
			if (callCount === 2) throw new Error('queue_send_throttled');
		});
		const deps = makeDeps({ db, queue: { send: queueSend } });

		const result = await brandAuditBatchStart(
			['apple.com', 'microsoft.com', 'brand-zeta.example.com'],
			{},
			'pk',
			deps,
		);

		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.partialEnqueue).toBe(true);
		expect(summary?.metadata?.requestedCount).toBe(3);
		expect((summary?.metadata?.failedToEnqueue as unknown[])).toHaveLength(1);
		expect(summary?.metadata?.targetCount).toBe(2);

		const finalUpdate = calls.find(
			(c) => c.sql.includes('UPDATE brand_audits') && c.sql.includes("status = 'failed'"),
		);
		expect(finalUpdate).toBeDefined();
	});

	it('threads format through to the parent row + queue message', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const { db, calls } = makeMockD1();
		const queueSend = vi.fn().mockResolvedValue(undefined);
		const deps = makeDeps({ db, queue: { send: queueSend } });

		await brandAuditBatchStart(['apple.com'], { format: 'markdown' }, 'pk', deps);

		const parentInsert = calls.find((c) => c.sql.includes('INSERT INTO brand_audits'));
		expect(parentInsert?.binds).toContain('markdown');
		expect((queueSend.mock.calls[0][0] as { format: string }).format).toBe('markdown');
	});

	it('threads deep-scan inputs through queue messages', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const queueSend = vi.fn().mockResolvedValue(undefined);
		const deps = makeDeps({ queue: { send: queueSend } });

		await brandAuditBatchStart(
			['example.com'],
			{ depth: 'deep', brand_aliases: ['examplecorp'], candidate_domains: ['example.net'], planner_mode: 'enforce' },
			'pk',
			deps,
		);

		expect(queueSend).toHaveBeenCalledWith(
			expect.objectContaining({
				depth: 'deep',
				brand_aliases: ['examplecorp'],
				candidate_domains: ['example.net'],
				planner_mode: 'enforce',
			}),
			{ contentType: 'json' },
		);
	});
});
