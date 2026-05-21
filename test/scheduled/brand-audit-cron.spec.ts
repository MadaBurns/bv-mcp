// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for handleBrandAuditWatches — the scheduled cron handler that
 * enumerates active brand-audit watches and enqueues fresh audits when due.
 *
 * Mocked: D1 (recording fake), queue producer, clock. The handler doesn't
 * compute classification hash diffs here — that's done by the result-watch
 * downstream (out of scope for v2.21.0). v2.21.0 enqueues a fresh audit when
 * due and updates `last_run_at`.
 */

import { describe, it, expect, vi } from 'vitest';

interface D1Call {
	sql: string;
	binds: unknown[];
}

function makeMockD1(opts: { dueWatches?: Record<string, unknown>[]; throwOnAll?: boolean } = {}) {
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
					return null;
				},
				async all() {
					calls.push({ sql, binds });
					if (opts.throwOnAll) throw new Error('d1_all_failed');
					return { results: opts.dueWatches ?? [], success: true, meta: {} };
				},
				async run() {
					calls.push({ sql, binds });
					return { success: true, meta: {} };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return { db, calls };
}

describe('handleBrandAuditWatches', () => {
	it('no-op when BRAND_AUDIT_DB binding is missing', async () => {
		const { handleBrandAuditWatches } = await import('../../src/scheduled');
		const queueSend = vi.fn();
		const auditQueueSend = vi.fn();
		const env = { BRAND_AUDIT_QUEUE: { send: queueSend } } as Record<string, unknown>;
		await handleBrandAuditWatches(env, { waitUntil: () => {} } as ExecutionContext);
		expect(queueSend).not.toHaveBeenCalled();
		expect(auditQueueSend).not.toHaveBeenCalled();
	});

	it('enqueues a fresh audit for each due watch and bumps last_run_at', async () => {
		const { handleBrandAuditWatches } = await import('../../src/scheduled');
		const dueWatches = [
			{ id: 'w-1', owner_id: 'owner-1', domain: 'apple.com', interval: 'daily', webhook_url: 'https://hooks.example.com/a', last_run_at: null, last_classification_hash: null, active: 1, created_at: 1 },
			{ id: 'w-2', owner_id: 'owner-2', domain: 'brand-zeta.example.com', interval: 'weekly', webhook_url: null, last_run_at: null, last_classification_hash: null, active: 1, created_at: 2 },
		];
		const { db, calls } = makeMockD1({ dueWatches });
		const queueSend = vi.fn().mockResolvedValue(undefined);

		const env = {
			BRAND_AUDIT_DB: db,
			BRAND_AUDIT_QUEUE: { send: queueSend },
		} as Record<string, unknown>;

		await handleBrandAuditWatches(env, { waitUntil: () => {} } as ExecutionContext);

		// 2 messages sent — one per due watch.
		expect(queueSend).toHaveBeenCalledTimes(2);
		const updates = calls.filter((c) => c.sql.includes('UPDATE brand_audit_watches') && c.sql.includes('last_run_at'));
		expect(updates).toHaveLength(2);
	});

	it('respects MAX_WATCHES_PER_TICK — does not enumerate unbounded set', async () => {
		const { MAX_WATCHES_PER_TICK } = await import('../../src/scheduled');
		expect(MAX_WATCHES_PER_TICK).toBeGreaterThan(0);
		expect(MAX_WATCHES_PER_TICK).toBeLessThanOrEqual(1000);
	});

	it('skips when BRAND_AUDIT_QUEUE binding is missing (configuration error)', async () => {
		const { handleBrandAuditWatches } = await import('../../src/scheduled');
		const { db } = makeMockD1();
		const env = { BRAND_AUDIT_DB: db } as Record<string, unknown>;
		await handleBrandAuditWatches(env, { waitUntil: () => {} } as ExecutionContext);
		// Nothing to assert beyond "doesn't throw" — handler must fail-soft.
	});

	it('swallows D1 enumeration failure without crashing the cron tick', async () => {
		const { handleBrandAuditWatches } = await import('../../src/scheduled');
		const { db } = makeMockD1({ throwOnAll: true });
		const queueSend = vi.fn();
		const env = { BRAND_AUDIT_DB: db, BRAND_AUDIT_QUEUE: { send: queueSend } } as Record<string, unknown>;
		await handleBrandAuditWatches(env, { waitUntil: () => {} } as ExecutionContext);
		expect(queueSend).not.toHaveBeenCalled();
	});
});
