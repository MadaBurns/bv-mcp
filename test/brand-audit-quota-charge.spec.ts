// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-290 item 5 — the monthly brand-audit quota unit is charged only for work
 * that actually happens. The quota coordinator has no refund primitive, so the
 * charge is DEFERRED until the handoff / persistence decision rather than
 * refunded:
 *
 *   - `brand_audit_single` with `timeoutBehavior: 'async_handoff'` used to charge
 *     one unit up front, then hand the caller to `brand_audit_batch_start`, which
 *     charged again for the same target (double charge). A handoff is now
 *     uncharged; the batch start that follows is the one charge.
 *   - `brand_audit_batch_start` used to charge before persisting, so a D1
 *     persistence failure (described to the caller as "safe to retry") still
 *     consumed quota. It now persists first and charges only once the rows exist.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import type { BrandAuditSingleDeps } from '../src/tools/brand-audit-single';
import type { BrandAuditBatchStartDeps } from '../src/tools/brand-audit-batch-start';

afterEach(() => {
	vi.useRealTimers();
});

const discovery = (): CheckResult => ({
	category: 'brand_discovery',
	passed: true,
	score: 100,
	findings: [
		{
			category: 'brand_discovery',
			title: 'Brand-domain discovery: 0 candidate(s) at confidence ≥ 0.5',
			severity: 'info',
			detail: 'Seed=example.com',
			metadata: { summary: true, signals: ['san'], signalStatus: {}, minConfidence: 0.5, totalAggregated: 0, surfaced: 0 },
		},
	],
});

describe('brand_audit_single quota charge (async_handoff)', () => {
	it('does not charge quota when the sync budget expires and the caller is handed off to batch_start', async () => {
		vi.useFakeTimers();
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 });
		const deps: BrandAuditSingleDeps = {
			discoverBrandDomains: vi.fn(() => new Promise<CheckResult>(() => {})),
			checkRdapLookup: vi.fn(),
			enforceQuota,
		};

		const resultPromise = brandAuditSingle('example.com', { deadlineMs: 24_000, now: () => 0, timeoutBehavior: 'async_handoff' }, deps);
		await vi.advanceTimersByTimeAsync(24_000);
		const result = await resultPromise;

		expect(result.findings[0].metadata?.asyncHandoff).toBe(true);
		// The abstaining handoff shape (#1196) must not change the uncharged-handoff contract.
		expect(result).toMatchObject({ score: 0, passed: false, checkStatus: 'timeout', partial: true });
		expect(enforceQuota).not.toHaveBeenCalled();
	});

	it('charges exactly one unit, after the pipeline completes inside the sync budget', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 });
		const chargesWhileRunning: number[] = [];
		const deps: BrandAuditSingleDeps = {
			discoverBrandDomains: vi.fn(async () => {
				chargesWhileRunning.push(enforceQuota.mock.calls.length);
				return discovery();
			}),
			checkRdapLookup: vi.fn(),
			enforceQuota,
		};

		const result = await brandAuditSingle('example.com', { deadlineMs: Date.now() + 60_000, timeoutBehavior: 'async_handoff' }, deps);

		expect(result.findings.some((f) => f.metadata?.quotaExceeded === true)).toBe(false);
		expect(chargesWhileRunning).toEqual([0]); // deferred: nothing charged while the pipeline ran
		expect(enforceQuota).toHaveBeenCalledTimes(1);
		expect(enforceQuota).toHaveBeenCalledWith(1);
	});

	it('withholds the result with a quotaExceeded finding when the deferred charge is denied', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: false, remaining: 0, limit: 50, retryAfterMs: 86_400_000 });
		const deps: BrandAuditSingleDeps = {
			discoverBrandDomains: vi.fn(async () => discovery()),
			checkRdapLookup: vi.fn(),
			enforceQuota,
		};

		const result = await brandAuditSingle('example.com', { deadlineMs: Date.now() + 60_000, timeoutBehavior: 'async_handoff' }, deps);

		const exceeded = result.findings.find((f) => f.metadata?.quotaExceeded === true);
		expect(exceeded).toBeDefined();
		expect(exceeded?.metadata?.limit).toBe(50);
		// The unpaid result is not leaked alongside the refusal.
		expect(result.findings).toHaveLength(1);
	});

	it('does not charge when the pipeline throws', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 });
		const deps: BrandAuditSingleDeps = {
			discoverBrandDomains: vi.fn(async () => {
				throw new Error('discovery exploded');
			}),
			checkRdapLookup: vi.fn(),
			enforceQuota,
		};

		await expect(
			brandAuditSingle('example.com', { deadlineMs: Date.now() + 60_000, timeoutBehavior: 'async_handoff' }, deps),
		).rejects.toThrow();
		expect(enforceQuota).not.toHaveBeenCalled();
	});

	it('without async_handoff (no handoff can happen) the unit is still charged up front', async () => {
		const { brandAuditSingle } = await import('../src/tools/brand-audit-single');
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 });
		const chargesWhileRunning: number[] = [];
		const deps: BrandAuditSingleDeps = {
			discoverBrandDomains: vi.fn(async () => {
				chargesWhileRunning.push(enforceQuota.mock.calls.length);
				return discovery();
			}),
			checkRdapLookup: vi.fn(),
			enforceQuota,
		};

		await brandAuditSingle('example.com', {}, deps);

		expect(chargesWhileRunning).toEqual([1]);
		expect(enforceQuota).toHaveBeenCalledTimes(1);
	});
});

interface D1Call {
	sql: string;
	binds: unknown[];
}

function makeD1(opts: { failInsert?: boolean } = {}) {
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
					if (opts.failInsert && sql.startsWith('INSERT')) throw new Error('d1_insert_failed');
					return { success: true, meta: { changes: 1 } };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return { db, calls };
}

function batchDeps(overrides: Partial<BrandAuditBatchStartDeps>): BrandAuditBatchStartDeps {
	return {
		db: makeD1().db,
		queue: { send: vi.fn().mockResolvedValue(undefined) },
		enforceQuota: vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 }),
		generateId: () => 'audit-test-id',
		now: () => 1_750_000_000_000,
		...overrides,
	};
}

describe('brand_audit_batch_start quota charge (persist first)', () => {
	it('does not consume quota when persistence fails (the "safe to retry" path)', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const { db } = makeD1({ failInsert: true });
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: true, remaining: 49, limit: 50 });

		const result = await brandAuditBatchStart(['apple.com', 'microsoft.com'], {}, 'pk', batchDeps({ db, enforceQuota }));

		expect(result.findings.some((f) => f.metadata?.persistenceFailure === true)).toBe(true);
		expect(enforceQuota).not.toHaveBeenCalled();
	});

	it('charges only after the audit + target rows are persisted, and before anything is enqueued', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const { db, calls } = makeD1();
		const order: string[] = [];
		const enforceQuota = vi.fn(async () => {
			order.push(`charge(after ${calls.filter((c) => c.sql.startsWith('INSERT')).length} inserts)`);
			return { allowed: true, remaining: 47, limit: 50 };
		});
		const queue = {
			send: vi.fn(async () => {
				order.push('enqueue');
			}),
		};

		await brandAuditBatchStart(['apple.com', 'microsoft.com'], {}, 'pk', batchDeps({ db, enforceQuota, queue }));

		expect(order[0]).toBe('charge(after 3 inserts)'); // 1 parent + 2 targets
		expect(order.slice(1)).toEqual(['enqueue', 'enqueue']);
		expect(enforceQuota).toHaveBeenCalledWith(2);
	});

	it('quota denied: nothing is enqueued and the rows persisted ahead of the charge are removed', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const { db, calls } = makeD1();
		const queueSend = vi.fn();
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: false, remaining: 0, limit: 50, retryAfterMs: 86_400_000 });

		const result = await brandAuditBatchStart(['apple.com'], {}, 'pk', batchDeps({ db, enforceQuota, queue: { send: queueSend } }));

		expect(result.findings.find((f) => f.metadata?.quotaExceeded === true)).toBeDefined();
		expect(queueSend).not.toHaveBeenCalled();
		const deletes = calls.filter((c) => c.sql.startsWith('DELETE'));
		expect(deletes.some((c) => c.sql.includes('brand_audit_targets') && c.binds.includes('audit-test-id'))).toBe(true);
		expect(
			deletes.some((c) => c.sql.includes('brand_audits') && !c.sql.includes('brand_audit_targets') && c.binds.includes('audit-test-id')),
		).toBe(true);
	});

	it('quota denied: a failing cleanup is swallowed (still returns quotaExceeded)', async () => {
		const { brandAuditBatchStart } = await import('../src/tools/brand-audit-batch-start');
		const db = {
			prepare(sql: string) {
				const stmt = {
					bind: () => stmt,
					async run() {
						if (sql.startsWith('DELETE')) throw new Error('d1_delete_failed');
						return { success: true, meta: { changes: 1 } };
					},
				};
				return stmt;
			},
		} as unknown as D1Database;
		const enforceQuota = vi.fn().mockResolvedValue({ allowed: false, remaining: 0, limit: 50 });

		const result = await brandAuditBatchStart(['apple.com'], {}, 'pk', batchDeps({ db, enforceQuota }));

		expect(result.findings.find((f) => f.metadata?.quotaExceeded === true)).toBeDefined();
	});
});
