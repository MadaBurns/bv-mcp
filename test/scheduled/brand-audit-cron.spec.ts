// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';

interface D1Call {
	sql: string;
	binds: unknown[];
}

interface AuditRow {
	owner_id: string;
	total_targets: number;
	format: string;
}

function makeExecutionContext(): ExecutionContext {
	return {
		waitUntil(promise: Promise<unknown>) {
			void promise;
		},
		passThroughOnException() {},
		exports: {} as ExecutionContext['exports'],
		props: undefined,
		tracing: {} as ExecutionContext['tracing'],
		abort(reason?: unknown) {
			void reason;
		},
	};
}

function makeMockD1(opts: { watches?: Record<string, unknown>[]; throwOnAll?: boolean } = {}) {
	const calls: D1Call[] = [];
	const audits = new Map<string, AuditRow>();
	const targets = new Set<string>();
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
					if (sql.includes('JOIN brand_audit_targets')) {
						const auditId = String(binds[0]);
						const target = String(binds[1]);
						const audit = audits.get(auditId);
						if (!audit || !targets.has(`${auditId}\0${target}`)) return null;
						return { ...audit, target };
					}
					return null;
				},
				async all() {
					calls.push({ sql, binds });
					if (opts.throwOnAll) throw new Error('d1_all_failed');
					const [dailyCutoff, weeklyCutoff, monthlyCutoff, limit] = binds as number[];
					const cutoffs: Record<string, number> = { daily: dailyCutoff, weekly: weeklyCutoff, monthly: monthlyCutoff };
					const results = (opts.watches ?? [])
						.filter((row) => {
							const interval = String(row.interval);
							if (!(interval in cutoffs) || row.active === 0) return false;
							return row.last_run_at === null || Number(row.last_run_at) <= cutoffs[interval];
						})
						.sort((left, right) => {
							if (left.last_run_at === null) return right.last_run_at === null ? String(left.id).localeCompare(String(right.id)) : -1;
							if (right.last_run_at === null) return 1;
							return Number(left.last_run_at) - Number(right.last_run_at) || String(left.id).localeCompare(String(right.id));
						})
						.slice(0, limit);
					return { results, success: true, meta: {} };
				},
				async run() {
					calls.push({ sql, binds });
					if (sql.includes('INSERT OR IGNORE INTO brand_audits')) {
						const [id, ownerId, , totalTargets, , format] = binds;
						if (!audits.has(String(id))) {
							audits.set(String(id), {
								owner_id: String(ownerId),
								total_targets: Number(totalTargets),
								format: String(format),
							});
						}
					}
					if (sql.includes('INSERT OR IGNORE INTO brand_audit_targets')) {
						targets.add(`${String(binds[0])}\0${String(binds[1])}`);
					}
					return { success: true, meta: { changes: 1 } };
				},
			};
			return stmt;
		},
		async batch(statements: Array<{ run(): Promise<unknown> }>) {
			return Promise.all(statements.map((statement) => statement.run()));
		},
	} as unknown as D1Database;
	return { db, calls };
}

function watch(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		id: 'w-1',
		owner_id: 'owner-1',
		domain: 'apple.com',
		interval: 'daily',
		webhook_url: 'https://hooks.example.com/a',
		last_run_at: null,
		last_classification_hash: null,
		active: 1,
		...overrides,
	};
}

describe('handleBrandAuditWatches', () => {
	it('no-ops when the database or queue binding is missing', async () => {
		const { handleBrandAuditWatches } = await import('../../src/scheduled');
		const queueSend = vi.fn();
		await handleBrandAuditWatches({ BRAND_AUDIT_QUEUE: { send: queueSend } }, makeExecutionContext());
		expect(queueSend).not.toHaveBeenCalled();

		const { db } = makeMockD1();
		await handleBrandAuditWatches({ BRAND_AUDIT_DB: db }, makeExecutionContext());
	});

	it('persists an exact parent+target precondition before enqueue, then CAS-advances last_run_at', async () => {
		const { handleBrandAuditWatches } = await import('../../src/scheduled');
		const { db, calls } = makeMockD1({
			watches: [watch(), watch({ id: 'w-2', owner_id: 'owner-2', domain: 'brand-zeta.example.com', interval: 'weekly' })],
		});
		const queueSend = vi.fn().mockResolvedValue(undefined);

		await handleBrandAuditWatches({ BRAND_AUDIT_DB: db, BRAND_AUDIT_QUEUE: { send: queueSend } }, makeExecutionContext());

		expect(queueSend).toHaveBeenCalledTimes(2);
		for (const call of queueSend.mock.calls) {
			const message = call[0] as { auditId: string };
			expect(message.auditId).toMatch(/^watch_[0-9a-f]{58}$/);
			expect(message.auditId).toHaveLength(64);
		}
		const firstInsert = calls.findIndex((call) => call.sql.includes('INSERT OR IGNORE INTO brand_audits'));
		const firstVerify = calls.findIndex((call) => call.sql.includes('JOIN brand_audit_targets'));
		const firstUpdate = calls.findIndex((call) => call.sql.includes('UPDATE brand_audit_watches'));
		expect(firstInsert).toBeGreaterThan(-1);
		expect(firstVerify).toBeGreaterThan(firstInsert);
		expect(firstUpdate).toBeGreaterThan(firstVerify);
		const updates = calls.filter((call) => call.sql.includes('UPDATE brand_audit_watches'));
		expect(updates).toHaveLength(2);
		expect(updates.every((call) => call.sql.includes('last_run_at IS ?'))).toBe(true);
	});

	it('filters due intervals in SQL before LIMIT so 100 monthly watches cannot starve a due daily watch', async () => {
		const { handleBrandAuditWatches, MAX_WATCHES_PER_TICK } = await import('../../src/scheduled');
		const now = Date.now();
		const notDueMonthly = Array.from({ length: MAX_WATCHES_PER_TICK + 25 }, (_, index) =>
			watch({ id: `monthly-${String(index).padStart(3, '0')}`, interval: 'monthly', last_run_at: now - 10 * 86_400_000 }),
		);
		const dueDaily = watch({ id: 'daily-due', domain: 'daily.example.com', interval: 'daily', last_run_at: now - 2 * 86_400_000 });
		const { db, calls } = makeMockD1({ watches: [...notDueMonthly, dueDaily] });
		const queueSend = vi.fn().mockResolvedValue(undefined);

		await handleBrandAuditWatches({ BRAND_AUDIT_DB: db, BRAND_AUDIT_QUEUE: { send: queueSend } }, makeExecutionContext());

		expect(queueSend).toHaveBeenCalledOnce();
		expect(queueSend.mock.calls[0][0]).toEqual(expect.objectContaining({ target: 'daily.example.com', watchId: 'daily-due' }));
		const enumeration = calls.find((call) => call.sql.includes('FROM brand_audit_watches'));
		expect(enumeration).toBeDefined();
		expect(enumeration!.sql.indexOf("interval = 'daily'")).toBeLessThan(enumeration!.sql.indexOf('LIMIT ?'));
		expect(enumeration!.sql).toContain("interval IN ('daily', 'weekly', 'monthly')");
	});

	it('leaves last_run_at unchanged on queue failure and reuses the deterministic audit ID on retry', async () => {
		const { handleBrandAuditWatches } = await import('../../src/scheduled');
		const due = watch({ last_run_at: 1_700_000_000_000 });
		const { db, calls } = makeMockD1({ watches: [due] });
		const queueSend = vi.fn().mockRejectedValueOnce(new Error('queue unavailable')).mockResolvedValueOnce(undefined);
		const env = { BRAND_AUDIT_DB: db, BRAND_AUDIT_QUEUE: { send: queueSend } };

		await handleBrandAuditWatches(env, makeExecutionContext());
		expect(calls.filter((call) => call.sql.includes('UPDATE brand_audit_watches'))).toHaveLength(0);
		await handleBrandAuditWatches(env, makeExecutionContext());

		expect(queueSend).toHaveBeenCalledTimes(2);
		expect((queueSend.mock.calls[0][0] as { auditId: string }).auditId).toBe((queueSend.mock.calls[1][0] as { auditId: string }).auditId);
		expect(calls.filter((call) => call.sql.includes('UPDATE brand_audit_watches'))).toHaveLength(1);
	});

	it('fails closed for an unknown interval and contains D1 enumeration failure', async () => {
		const { handleBrandAuditWatches } = await import('../../src/scheduled');
		const invalid = makeMockD1({ watches: [watch({ interval: 'hourly' })] });
		const invalidQueue = vi.fn();
		await handleBrandAuditWatches({ BRAND_AUDIT_DB: invalid.db, BRAND_AUDIT_QUEUE: { send: invalidQueue } }, makeExecutionContext());
		expect(invalidQueue).not.toHaveBeenCalled();

		const broken = makeMockD1({ throwOnAll: true });
		const brokenQueue = vi.fn();
		await handleBrandAuditWatches({ BRAND_AUDIT_DB: broken.db, BRAND_AUDIT_QUEUE: { send: brokenQueue } }, makeExecutionContext());
		expect(brokenQueue).not.toHaveBeenCalled();
	});
});
