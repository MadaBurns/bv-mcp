// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos hypotheses for the Phase-3 Tenant cron handlers
 * (`handleTenantWeeklyRescan` + `handleTenantCycleAlerts` in
 * `src/tenants/scheduled-handlers.ts`).
 *
 * Each test takes the form "Given [failure], system should
 * [degrade gracefully]." Per the testing-methodology skill, these are
 * explicit failure hypotheses, not regression smoke tests.
 */

import { describe, it, expect, vi } from 'vitest';
import { env } from 'cloudflare:test';
import type { TenantScheduledEnv } from '../../src/tenants/scheduled-handlers';
import type { DnsQueryFn } from '../../src/tenants/dns-fingerprint';
import type { DohResponse } from '../../src/lib/dns-types';

const SUPER = 'super-tenant-1';
const TENANT_A = 'tenant-1';
const TENANT_A_BINDING = 'TENANT_DB_TENANT_1';

const SQL_TAGS = {
	ACTIVE_TENANTS: 'FROM sub_tenants WHERE active = 1',
	DUE_DOMAINS: 'FROM domains',
	PENDING_CYCLES: 'completed_total + errored_total >= expected_total',
	STAMP_ALERT: 'UPDATE tenant_cycles SET alert_sent_at = ?',
	FINDINGS_FOR_CYCLE: 'FROM findings f',
	INSERT_CYCLE: 'INSERT INTO tenant_cycles',
	// Phase 4: the cron now resolves the per-tenant DB via resolveTenantUncached,
	// which reads this registry row (routing_mode → convention => the static binding).
	REGISTRY_LOOKUP: 'd1_db_id, routing_mode, active FROM sub_tenants',
} as const;

/** A convention-mode registry row so resolveTenantUncached resolves to the static binding. */
const REGISTRY_ROW_A = { id: TENANT_A, super_tenant_id: SUPER, d1_db_id: 'db-1', routing_mode: 'convention', active: 1 };

function makeCtx() {
	return { waitUntil: (_p: Promise<unknown>) => undefined };
}

const okMeta = (): D1ExecResult => ({ count: 0, duration: 0 } as unknown as D1ExecResult);

/** A registry D1 stub that throws on the very first read. */
function brokenRegistry(): D1Database {
	const stmt = {
		bind: () => stmt,
		async first<T = unknown>(): Promise<T | null> {
			throw new Error('registry_offline');
		},
		async all<_T = unknown>() {
			throw new Error('registry_offline');
		},
		async run() {
			throw new Error('registry_offline');
		},
		async raw() {
			return [] as unknown[];
		},
	};
	const db: Record<string, unknown> = {
		prepare: () => stmt as unknown as D1PreparedStatement,
		batch: async () => [],
		exec: async () => okMeta(),
		dump: () => {
			throw new Error('ni');
		},
		withSession: () => {
			throw new Error('ni');
		},
	};
	return db as unknown as D1Database;
}

/** Recording D1 stub that returns canned rows by SQL substring. */
function makeRecordingD1(rowsByTag: Record<string, unknown[]>) {
	const calls: Array<{ sql: string; binds: unknown[] }> = [];
	const lookup = (sql: string): unknown[] => {
		for (const tag of Object.keys(rowsByTag)) if (sql.includes(tag)) return rowsByTag[tag];
		return [];
	};
	const db: Record<string, unknown> = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					calls.push({ sql, binds });
					return ((lookup(sql)[0] ?? null) as T | null);
				},
				async all<T = unknown>() {
					calls.push({ sql, binds });
					return { results: lookup(sql) as T[], success: true, meta: {} } as unknown as D1Result<T>;
				},
				async run() {
					calls.push({ sql, binds });
					return { success: true, meta: {} } as unknown as D1Response;
				},
				async raw() {
					return [] as unknown[];
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
		batch: async () => [],
		exec: async () => okMeta(),
		dump: () => {
			throw new Error('ni');
		},
		withSession: () => {
			throw new Error('ni');
		},
	};
	return { db: db as unknown as D1Database, calls };
}

const okDns: DnsQueryFn = async (_d, _t): Promise<DohResponse> =>
	({ Status: 0, Answer: [] }) as DohResponse;

describe('Tenant cron chaos', () => {
	it('Hypothesis: when the registry D1 throws on tenant enumeration, handleTenantWeeklyRescan resolves cleanly without re-issuing queue sends', async () => {
		const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');

		const queueSends: unknown[] = [];
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: brokenRegistry(),
			BV_SCANNER_QUEUE: {
				async send(msg: unknown) {
					queueSends.push(msg);
				},
			},
		} as TenantScheduledEnv;

		await expect(
			handleTenantWeeklyRescan(customEnv, makeCtx(), {
				now: () => 1,
				newCycleId: () => 'c',
				dnsQuery: okDns,
			}),
		).resolves.toBeUndefined();
		// Tenant enumeration failed → no queue activity at all.
		expect(queueSends).toHaveLength(0);
	});

	it('Hypothesis: when queue.send throws on the 5th of 10 due domains, the prior sends still happened and the handler still resolves', async () => {
		const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');

		const due = Array.from({ length: 10 }, (_, i) => ({
			domain: `d${i}.com`,
			last_scanned_at: null,
			watch_interval_hours: 168,
			fingerprint: null,
		}));
		const registry = makeRecordingD1({
			[SQL_TAGS.ACTIVE_TENANTS]: [{ id: TENANT_A, super_tenant_id: SUPER }],
			[SQL_TAGS.REGISTRY_LOOKUP]: [REGISTRY_ROW_A],
		});
		const tenant = makeRecordingD1({ [SQL_TAGS.DUE_DOMAINS]: due });

		const queueSends: unknown[] = [];
		let callIdx = 0;
		const queue = {
			async send(msg: unknown) {
				if (callIdx === 4) {
					callIdx += 1;
					throw new Error('queue 503');
				}
				queueSends.push(msg);
				callIdx += 1;
			},
		};
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			BV_SCANNER_QUEUE: queue,
			[TENANT_A_BINDING]: tenant.db,
		} as TenantScheduledEnv;

		await expect(
			handleTenantWeeklyRescan(customEnv, makeCtx(), {
				now: () => 9_999_999_999_999,
				newCycleId: () => 'c1',
				dnsQuery: okDns,
			}),
		).resolves.toBeUndefined();

		// Sends 0..3 succeeded, send 4 threw, sends 5..9 still attempted.
		// We require all 9 surviving messages to have landed and exactly one
		// cycle row inserted with expected_total = 10 (9 queued + 1 errored).
		expect(queueSends.length).toBe(9);
		const cycleInserts = registry.calls.filter((c) => c.sql.includes(SQL_TAGS.INSERT_CYCLE));
		expect(cycleInserts).toHaveLength(1);
		expect(cycleInserts[0].binds[4]).toBe(10);
	});

	it('Hypothesis: a TRANSIENT registry error while resolving the tenant does NOT stamp the cycle skipped_no_tenant_binding (alert stays retryable) — T2', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');

		const cycle = {
			id: 'cycle-curr',
			super_tenant_id: SUPER,
			sub_tenant_id: TENANT_A,
			started_at: 1_000_000,
			expected_total: 1,
			completed_total: 1,
			errored_total: 0,
			baseline_cycle_id: 'cycle-base',
		};

		// Registry: PENDING_CYCLES enumerates the settled cycle, but the per-tenant
		// REGISTRY_LOOKUP read throws a TRANSIENT error (not "Tenant not found").
		const stampRuns: Array<{ sql: string; binds: unknown[] }> = [];
		const registry: Record<string, unknown> = {
			prepare(sql: string) {
				let binds: unknown[] = [];
				const stmt = {
					bind(...args: unknown[]) {
						binds = args;
						return stmt;
					},
					async first<T = unknown>(): Promise<T | null> {
						if (sql.includes(SQL_TAGS.REGISTRY_LOOKUP)) {
							throw new Error('D1_ERROR: database is locked: SQLITE_BUSY');
						}
						return null as T | null;
					},
					async all<T = unknown>() {
						if (sql.includes(SQL_TAGS.PENDING_CYCLES)) {
							return { results: [cycle] as T[], success: true, meta: {} } as unknown as D1Result<T>;
						}
						return { results: [] as T[], success: true, meta: {} } as unknown as D1Result<T>;
					},
					async run() {
						if (sql.includes(SQL_TAGS.STAMP_ALERT)) stampRuns.push({ sql, binds });
						return { success: true, meta: {} } as unknown as D1Response;
					},
					async raw() {
						return [] as unknown[];
					},
				};
				return stmt as unknown as D1PreparedStatement;
			},
			batch: async () => [],
			exec: async () => okMeta(),
			dump: () => {
				throw new Error('ni');
			},
			withSession: () => {
				throw new Error('ni');
			},
		};

		const sendAlert = vi.fn(async () => ({ delivered: true, status: 200 }));
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry as unknown as D1Database,
			[TENANT_A_BINDING]: {} as D1Database,
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/abc',
		} as TenantScheduledEnv;

		// The handler stays fail-soft (no throw out of the tick) because the outer
		// sweep loop catches the re-thrown transient error and logs it.
		await expect(
			handleTenantCycleAlerts(customEnv, makeCtx(), { now: () => 2_000_000, sendAlert }),
		).resolves.toBeUndefined();

		// The transient error must NOT be conflated with a missing tenant: no stamp
		// at all → alert_sent_at stays NULL → the next cron tick retries the cycle.
		expect(stampRuns).toHaveLength(0);
		// And the alert webhook was never (mis)fired for an unresolved tenant.
		expect(sendAlert).not.toHaveBeenCalled();
	});

	it('Hypothesis: webhook returns delivered:false → registry stamps "webhook_failed" with alert_sent_at set so the next sweep does NOT retry', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');

		const cycle = {
			id: 'cycle-curr',
			super_tenant_id: SUPER,
			sub_tenant_id: TENANT_A,
			started_at: 1_000_000,
			expected_total: 1,
			completed_total: 1,
			errored_total: 0,
			baseline_cycle_id: 'cycle-base',
		};
		const registry = makeRecordingD1({
			[SQL_TAGS.PENDING_CYCLES]: [cycle],
			[SQL_TAGS.REGISTRY_LOOKUP]: [REGISTRY_ROW_A],
		});

		// Tenant DB returns differing findings per cycle id so deltas > 0.
		const tenant: Record<string, unknown> = {
			prepare(sql: string) {
				let binds: unknown[] = [];
				const stmt = {
					bind(...args: unknown[]) {
						binds = args;
						return stmt;
					},
					async first<T = unknown>(): Promise<T | null> {
						return null as T | null;
					},
					async all<T = unknown>() {
						if (sql.includes(SQL_TAGS.FINDINGS_FOR_CYCLE)) {
							const cycleId = binds[0] as string;
							if (cycleId === 'cycle-curr') {
								return {
									results: [
										{ domain: 'a.com', category: 'spf', severity: 'high', title: 'spf weak' },
									] as T[],
									success: true,
									meta: {},
								} as unknown as D1Result<T>;
							}
							return { results: [] as T[], success: true, meta: {} } as unknown as D1Result<T>;
						}
						return { results: [] as T[], success: true, meta: {} } as unknown as D1Result<T>;
					},
					async run() {
						return { success: true, meta: {} } as unknown as D1Response;
					},
					async raw() {
						return [] as unknown[];
					},
				};
				return stmt as unknown as D1PreparedStatement;
			},
			batch: async () => [],
			exec: async () => okMeta(),
			dump: () => {
				throw new Error('ni');
			},
			withSession: () => {
				throw new Error('ni');
			},
		};

		const sendAlert = vi.fn(async () => ({ delivered: false, status: 503 }));
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			[TENANT_A_BINDING]: tenant as unknown as D1Database,
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/abc',
		} as TenantScheduledEnv;

		await handleTenantCycleAlerts(customEnv, makeCtx(), {
			now: () => 2_000_000,
			sendAlert,
		});

		expect(sendAlert).toHaveBeenCalledTimes(1);
		const stamps = registry.calls.filter((c) => c.sql.includes(SQL_TAGS.STAMP_ALERT));
		expect(stamps).toHaveLength(1);
		// alert_sent_at (binds[0]) is set so the cycle won't loop next tick.
		expect(stamps[0].binds[0]).toBe(2_000_000);
		// alert_outcome (binds[1]) records the failure.
		expect(stamps[0].binds[1]).toBe('webhook_failed');
	});
});
