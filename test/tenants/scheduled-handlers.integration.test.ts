// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the Phase-3 Tenant scheduled handlers
 * (`handleTenantWeeklyRescan` + `handleTenantCycleAlerts` in
 * `src/tenants/scheduled-handlers.ts`).
 *
 * Pattern mirrors `test/tenants/queue-consumer.integration.test.ts`:
 *   - Recording D1 fake keyed by SQL string.
 *   - Test seams (`now`, `newCycleId`, `dnsQuery`, `sendAlert`) injected via
 *     the handler `options` argument so we never need to mock global fetch.
 *
 * One observable behaviour per test (TDD discipline).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';
import type { TenantScheduledEnv } from '../../src/tenants/scheduled-handlers';
import type { DnsQueryFn } from '../../src/tenants/dns-fingerprint';
import type { DohResponse } from '../../src/lib/dns-types';

const SUPER = 'super-tenant-1';
const TENANT_A = 'tenant-1';
const TENANT_A_BINDING = 'TENANT_DB_TENANT_1';
const TENANT_B = 'tenant-2';
const TENANT_B_BINDING = 'TENANT_DB_TENANT_2';

// --- SQL fingerprints (substring tags — production SQL uses tabbed template
//     literals, so we identify each statement by a unique substring instead
//     of relying on byte-exact whitespace).

const SQL_TAGS = {
	ACTIVE_TENANTS: 'FROM sub_tenants WHERE active = 1',
	DUE_DOMAINS: 'FROM domains',
	UPDATE_FINGERPRINT: 'UPDATE domains SET fingerprint = ?',
	INSERT_CYCLE: 'INSERT INTO tenant_cycles',
	INCREMENT_ERRORED: 'UPDATE tenant_cycles SET errored_total',
	FIND_BASELINE: 'alert_sent_at IS NOT NULL ORDER BY started_at DESC',
	PENDING_CYCLES: 'completed_total + errored_total >= expected_total',
	STAMP_ALERT: 'UPDATE tenant_cycles SET alert_sent_at = ?',
	FINDINGS_FOR_CYCLE: 'FROM findings f',
} as const;

const ACTIVE_TENANTS_SQL = SQL_TAGS.ACTIVE_TENANTS;
const DUE_DOMAINS_SQL = SQL_TAGS.DUE_DOMAINS;
const UPDATE_FINGERPRINT_SQL = SQL_TAGS.UPDATE_FINGERPRINT;
const INSERT_CYCLE_SQL = SQL_TAGS.INSERT_CYCLE;
const INCREMENT_ERRORED_SQL = SQL_TAGS.INCREMENT_ERRORED;
const FIND_BASELINE_CYCLE_SQL = SQL_TAGS.FIND_BASELINE;
const PENDING_CYCLES_SQL = SQL_TAGS.PENDING_CYCLES;
const STAMP_ALERT_SQL = SQL_TAGS.STAMP_ALERT;
const FINDINGS_FOR_CYCLE_SQL = SQL_TAGS.FINDINGS_FOR_CYCLE;

/** Match a recorded call by SQL substring (production SQL contains the tag). */
function callMatches(sql: string, tag: string): boolean {
	return sql.includes(tag);
}

// --- Mock D1 (recording, SQL-keyed) --------------------------------------

type RecordedCall = { sql: string; binds: unknown[] };

interface MakeMockD1Options {
	rowsBySql?: Record<string, unknown[]>;
	throwOnSql?: Set<string>;
}

/** Look up rows by tag-substring. Both keys and `sql` are substring-matched. */
function lookupRows(rowsBySql: Record<string, unknown[]>, sql: string): unknown[] {
	for (const tag of Object.keys(rowsBySql)) {
		if (sql.includes(tag)) return rowsBySql[tag];
	}
	// Phase 4: the cron now resolves the per-tenant DB handle via
	// `resolveTenantUncached`, which issues `REGISTRY_LOOKUP_SQL` against the
	// registry. Default to a resolvable, active, convention-routed tenant unless
	// a test overrides it — buildTenantDb derives the binding from the id, so this
	// single synthetic row serves every tenant id.
	if (sql.includes('routing_mode, active FROM sub_tenants')) {
		return [{ active: 1, routing_mode: null }];
	}
	return [];
}

function shouldThrow(throwOnSql: Set<string>, sql: string): boolean {
	for (const tag of throwOnSql) if (sql.includes(tag)) return true;
	return false;
}

function makeMockD1(opts: MakeMockD1Options = {}) {
	const rowsBySql = opts.rowsBySql ?? {};
	const throwOnSql = opts.throwOnSql ?? new Set<string>();
	const calls: RecordedCall[] = [];
	const db: D1Database = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					calls.push({ sql, binds });
					if (shouldThrow(throwOnSql, sql)) throw new Error('d1_first_failed');
					const rows = lookupRows(rowsBySql, sql);
					return (rows[0] as T | undefined) ?? null;
				},
				async all<T = unknown>() {
					calls.push({ sql, binds });
					if (shouldThrow(throwOnSql, sql)) throw new Error('d1_all_failed');
					const rows = lookupRows(rowsBySql, sql);
					return { results: rows as T[], success: true, meta: {} } as unknown as D1Result<T>;
				},
				async run() {
					calls.push({ sql, binds });
					if (shouldThrow(throwOnSql, sql)) throw new Error('d1_run_failed');
					return {
						success: true,
						meta: { changes: 1, last_row_id: 0, duration: 0, rows_read: 0, rows_written: 1, size_after: 0 },
					} as unknown as D1Response;
				},
				async raw() {
					calls.push({ sql, binds });
					return [] as unknown[];
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
		async batch<T = unknown>(stmts: D1PreparedStatement[]): Promise<D1Result<T>[]> {
			const out: D1Result<T>[] = [];
			for (const s of stmts) {
				const r = (await (s as unknown as { run: () => Promise<unknown> }).run()) as D1Result<T>;
				out.push(r);
			}
			return out;
		},
		async exec() {
			return { count: 0, duration: 0 } as unknown as D1ExecResult;
		},
		dump() {
			throw new Error('not implemented');
		},
		withSession() {
			throw new Error('not implemented');
		},
	} as unknown as D1Database;
	return { db, calls };
}

interface MockQueue {
	sends: Array<{ msg: unknown; opts?: unknown }>;
	send: (msg: unknown, opts?: unknown) => Promise<void>;
}

function makeMockQueue(): MockQueue {
	const sends: Array<{ msg: unknown; opts?: unknown }> = [];
	return {
		sends,
		async send(msg: unknown, sendOpts?: unknown) {
			sends.push({ msg, opts: sendOpts });
		},
	};
}

function makeCtx() {
	return { waitUntil: (_p: Promise<unknown>) => undefined };
}

// Build a stub DnsQueryFn driven by per-domain options.
function makeDnsQuery(opts: {
	throwForDomains?: Set<string>;
	txt?: Record<string, string[]>;
	mxByDomain?: Record<string, Array<{ priority: number; host: string }>>;
}): DnsQueryFn {
	return async (domain: string, type: string): Promise<DohResponse> => {
		// Match the bare domain plus the `_dmarc.<domain>` sub-query so every
		// fingerprint sub-query fires the failure path (otherwise allSettled
		// keeps one fulfilled response and the overall fingerprint succeeds).
		const matched =
			opts.throwForDomains &&
			[...opts.throwForDomains].some(
				(d) => domain === d || domain === `_dmarc.${d}` || domain.endsWith(`.${d}`),
			);
		if (matched) throw new Error('dns_failed');
		if (type === 'TXT') {
			const items = opts.txt?.[domain] ?? [];
			return {
				Status: 0,
				Answer: items.map((data) => ({ name: domain, type: 16, TTL: 60, data: `"${data}"` })),
			} as DohResponse;
		}
		if (type === 'MX') {
			const items = opts.mxByDomain?.[domain] ?? [];
			return {
				Status: 0,
				Answer: items.map((m) => ({
					name: domain,
					type: 15,
					TTL: 60,
					data: `${m.priority} ${m.host}`,
				})),
			} as DohResponse;
		}
		return { Status: 0, Answer: [] } as DohResponse;
	};
}

beforeEach(() => {
	vi.restoreAllMocks();
});

// =========================================================================
// handleTenantWeeklyRescan
// =========================================================================

describe('handleTenantWeeklyRescan', () => {
	it('a. enqueues 1 scan per due domain whose fingerprint differs and inserts one tenant_cycles row per sub-tenant', async () => {
		const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({
			rowsBySql: {
				[ACTIVE_TENANTS_SQL]: [
					{ id: TENANT_A, super_tenant_id: SUPER },
					{ id: TENANT_B, super_tenant_id: SUPER },
				],
			},
		});
		const tenantA = makeMockD1({
			rowsBySql: {
				[DUE_DOMAINS_SQL]: [
					{ domain: 'a1.com', last_scanned_at: 0, watch_interval_hours: 168, fingerprint: 'old1' },
					{ domain: 'a2.com', last_scanned_at: 0, watch_interval_hours: 168, fingerprint: 'old2' },
					{ domain: 'a3.com', last_scanned_at: 0, watch_interval_hours: 168, fingerprint: 'old3' },
				],
			},
		});
		const tenantB = makeMockD1({
			rowsBySql: {
				[DUE_DOMAINS_SQL]: [
					{ domain: 'b1.com', last_scanned_at: 0, watch_interval_hours: 168, fingerprint: 'old4' },
					{ domain: 'b2.com', last_scanned_at: 0, watch_interval_hours: 168, fingerprint: 'old5' },
					{ domain: 'b3.com', last_scanned_at: 0, watch_interval_hours: 168, fingerprint: 'old6' },
				],
			},
		});
		const queue = makeMockQueue();
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			BV_SCANNER_QUEUE: queue,
			[TENANT_A_BINDING]: tenantA.db,
			[TENANT_B_BINDING]: tenantB.db,
		} as TenantScheduledEnv;

		await handleTenantWeeklyRescan(customEnv, makeCtx(), {
			now: () => 9_999_999_999_999,
			newCycleId: () => 'cycle-test',
			dnsQuery: makeDnsQuery({}),
		});

		expect(queue.sends).toHaveLength(6);
		const cycleInserts = registry.calls.filter((c) => callMatches(c.sql, INSERT_CYCLE_SQL));
		expect(cycleInserts).toHaveLength(2);
	});

	it('b. skips queue.send when stored fingerprint matches the freshly computed one', async () => {
		const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');
		const { computeFingerprint } = await import('../../src/tenants/dns-fingerprint');

		const dnsQuery = makeDnsQuery({});
		const fp = await computeFingerprint('skip.com', { dnsQuery });
		if (fp.kind !== 'ok') throw new Error('fixture: fingerprint must be ok');

		const registry = makeMockD1({
			rowsBySql: { [ACTIVE_TENANTS_SQL]: [{ id: TENANT_A, super_tenant_id: SUPER }] },
		});
		const tenant = makeMockD1({
			rowsBySql: {
				[DUE_DOMAINS_SQL]: [
					{
						domain: 'skip.com',
						// Recent scan so the stale-rescan bypass doesn't fire.
						last_scanned_at: 9_999_999_900_000,
						watch_interval_hours: 168,
						fingerprint: fp.fingerprint,
					},
				],
			},
		});
		const queue = makeMockQueue();
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			BV_SCANNER_QUEUE: queue,
			[TENANT_A_BINDING]: tenant.db,
		} as TenantScheduledEnv;

		await handleTenantWeeklyRescan(customEnv, makeCtx(), {
			now: () => 9_999_999_999_999,
			newCycleId: () => 'cycle-test',
			dnsQuery,
		});

		expect(queue.sends).toHaveLength(0);
		expect(registry.calls.filter((c) => callMatches(c.sql, INSERT_CYCLE_SQL))).toHaveLength(0);
		// Cache refresh always runs, even on a no-op skip.
		expect(tenant.calls.filter((c) => callMatches(c.sql, UPDATE_FINGERPRINT_SQL))).toHaveLength(1);
	});

	it('c. domain not yet due is filtered by SQL — no fingerprint computed, no enqueue', async () => {
		const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({
			rowsBySql: { [ACTIVE_TENANTS_SQL]: [{ id: TENANT_A, super_tenant_id: SUPER }] },
		});
		const tenant = makeMockD1({ rowsBySql: { [DUE_DOMAINS_SQL]: [] } });
		const queue = makeMockQueue();
		const dnsCalls: string[] = [];
		const dnsQuery: DnsQueryFn = async (d) => {
			dnsCalls.push(d);
			return { Status: 0, Answer: [] } as DohResponse;
		};
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			BV_SCANNER_QUEUE: queue,
			[TENANT_A_BINDING]: tenant.db,
		} as TenantScheduledEnv;

		await handleTenantWeeklyRescan(customEnv, makeCtx(), {
			now: () => 1,
			newCycleId: () => 'cycle-test',
			dnsQuery,
		});

		expect(dnsCalls).toHaveLength(0);
		expect(queue.sends).toHaveLength(0);
		expect(registry.calls.filter((c) => callMatches(c.sql, INSERT_CYCLE_SQL))).toHaveLength(0);
	});

	it('d. inactive sub-tenants are filtered by SQL (active=1 clause)', async () => {
		const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({ rowsBySql: { [ACTIVE_TENANTS_SQL]: [] } });
		const tenant = makeMockD1({
			rowsBySql: {
				[DUE_DOMAINS_SQL]: [
					{ domain: 'never.com', last_scanned_at: 0, watch_interval_hours: 168, fingerprint: null },
				],
			},
		});
		const queue = makeMockQueue();
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			BV_SCANNER_QUEUE: queue,
			[TENANT_A_BINDING]: tenant.db,
		} as TenantScheduledEnv;

		await handleTenantWeeklyRescan(customEnv, makeCtx(), {
			now: () => 9_999_999_999_999,
			newCycleId: () => 'cycle-test',
			dnsQuery: makeDnsQuery({}),
		});

		expect(tenant.calls).toHaveLength(0);
		expect(queue.sends).toHaveLength(0);
	});

	it('e. TENANT_REGISTRY_DB unbound → fail-soft, no throw, no queue sends', async () => {
		const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');
		const queue = makeMockQueue();
		const customEnv: TenantScheduledEnv = {
			...env,
			BV_SCANNER_QUEUE: queue,
		} as TenantScheduledEnv;

		await expect(
			handleTenantWeeklyRescan(customEnv, makeCtx(), { now: () => 1 }),
		).resolves.toBeUndefined();
		expect(queue.sends).toHaveLength(0);
	});

	it('f. one DNS-failed domain does not block sibling enqueues; cycle.expected_total counts errors', async () => {
		const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({
			rowsBySql: { [ACTIVE_TENANTS_SQL]: [{ id: TENANT_A, super_tenant_id: SUPER }] },
		});
		const tenant = makeMockD1({
			rowsBySql: {
				[DUE_DOMAINS_SQL]: [
					{ domain: 'good1.com', last_scanned_at: null, watch_interval_hours: 168, fingerprint: null },
					{ domain: 'broken.com', last_scanned_at: null, watch_interval_hours: 168, fingerprint: null },
					{ domain: 'good2.com', last_scanned_at: null, watch_interval_hours: 168, fingerprint: null },
				],
			},
		});
		const queue = makeMockQueue();
		const dnsQuery = makeDnsQuery({ throwForDomains: new Set(['broken.com']) });
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			BV_SCANNER_QUEUE: queue,
			[TENANT_A_BINDING]: tenant.db,
		} as TenantScheduledEnv;

		await handleTenantWeeklyRescan(customEnv, makeCtx(), {
			now: () => 9_999_999_999_999,
			newCycleId: () => 'cycle-test',
			dnsQuery,
		});

		expect(queue.sends).toHaveLength(2);
		const cycleInserts = registry.calls.filter((c) => callMatches(c.sql, INSERT_CYCLE_SQL));
		expect(cycleInserts).toHaveLength(1);
		// expected_total bind position 5 (zero-indexed 4) of INSERT_CYCLE_SQL.
		expect(cycleInserts[0].binds[4]).toBe(3);
		const errIncs = registry.calls.filter((c) => callMatches(c.sql, INCREMENT_ERRORED_SQL));
		expect(errIncs).toHaveLength(1);
		expect(errIncs[0].binds[0]).toBe(1);
	});

	it('g. BV_SCANNER_QUEUE unbound → fail-soft, no throw', async () => {
		const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({
			rowsBySql: { [ACTIVE_TENANTS_SQL]: [{ id: TENANT_A, super_tenant_id: SUPER }] },
		});
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
		} as TenantScheduledEnv;

		await expect(
			handleTenantWeeklyRescan(customEnv, makeCtx(), { now: () => 1 }),
		).resolves.toBeUndefined();
		// Active-tenants enumeration NOT run — handler returns before that step.
		expect(registry.calls.filter((c) => callMatches(c.sql, ACTIVE_TENANTS_SQL))).toHaveLength(0);
	});

	it('passes baseline_cycle_id from registry to the cycle insert when one exists', async () => {
		const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({
			rowsBySql: {
				[ACTIVE_TENANTS_SQL]: [{ id: TENANT_A, super_tenant_id: SUPER }],
				[FIND_BASELINE_CYCLE_SQL]: [{ id: 'baseline-cycle-7' }],
			},
		});
		const tenant = makeMockD1({
			rowsBySql: {
				[DUE_DOMAINS_SQL]: [
					{ domain: 'a.com', last_scanned_at: null, watch_interval_hours: 168, fingerprint: null },
				],
			},
		});
		const queue = makeMockQueue();
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			BV_SCANNER_QUEUE: queue,
			[TENANT_A_BINDING]: tenant.db,
		} as TenantScheduledEnv;

		await handleTenantWeeklyRescan(customEnv, makeCtx(), {
			now: () => 9_999_999_999_999,
			newCycleId: () => 'cycle-test',
			dnsQuery: makeDnsQuery({}),
		});

		const inserts = registry.calls.filter((c) => callMatches(c.sql, INSERT_CYCLE_SQL));
		expect(inserts).toHaveLength(1);
		// baseline_cycle_id is the 6th bind (zero-indexed 5).
		expect(inserts[0].binds[5]).toBe('baseline-cycle-7');
	});
});

// =========================================================================
// handleTenantCycleAlerts
// =========================================================================

/**
 * Build a tenant DB whose findings query distinguishes between current and
 * baseline cycle ids — required so `computeCycleDiff` actually has a delta.
 * The simple `makeMockD1` helper returns the same rows for any prepare of a
 * given SQL, which would always produce zero deltas.
 */
function makeFindingsTenantDb(rowsByCycleId: Record<string, unknown[]>): D1Database {
	return {
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
					if (sql.includes(FINDINGS_FOR_CYCLE_SQL)) {
						const cycleId = binds[0] as string;
						const rows = rowsByCycleId[cycleId] ?? [];
						return { results: rows as T[], success: true, meta: {} } as unknown as D1Result<T>;
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
		async batch() {
			return [];
		},
		async exec() {
			return { count: 0, duration: 0 } as unknown as D1ExecResult;
		},
		dump() {
			throw new Error('not implemented');
		},
		withSession() {
			throw new Error('not implemented');
		},
	} as unknown as D1Database;
}

describe('handleTenantCycleAlerts', () => {
	const baseCycle = {
		id: 'cycle-curr',
		super_tenant_id: SUPER,
		sub_tenant_id: TENANT_A,
		started_at: 1_000_000,
		expected_total: 5,
		completed_total: 5,
		errored_total: 0,
		baseline_cycle_id: 'cycle-base',
	};

	it('h. fires sendTenantAlert + stamps "sent" when cycle has new findings vs baseline', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({
			rowsBySql: { [PENDING_CYCLES_SQL]: [{ ...baseCycle }] },
		});
		const tenant = makeFindingsTenantDb({
			'cycle-curr': [{ domain: 'a.com', category: 'spf', severity: 'high', title: 'spf weak' }],
			'cycle-base': [],
		});
		const sendAlert = vi.fn(async () => ({ delivered: true, status: 200 }));
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			[TENANT_A_BINDING]: tenant,
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/abc',
		} as TenantScheduledEnv;

		await handleTenantCycleAlerts(customEnv, makeCtx(), {
			now: () => 2_000_000,
			sendAlert,
		});

		expect(sendAlert).toHaveBeenCalledTimes(1);
		const stamps = registry.calls.filter((c) => callMatches(c.sql, STAMP_ALERT_SQL));
		expect(stamps).toHaveLength(1);
		expect(stamps[0].binds[1]).toBe('sent');
	});

	it('i. zero deltas → marks "no_diff" and does NOT call sendTenantAlert', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({
			rowsBySql: { [PENDING_CYCLES_SQL]: [{ ...baseCycle }] },
		});
		const sameRow = { domain: 'x.com', category: 'spf', severity: 'low', title: 'same finding' };
		const tenant = makeFindingsTenantDb({
			'cycle-curr': [sameRow],
			'cycle-base': [sameRow],
		});
		const sendAlert = vi.fn(async () => ({ delivered: true, status: 200 }));
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			[TENANT_A_BINDING]: tenant,
		} as TenantScheduledEnv;

		await handleTenantCycleAlerts(customEnv, makeCtx(), {
			now: () => 2_000_000,
			sendAlert,
		});

		expect(sendAlert).not.toHaveBeenCalled();
		const stamps = registry.calls.filter((c) => callMatches(c.sql, STAMP_ALERT_SQL));
		expect(stamps).toHaveLength(1);
		expect(stamps[0].binds[1]).toBe('no_diff');
	});

	it('j. baseline_cycle_id null → marks "skipped_no_baseline", no sendAlert, no findings query', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({
			rowsBySql: { [PENDING_CYCLES_SQL]: [{ ...baseCycle, baseline_cycle_id: null }] },
		});
		const tenant = makeMockD1();
		const sendAlert = vi.fn(async () => ({ delivered: true, status: 200 }));
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			[TENANT_A_BINDING]: tenant.db,
		} as TenantScheduledEnv;

		await handleTenantCycleAlerts(customEnv, makeCtx(), {
			now: () => 2_000_000,
			sendAlert,
		});

		expect(sendAlert).not.toHaveBeenCalled();
		expect(tenant.calls.filter((c) => callMatches(c.sql, FINDINGS_FOR_CYCLE_SQL))).toHaveLength(0);
		const stamps = registry.calls.filter((c) => callMatches(c.sql, STAMP_ALERT_SQL));
		expect(stamps).toHaveLength(1);
		expect(stamps[0].binds[1]).toBe('skipped_no_baseline');
	});

	it('k. sendTenantAlert returns delivered:false → marks "webhook_failed" with alert_sent_at still stamped', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({
			rowsBySql: { [PENDING_CYCLES_SQL]: [{ ...baseCycle }] },
		});
		const tenant = makeFindingsTenantDb({
			'cycle-curr': [{ domain: 'a.com', category: 'dmarc', severity: 'high', title: 'dmarc weak' }],
			'cycle-base': [],
		});
		const sendAlert = vi.fn(async () => ({ delivered: false, status: 503 }));
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			[TENANT_A_BINDING]: tenant,
			ALERT_WEBHOOK_URL: 'https://hooks.example.com/abc',
		} as TenantScheduledEnv;

		await handleTenantCycleAlerts(customEnv, makeCtx(), {
			now: () => 2_000_000,
			sendAlert,
		});

		expect(sendAlert).toHaveBeenCalledTimes(1);
		const stamps = registry.calls.filter((c) => callMatches(c.sql, STAMP_ALERT_SQL));
		expect(stamps).toHaveLength(1);
		expect(stamps[0].binds[1]).toBe('webhook_failed');
		expect(stamps[0].binds[0]).toBe(2_000_000);
	});

	// l. The SQL-level filter (`completed_total + errored_total >= expected_total`)
	// is enforced inside the production query string, but the SQL-keyed mock
	// fake doesn't actually evaluate WHERE clauses — it returns whatever rows
	// we hand it for a given SQL key. Verifying that filter belongs at the D1
	// integration layer (or by inspection of PENDING_CYCLES_SQL itself), not
	// here. We assert the cleanly-defined "no pending rows" outcome instead.
	it('l. no pending cycles → no stamp, no sendAlert, fail-soft', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({ rowsBySql: { [PENDING_CYCLES_SQL]: [] } });
		const sendAlert = vi.fn(async () => ({ delivered: true, status: 200 }));
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
		} as TenantScheduledEnv;

		await handleTenantCycleAlerts(customEnv, makeCtx(), { now: () => 1, sendAlert });

		expect(sendAlert).not.toHaveBeenCalled();
		expect(registry.calls.filter((c) => callMatches(c.sql, STAMP_ALERT_SQL))).toHaveLength(0);
	});

	it('m. multiple pending cycles in one tick → each gets stamped exactly once', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const cycle1 = { ...baseCycle, id: 'cycle-1', baseline_cycle_id: null };
		const cycle2 = { ...baseCycle, id: 'cycle-2', baseline_cycle_id: null };
		const cycle3 = { ...baseCycle, id: 'cycle-3', baseline_cycle_id: null };
		const registry = makeMockD1({
			rowsBySql: { [PENDING_CYCLES_SQL]: [cycle1, cycle2, cycle3] },
		});
		const tenant = makeMockD1();
		const sendAlert = vi.fn(async () => ({ delivered: true, status: 200 }));
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			[TENANT_A_BINDING]: tenant.db,
		} as TenantScheduledEnv;

		await handleTenantCycleAlerts(customEnv, makeCtx(), {
			now: () => 2_000_000,
			sendAlert,
		});

		const stamps = registry.calls.filter((c) => callMatches(c.sql, STAMP_ALERT_SQL));
		expect(stamps).toHaveLength(3);
		const stampedIds = stamps.map((s) => s.binds[2] as string).sort();
		expect(stampedIds).toEqual(['cycle-1', 'cycle-2', 'cycle-3']);
	});

	it('n. registry D1 throws on PENDING_CYCLES_SQL → fail-soft, no stamp', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const registry = makeMockD1({ throwOnSql: new Set([PENDING_CYCLES_SQL]) });
		const sendAlert = vi.fn(async () => ({ delivered: true, status: 200 }));
		const customEnv: TenantScheduledEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
		} as TenantScheduledEnv;

		await expect(
			handleTenantCycleAlerts(customEnv, makeCtx(), { now: () => 1, sendAlert }),
		).resolves.toBeUndefined();
		expect(sendAlert).not.toHaveBeenCalled();
	});

	it('TENANT_REGISTRY_DB unbound → returns immediately', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const sendAlert = vi.fn(async () => ({ delivered: true, status: 200 }));
		const customEnv: TenantScheduledEnv = { ...env } as TenantScheduledEnv;

		await expect(
			handleTenantCycleAlerts(customEnv, makeCtx(), { now: () => 1, sendAlert }),
		).resolves.toBeUndefined();
		expect(sendAlert).not.toHaveBeenCalled();
	});
});
