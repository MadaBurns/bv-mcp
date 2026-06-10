// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos tests for the Tenant scanner queue consumer.
 *
 * Hypotheses:
 *   - Given a `processScanMessage` that throws unexpectedly mid-batch, the
 *     handleScanQueue wrapper still acks/retries the surrounding messages
 *     correctly (the catch in `handleScanQueue` forces 'retry' on throw).
 *   - Given a tenant D1 that fails on a specific INSERT, idempotency on the
 *     next delivery prevents duplicate scan rows.
 *   - Given a tenant resolver that throws (registry D1 down), the consumer
 *     acks (no DB to write to) without crashing the rest of the batch.
 *
 * Each case asserts a fail-soft invariant — "no crash propagates" /
 * "queue still drains" — rather than precise output.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { env, createExecutionContext } from 'cloudflare:test';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';

const handleToolsCallMock = vi.hoisted(() =>
	vi.fn<
		(...args: unknown[]) => Promise<{ isError?: boolean; content: unknown[] }>
	>(),
);

vi.mock('../../src/handlers/tools', () => ({
	handleToolsCall: handleToolsCallMock,
}));

const TEST_TENANT_ID = 'tenant-1';
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';
const REGISTRY_LOOKUP_SQL =
	'SELECT id, super_tenant_id, d1_db_id, active FROM sub_tenants WHERE id = ? LIMIT 1';
// Cheap single-column active-flag probe run by resolveTenant on a cache HIT (3.17.2,
// FINDING #2). Per-message queue resolution warm-hits this, so the mock must model it
// or cache-hit resolutions see no row and treat the tenant as deactivated.
const ACTIVE_PROBE_SQL = 'SELECT active FROM sub_tenants WHERE id = ? LIMIT 1';
const SCAN_PROBE_BY_DOMAIN_SQL = 'SELECT id FROM scans WHERE cycle_id = ? AND domain = ? LIMIT 1';
const SCANS_INSERT_SQL =
	'INSERT INTO scans (id, domain, scan_at, score, grade, maturity_stage, finding_count, result_json, cycle_id) ' +
	'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';

type RecordedCall = { sql: string; binds: unknown[] };

interface MakeMockD1Options {
	rowsBySql?: Record<string, unknown[]>;
	throwOnSql?: Set<string>;
	failNthRunForSql?: { sql: string; n: number };
}

function makeMockD1(opts: MakeMockD1Options = {}) {
	const rowsBySql = opts.rowsBySql ?? {};
	const throwOnSql = opts.throwOnSql ?? new Set<string>();
	const failNth = opts.failNthRunForSql;
	const calls: RecordedCall[] = [];
	const runCountBySql: Record<string, number> = {};
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
					if (throwOnSql.has(sql)) throw new Error('d1_first_failed');
					const rows = rowsBySql[sql] ?? [];
					return (rows[0] as T | undefined) ?? null;
				},
				async all<T = unknown>() {
					calls.push({ sql, binds });
					const rows = rowsBySql[sql] ?? [];
					return { results: rows as T[], success: true, meta: {} } as unknown as D1Result<T>;
				},
				async run() {
					calls.push({ sql, binds });
					runCountBySql[sql] = (runCountBySql[sql] ?? 0) + 1;
					if (throwOnSql.has(sql)) throw new Error('d1_run_failed');
					if (failNth && failNth.sql === sql && runCountBySql[sql] === failNth.n) {
						throw new Error('d1_run_failed_intermittent');
					}
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

function makeMessageBatch(bodies: unknown[]) {
	const acks: number[] = [];
	const retries: number[] = [];
	const messages = bodies.map((body, i) => ({
		id: `msg-${i}`,
		body,
		attempts: 1,
		timestamp: new Date(),
		ack: () => acks.push(i),
		retry: () => retries.push(i),
	}));
	const batch = {
		queue: 'BV_SCANNER_QUEUE',
		messages,
		ackAll: () => {
			for (let i = 0; i < messages.length; i++) acks.push(i);
		},
		retryAll: () => {
			for (let i = 0; i < messages.length; i++) retries.push(i);
		},
	} as unknown as MessageBatch<unknown>;
	return { batch, acks, retries };
}

beforeEach(() => {
	resetTenantResolverCache();
	handleToolsCallMock.mockReset();
});
afterEach(() => {
	resetTenantResolverCache();
});

describe('Tenant queue consumer chaos: handleScanQueue wrapper resilience', () => {
	it('retries only the failing message when handleToolsCall throws mid-batch', async () => {
		let callCount = 0;
		handleToolsCallMock.mockImplementation(async (_call, _kv, runtimeOptions) => {
			callCount += 1;
			if (callCount === 2) {
				throw new Error('synthetic_failure_on_msg_2');
			}
			const opts = runtimeOptions as { resultCapture?: (r: unknown) => void } | undefined;
			opts?.resultCapture?.({
				category: 'spf',
				passed: true,
				score: 90,
				findings: [],
			});
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});

		const { handleScanQueue } = await import('../../src/tenants/queue-consumer');
		const registry = makeMockD1({
			rowsBySql: {
				[REGISTRY_LOOKUP_SQL]: [
					{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'x', active: 1 },
				],
				// Cache-hit active-flag re-probe (3.17.2) — same tenant stays active.
				[ACTIVE_PROBE_SQL]: [{ active: 1 }],
			},
		});
		const tenant = makeMockD1();
		const customEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		};
		const ctx = createExecutionContext();

		const validBody = (suffix: string) => ({
			cycle_id: `cycle_chaos_${suffix}`,
			sub_tenant_id: TEST_TENANT_ID,
			domain: `${suffix}.example.com`,
		});
		const { batch, acks, retries } = makeMessageBatch([
			validBody('a'),
			validBody('b'),
			validBody('c'),
		]);

		await handleScanQueue(batch, customEnv, ctx);

		// Messages 0 + 2 succeed; message 1's handleToolsCall throw is caught by
		// processScanMessage, which returns 'retry' on attempt 1.
		expect(acks).toEqual([0, 2]);
		expect(retries).toEqual([1]);
	});

	it('retries the message with a transient D1 insert failure; idempotency probe runs on every delivery', async () => {
		handleToolsCallMock.mockImplementation(async (_call, _kv, runtimeOptions) => {
			const opts = runtimeOptions as { resultCapture?: (r: unknown) => void } | undefined;
			opts?.resultCapture?.({
				category: 'spf',
				passed: true,
				score: 90,
				findings: [],
			});
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const { handleScanQueue } = await import('../../src/tenants/queue-consumer');

		const registry = makeMockD1({
			rowsBySql: {
				[REGISTRY_LOOKUP_SQL]: [
					{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'x', active: 1 },
				],
				// Cache-hit active-flag re-probe (3.17.2) — same tenant stays active.
				[ACTIVE_PROBE_SQL]: [{ active: 1 }],
			},
		});
		// Fail on the 2nd SCANS_INSERT call (the 2nd message's persistScan).
		const tenant = makeMockD1({ failNthRunForSql: { sql: SCANS_INSERT_SQL, n: 2 } });
		const customEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		};
		const ctx = createExecutionContext();

		const validBody = (suffix: string) => ({
			cycle_id: `cycle_chaos_d1_${suffix}`,
			sub_tenant_id: TEST_TENANT_ID,
			domain: `${suffix}.example.com`,
		});
		const { batch, acks, retries } = makeMessageBatch([
			validBody('a'),
			validBody('b'),
			validBody('c'),
		]);

		await handleScanQueue(batch, customEnv, ctx);

		expect(acks).toEqual([0, 2]);
		expect(retries).toEqual([1]);

		// The idempotency probe ran for all 3 — guarantees re-delivery sees the
		// existing row and short-circuits without duplicate inserts.
		const probeCalls = tenant.calls.filter((c) => c.sql === SCAN_PROBE_BY_DOMAIN_SQL);
		expect(probeCalls.length).toBe(3);
	});

	it('acks the message and never crashes when the tenant resolver D1 throws', async () => {
		const { handleScanQueue } = await import('../../src/tenants/queue-consumer');
		const brokenRegistry = makeMockD1({ throwOnSql: new Set([REGISTRY_LOOKUP_SQL]) });
		const customEnv = {
			...env,
			TENANT_REGISTRY_DB: brokenRegistry.db,
		};
		const ctx = createExecutionContext();

		const validBody = {
			cycle_id: 'cycle_chaos_resolver',
			sub_tenant_id: TEST_TENANT_ID,
			domain: 'example.com',
		};
		const { batch, acks, retries } = makeMessageBatch([validBody]);

		await expect(handleScanQueue(batch, customEnv, ctx)).resolves.toBeUndefined();
		expect(acks).toEqual([0]);
		expect(retries).toEqual([]);
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});
});
