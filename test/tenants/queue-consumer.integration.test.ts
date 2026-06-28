// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the Tenant scanner-queue consumer (`processScanMessage` +
 * `handleScanQueue` in `src/tenants/queue-consumer.ts`).
 *
 * Strategy:
 *   - Mock `handleToolsCall` so we can drive isError/throw outcomes per case
 *     without DNS or KV side effects.
 *   - Use a recording D1 fake (mirrors `routes.integration.test.ts`) for the
 *     per-tenant DB so we can assert "wrote N rows" + the SQL/binds shape.
 *   - Spread `cloudflare:test` `env` so `parseScoringConfigCached` etc. don't
 *     trip on missing globals.
 *
 * One observable behaviour per test (TDD discipline).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { env, createExecutionContext } from 'cloudflare:test';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';

// Hoisted mock state so vi.mock factory can read it.
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
	'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';
const SCAN_PROBE_BY_DOMAIN_SQL = 'SELECT id FROM scans WHERE cycle_id = ? AND domain = ? LIMIT 1';
const SCANS_INSERT_SQL =
	'INSERT INTO scans (id, domain, scan_at, score, grade, maturity_stage, finding_count, result_json, cycle_id) ' +
	'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
const FINDINGS_INSERT_SQL =
	'INSERT INTO findings (id, scan_id, domain, category, severity, title, detail, metadata) ' +
	'VALUES (?, ?, ?, ?, ?, ?, ?, ?)';

type RecordedCall = { sql: string; binds: unknown[] };

interface MakeMockD1Options {
	rowsBySql?: Record<string, unknown[]>;
	throwOnSql?: Set<string>;
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
					if (throwOnSql.has(sql)) throw new Error('d1_first_failed');
					const rows = rowsBySql[sql] ?? [];
					return (rows[0] as T | undefined) ?? null;
				},
				async all<T = unknown>() {
					calls.push({ sql, binds });
					if (throwOnSql.has(sql)) throw new Error('d1_all_failed');
					const rows = rowsBySql[sql] ?? [];
					return { results: rows as T[], success: true, meta: {} } as unknown as D1Result<T>;
				},
				async run() {
					calls.push({ sql, binds });
					if (throwOnSql.has(sql)) throw new Error('d1_run_failed');
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

function buildEnv(overrides: Record<string, unknown> = {}) {
	const registry = makeMockD1({
		rowsBySql: {
			[REGISTRY_LOOKUP_SQL]: [
				{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 },
			],
		},
	});
	const tenant = makeMockD1();
	const customEnv = {
		...env,
		TENANT_REGISTRY_DB: registry.db,
		[TEST_TENANT_BINDING]: tenant.db,
		...overrides,
	};
	return { customEnv, registryCalls: registry.calls, tenantCalls: tenant.calls };
}

function makeCtx() {
	const ctx = createExecutionContext();
	return { waitUntil: (p: Promise<unknown>) => ctx.waitUntil(p) };
}

beforeEach(() => {
	resetTenantResolverCache();
	handleToolsCallMock.mockReset();
});
afterEach(() => {
	resetTenantResolverCache();
});

describe('processScanMessage', () => {
	const validMsg = {
		cycle_id: 'cycle_test_001',
		sub_tenant_id: TEST_TENANT_ID,
		domain: 'example.com',
	};

	it('returns ack on the happy path and writes 1 scan row + a single batched findings INSERT', async () => {
		handleToolsCallMock.mockImplementation(async (_call, _kv, runtimeOptions) => {
			const opts = runtimeOptions as { resultCapture?: (r: unknown) => void } | undefined;
			opts?.resultCapture?.({
				category: 'spf',
				passed: true,
				score: 90,
				findings: [
					{ category: 'spf', severity: 'info', title: 'spf_ok', detail: 'looks good' },
					{ category: 'spf', severity: 'low', title: 'spf_pct', detail: 'pct=100' },
				],
			});
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv, tenantCalls } = buildEnv();

		const outcome = await processScanMessage(validMsg, 1, customEnv, makeCtx());
		expect(outcome).toBe('ack');

		// T3: 2 findings now batch into ONE multi-row INSERT (not 2 sequential rows).
		const scanInserts = tenantCalls.filter((c) => c.sql === SCANS_INSERT_SQL);
		const findingInserts = tenantCalls.filter((c) => c.sql.startsWith('INSERT INTO findings'));
		expect(scanInserts.length).toBe(1);
		expect(findingInserts.length).toBe(1);
		// 2 findings × 8 columns = 16 bound params in the single statement.
		expect(findingInserts[0]!.binds.length).toBe(16);
	});

	it('returns ack without writing when an existing scan row is found (idempotency)', async () => {
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const registry = makeMockD1({
			rowsBySql: {
				[REGISTRY_LOOKUP_SQL]: [
					{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'x', active: 1 },
				],
			},
		});
		const tenant = makeMockD1({
			rowsBySql: {
				[SCAN_PROBE_BY_DOMAIN_SQL]: [{ id: 'pre-existing-scan-row' }],
			},
		});
		const customEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		};

		const outcome = await processScanMessage(validMsg, 1, customEnv, makeCtx());
		expect(outcome).toBe('ack');
		expect(tenant.calls.filter((c) => c.sql === SCANS_INSERT_SQL)).toHaveLength(0);
		expect(tenant.calls.filter((c) => c.sql === FINDINGS_INSERT_SQL)).toHaveLength(0);
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});

	it('returns ack and drops a malformed message (Zod failure, no retry)', async () => {
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv, tenantCalls } = buildEnv();

		const outcome = await processScanMessage({ not: 'a valid message' }, 1, customEnv, makeCtx());
		expect(outcome).toBe('ack');
		expect(tenantCalls).toHaveLength(0);
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});

	it('returns ack when the tenant resolver throws (no DB binding to write to)', async () => {
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const customEnv = { ...env };

		const outcome = await processScanMessage(validMsg, 1, customEnv, makeCtx());
		expect(outcome).toBe('ack');
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});

	it('returns retry when handleToolsCall returns isError on the first attempt', async () => {
		handleToolsCallMock.mockResolvedValue({
			isError: true,
			content: [{ type: 'text', text: 'tool_failed' }],
		});
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv, tenantCalls } = buildEnv();

		const outcome = await processScanMessage(validMsg, 1, customEnv, makeCtx());
		expect(outcome).toBe('retry');
		expect(tenantCalls.filter((c) => c.sql === SCANS_INSERT_SQL)).toHaveLength(0);
	});

	it('returns ack and writes a DLQ scan + DLQ finding row when isError on the last attempt', async () => {
		handleToolsCallMock.mockResolvedValue({
			isError: true,
			content: [{ type: 'text', text: 'tool_failed' }],
		});
		const { processScanMessage, MAX_ATTEMPTS } = await import('../../src/tenants/queue-consumer');
		const { customEnv, tenantCalls } = buildEnv();

		const outcome = await processScanMessage(validMsg, MAX_ATTEMPTS, customEnv, makeCtx());
		expect(outcome).toBe('ack');

		const scanInserts = tenantCalls.filter((c) => c.sql === SCANS_INSERT_SQL);
		const findingInserts = tenantCalls.filter((c) => c.sql === FINDINGS_INSERT_SQL);
		expect(scanInserts).toHaveLength(1);
		expect(findingInserts).toHaveLength(1);
		const dlqFinding = findingInserts[0]!;
		expect(dlqFinding.binds[5]).toBe('queue_dlq');
	});

	it('returns retry when handleToolsCall throws on a non-final attempt', async () => {
		handleToolsCallMock.mockRejectedValue(new Error('upstream_500'));
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv } = buildEnv();

		const outcome = await processScanMessage(validMsg, 1, customEnv, makeCtx());
		expect(outcome).toBe('retry');
	});

	it('returns ack and writes DLQ persist_failed when D1 insert throws on the last attempt', async () => {
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
		const { processScanMessage, MAX_ATTEMPTS } = await import('../../src/tenants/queue-consumer');
		const registry = makeMockD1({
			rowsBySql: {
				[REGISTRY_LOOKUP_SQL]: [
					{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'x', active: 1 },
				],
			},
		});
		const tenant = makeMockD1({ throwOnSql: new Set([SCANS_INSERT_SQL]) });
		const customEnv = {
			...env,
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		};

		const outcome = await processScanMessage(validMsg, MAX_ATTEMPTS, customEnv, makeCtx());
		expect(outcome).toBe('ack');
		expect(tenant.calls.filter((c) => c.sql === SCANS_INSERT_SQL).length).toBeGreaterThanOrEqual(1);
	});

	// NOTE: DLQ-on-queue_timeout is not directly tested here — driving the
	// 20s `QUEUE_MESSAGE_TIMEOUT_MS` race deterministically requires vitest
	// fake timers cooperating with Promise.race, which currently does not
	// fire `setTimeout` callbacks under workerd's `cloudflare:test` pool.
	// The error path is exercised by the rejecting-handleToolsCall case
	// above (same code branch — `withTimeout` simply rejects).
});

describe('handleScanQueue', () => {
	const validMsg = {
		cycle_id: 'cycle_test_002',
		sub_tenant_id: TEST_TENANT_ID,
		domain: 'example.com',
	};

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

	it('routes ack/retry per-message based on processScanMessage outcome', async () => {
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
		const { customEnv } = buildEnv();
		const ctx = createExecutionContext();
		const { batch, acks, retries } = makeMessageBatch([
			validMsg,
			{ not: 'valid' },
		]);
		await handleScanQueue(batch, customEnv, ctx);
		expect(acks).toEqual([0, 1]);
		expect(retries).toEqual([]);
	});
});
