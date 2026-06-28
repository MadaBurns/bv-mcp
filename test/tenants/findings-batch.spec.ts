// SPDX-License-Identifier: BUSL-1.1

/**
 * T3 (per-finding write amplification) regression tests.
 *
 * Both the queue consumer (`processScanMessage` in `queue-consumer.ts`) and the
 * sync orchestrator route (`POST /internal/tenants/scan` in `routes.ts`) used to
 * persist findings with one D1 `.run()` per finding. On the dispatch/rest
 * `TenantDbHandle` backends each `.run()` is a separate HTTP round-trip, so an
 * N-finding scan issued ~N+1 calls and blew the per-invocation budget. The fix
 * batches findings into chunked multi-row INSERTs, bounded to
 * `ceil(N / 12)` statements with ≤ 100 bound params each (D1/workerd's cap).
 *
 * These tests assert the STATEMENT count is bounded (not N) and that each
 * statement respects the 100-param cap. `handleToolsCall` is mocked so we can
 * drive an exact finding count without DNS.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';

const handleToolsCallMock = vi.hoisted(() =>
	vi.fn<(...args: unknown[]) => Promise<{ isError?: boolean; content: unknown[] }>>(),
);

vi.mock('../../src/handlers/tools', () => ({
	handleToolsCall: handleToolsCallMock,
}));

const TEST_TENANT_ID = 'tenant-1';
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';
const TEST_INTERNAL_KEY = 'tenant-orchestrator-internal-key';
const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';
const SCANS_INSERT_SQL =
	'INSERT INTO scans (id, domain, scan_at, score, grade, maturity_stage, finding_count, result_json, cycle_id) ' +
	'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';

/** findings table column count — the chunk size that keeps params ≤ 100 is floor(100/8) = 12. */
const FINDINGS_COLUMNS = 8;
const FINDINGS_CHUNK = Math.floor(100 / FINDINGS_COLUMNS); // 12

type RecordedCall = { sql: string; binds: unknown[] };

function makeMockD1(rowsBySql: Record<string, unknown[]> = {}) {
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

function makeFindings(n: number) {
	return Array.from({ length: n }, (_, i) => ({
		category: 'spf',
		severity: 'low',
		title: `finding_${i}`,
		detail: `detail_${i}`,
		metadata: { idx: i },
	}));
}

/** Assert a set of finding-INSERT calls is bounded + within the param cap. */
function assertBoundedFindingInserts(findingInserts: RecordedCall[], n: number) {
	// Bounded: ceil(N / 12) statements, NOT N.
	expect(findingInserts.length).toBe(Math.ceil(n / FINDINGS_CHUNK));
	let totalRows = 0;
	for (const call of findingInserts) {
		// Every statement is a multi-row INSERT INTO findings ... VALUES (...),(...)
		expect(call.sql.startsWith('INSERT INTO findings')).toBe(true);
		// 100-bound-param cap respected.
		expect(call.binds.length).toBeLessThanOrEqual(100);
		// Each row contributes exactly 8 params.
		expect(call.binds.length % FINDINGS_COLUMNS).toBe(0);
		totalRows += call.binds.length / FINDINGS_COLUMNS;
	}
	// No findings dropped across the chunk boundary.
	expect(totalRows).toBe(n);
}

beforeEach(() => {
	resetTenantResolverCache();
	handleToolsCallMock.mockReset();
});
afterEach(() => {
	resetTenantResolverCache();
});

describe('queue-consumer persistScan — findings batching (T3)', () => {
	function buildEnv() {
		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'x', active: 1 }],
		});
		const tenant = makeMockD1();
		const customEnv = { ...env, TENANT_REGISTRY_DB: registry.db, [TEST_TENANT_BINDING]: tenant.db };
		return { customEnv, tenantCalls: tenant.calls };
	}

	it('persists 25 findings in 3 bounded multi-row INSERTs (not 25), each ≤ 100 params', async () => {
		const n = 25;
		handleToolsCallMock.mockImplementation(async (_call, _kv, runtimeOptions) => {
			const opts = runtimeOptions as { resultCapture?: (r: unknown) => void } | undefined;
			opts?.resultCapture?.({ category: 'spf', passed: true, score: 80, findings: makeFindings(n) });
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv, tenantCalls } = buildEnv();

		const outcome = await processScanMessage(
			{ cycle_id: 'cycle_t3_q', sub_tenant_id: TEST_TENANT_ID, domain: 'example.com' },
			1,
			customEnv,
			{ waitUntil: (p: Promise<unknown>) => createExecutionContext().waitUntil(p) },
		);
		expect(outcome).toBe('ack');

		expect(tenantCalls.filter((c) => c.sql === SCANS_INSERT_SQL).length).toBe(1);
		assertBoundedFindingInserts(
			tenantCalls.filter((c) => c.sql.startsWith('INSERT INTO findings')),
			n,
		);
	});

	it('persists exactly 12 findings in a single statement (chunk boundary)', async () => {
		const n = 12;
		handleToolsCallMock.mockImplementation(async (_call, _kv, runtimeOptions) => {
			const opts = runtimeOptions as { resultCapture?: (r: unknown) => void } | undefined;
			opts?.resultCapture?.({ category: 'spf', passed: true, score: 80, findings: makeFindings(n) });
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv, tenantCalls } = buildEnv();

		await processScanMessage({ cycle_id: 'cycle_t3_q12', sub_tenant_id: TEST_TENANT_ID, domain: 'example.com' }, 1, customEnv, {
			waitUntil: (p: Promise<unknown>) => createExecutionContext().waitUntil(p),
		});

		const findingInserts = tenantCalls.filter((c) => c.sql.startsWith('INSERT INTO findings'));
		expect(findingInserts.length).toBe(1);
		expect(findingInserts[0]!.binds.length).toBe(96); // 12 × 8, the max under the 100 cap
	});

	it('writes no findings INSERT when the scan has zero findings', async () => {
		handleToolsCallMock.mockImplementation(async (_call, _kv, runtimeOptions) => {
			const opts = runtimeOptions as { resultCapture?: (r: unknown) => void } | undefined;
			opts?.resultCapture?.({ category: 'spf', passed: true, score: 100, findings: [] });
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv, tenantCalls } = buildEnv();

		await processScanMessage({ cycle_id: 'cycle_t3_q0', sub_tenant_id: TEST_TENANT_ID, domain: 'example.com' }, 1, customEnv, {
			waitUntil: (p: Promise<unknown>) => createExecutionContext().waitUntil(p),
		});

		expect(tenantCalls.filter((c) => c.sql.startsWith('INSERT INTO findings')).length).toBe(0);
	});
});

describe('routes POST /internal/tenants/scan — findings batching (T3)', () => {
	function buildEnvWithTenant() {
		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
		});
		const tenant = makeMockD1();
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		} as typeof env & Record<string, unknown>;
		return { customEnv, tenantCalls: tenant.calls };
	}

	it('persists 25 findings in 3 bounded multi-row INSERTs via the sync scan path', async () => {
		const n = 25;
		handleToolsCallMock.mockImplementation(async (_call, _kv, runtimeOptions) => {
			const opts = runtimeOptions as { resultCapture?: (r: unknown) => void } | undefined;
			opts?.resultCapture?.({ category: 'spf', passed: true, score: 80, findings: makeFindings(n) });
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
		const worker = (await import('../../src')).default;
		const { customEnv, tenantCalls } = buildEnvWithTenant();

		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/scan', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
			},
			body: JSON.stringify({ domains: ['example.com'] }),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, customEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(200);

		expect(tenantCalls.filter((c) => c.sql === SCANS_INSERT_SQL).length).toBe(1);
		assertBoundedFindingInserts(
			tenantCalls.filter((c) => c.sql.startsWith('INSERT INTO findings')),
			n,
		);
	});
});
