// SPDX-License-Identifier: BUSL-1.1

/**
 * Integration tests for the Phase 2 producer side of the scanner queue:
 *   POST /internal/tenants/scan with `mode: 'queue'` enqueues one message per
 *   validated target and returns 202 with `{ cycle_id, total, queued, started_at }`.
 *
 * Reuses the makeMockD1 + buildEnvWithTenant pattern from
 * `routes.integration.test.ts`. Only this surface area is asserted here —
 * the consumer side is covered by `queue-consumer.integration.test.ts`.
 *
 * One observable behaviour per test (TDD discipline).
 */

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import worker from '../../src';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';

const TEST_INTERNAL_KEY = 'tenant-orchestrator-internal-key';
const TEST_TENANT_ID = 'tenant-1';
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';
const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';

type TestEnv = typeof env & {
	BV_WEB_INTERNAL_KEY?: string;
	REQUIRE_INTERNAL_AUTH?: string;
	TENANT_REGISTRY_DB?: D1Database;
	BV_SCANNER_QUEUE?: { send: (msg: unknown, opts?: unknown) => Promise<void> };
	[k: string]: unknown;
};

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

function buildEnvWithQueue() {
	const registry = makeMockD1({
		[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
	});
	const tenant = makeMockD1();
	const queueSend = vi.fn(async () => {});
	const customEnv = {
		...env,
		BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
		REQUIRE_INTERNAL_AUTH: 'true',
		TENANT_REGISTRY_DB: registry.db,
		[TEST_TENANT_BINDING]: tenant.db,
		BV_SCANNER_QUEUE: { send: queueSend },
	} as TestEnv;
	return { customEnv, queueSend, tenantCalls: tenant.calls };
}

async function sendRequest(req: Request, customEnv: TestEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

function makeReq(body: unknown): Request {
	return new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/scan', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
			'X-Tenant': TEST_TENANT_ID,
		},
		body: JSON.stringify(body),
	});
}

beforeEach(() => {
	resetTenantResolverCache();
});
afterEach(() => {
	resetTenantResolverCache();
});

describe('POST /internal/tenants/scan (mode=queue producer)', () => {
	it('returns 202 with cycle_id, total, queued, started_at and no completed/errored fields', async () => {
		const { customEnv } = buildEnvWithQueue();
		const res = await sendRequest(makeReq({ mode: 'queue', domains: ['example.com', 'foo.com'] }), customEnv);
		expect(res.status).toBe(202);
		const body = (await res.json()) as Record<string, unknown>;
		expect(typeof body.cycle_id).toBe('string');
		expect(body.total).toBe(2);
		expect(body.queued).toBe(2);
		expect(typeof body.started_at).toBe('number');
		expect(body).not.toHaveProperty('completed');
		expect(body).not.toHaveProperty('errored');
		expect(body).not.toHaveProperty('finished_at');
	});

	it('produces one queue message per validated target domain', async () => {
		const { customEnv, queueSend } = buildEnvWithQueue();
		const res = await sendRequest(
			makeReq({ mode: 'queue', domains: ['example.com', 'foo.com', 'bar.com'] }),
			customEnv,
		);
		expect(res.status).toBe(202);
		expect(queueSend).toHaveBeenCalledTimes(3);
		for (const call of queueSend.mock.calls) {
			const msg = call[0] as { cycle_id: string; sub_tenant_id: string; domain: string };
			expect(typeof msg.cycle_id).toBe('string');
			expect(msg.sub_tenant_id).toBe(TEST_TENANT_ID);
			expect(typeof msg.domain).toBe('string');
		}
	});

	it('returns 400 with no messages sent when domain_ids resolve to an empty enrolled set', async () => {
		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'x', active: 1 }],
		});
		const tenant = makeMockD1({
			'SELECT domain FROM domains WHERE domain IN (?)': [],
		});
		const queueSend = vi.fn(async () => {});
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
			BV_SCANNER_QUEUE: { send: queueSend },
		} as TestEnv;
		const res = await sendRequest(
			makeReq({ mode: 'queue', domain_ids: ['attacker-domain.com'] }),
			customEnv,
		);
		expect(res.status).toBe(400);
		expect(queueSend).not.toHaveBeenCalled();
	});

	it('default mode (unspecified) hits the sync path and returns completed/errored fields', async () => {
		const { mockTxtRecords } = await import('../helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const { customEnv, queueSend } = buildEnvWithQueue();
		const res = await sendRequest(makeReq({ domains: ['example.com'] }), customEnv);
		expect(res.status).toBe(200);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body).toHaveProperty('completed');
		expect(body).toHaveProperty('errored');
		expect(body).toHaveProperty('finished_at');
		expect(body).not.toHaveProperty('queued');
		expect(queueSend).not.toHaveBeenCalled();
	});

	it('default mode auto-queues large domain sets instead of running synchronously', async () => {
		const { customEnv, queueSend } = buildEnvWithQueue();
		const domains = Array.from({ length: 51 }, (_, i) => `tenant-${i}.example.com`);
		const res = await sendRequest(makeReq({ domains }), customEnv);
		expect(res.status).toBe(202);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.total).toBe(51);
		expect(body.queued).toBe(51);
		expect(body).not.toHaveProperty('completed');
		expect(queueSend).toHaveBeenCalledTimes(51);
	});

	it('returns 400 when mode=queue but BV_SCANNER_QUEUE binding is absent', async () => {
		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'x', active: 1 }],
		});
		const tenant = makeMockD1();
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		} as TestEnv;
		const res = await sendRequest(makeReq({ mode: 'queue', domains: ['example.com'] }), customEnv);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/Invalid mode/);
	});
});
