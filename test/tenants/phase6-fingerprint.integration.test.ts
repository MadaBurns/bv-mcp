// SPDX-License-Identifier: BUSL-1.1
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import worker from '../../src';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';
import * as dnsFingerprint from '../../src/tenants/dns-fingerprint';
import { handleToolsCall } from '../../src/handlers/tools';

vi.mock('../../src/handlers/tools');

const TEST_INTERNAL_KEY = 'tenant-orchestrator-internal-key';
const TEST_TENANT_ID = 'tenant-1';
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';

type TestEnv = typeof env & {
	BV_WEB_INTERNAL_KEY?: string;
	REQUIRE_INTERNAL_AUTH?: string;
	TENANT_REGISTRY_DB?: D1Database;
	[k: string]: unknown;
};

function makeMockD1(rowsBySql: Record<string, unknown[]> = {}) {
	const calls: Array<{ sql: string; binds: unknown[] }> = [];
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
					return { success: true, meta: {} } as unknown as D1Response;
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
	} as unknown as D1Database;
	return { db, calls };
}

const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';

describe('Phase 6 Fingerprint Pre-flight Integration', () => {
	beforeEach(() => {
		resetTenantResolverCache();
		vi.restoreAllMocks();
	});

	it('should skip full scan when fingerprint matches and last scan is recent', async () => {
		const e = env as TestEnv;
		e.BV_WEB_INTERNAL_KEY = TEST_INTERNAL_KEY;
		e.REQUIRE_INTERNAL_AUTH = 'true';

		const lastScanResult = { score: 95, findings: [] };
		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
		});
		const tenant = makeMockD1({
			['SELECT result_json, scan_at FROM scans WHERE domain = ? ORDER BY scan_at DESC LIMIT 1']: [
				{ result_json: JSON.stringify(lastScanResult), scan_at: Date.now() - 1000 }
			],
			['SELECT fingerprint FROM domains WHERE domain = ?']: [{ fingerprint: 'match' }]
		});

		e.TENANT_REGISTRY_DB = registry.db;
		e[TEST_TENANT_BINDING] = tenant.db;

		const fpSpy = vi.spyOn(dnsFingerprint, 'computeFingerprint').mockResolvedValue({
			kind: 'ok',
			domain: 'test.com',
			fingerprint: 'match',
			capturedAt: Date.now(),
			records: {}
		} as unknown as Awaited<ReturnType<typeof dnsFingerprint.computeFingerprint>>);

		const req = new Request('https://api.blackveil.local/internal/tenants/scan', {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ domains: ['test.com'] }),
		});

		const ctx = createExecutionContext();
		const res = await worker.fetch(req, e, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(200);
		const body = await res.json() as { completed: number };
		expect(body.completed).toBe(1);
		
		// Full scan should NOT be called
		expect(handleToolsCall).not.toHaveBeenCalled();
		expect(fpSpy).toHaveBeenCalled();
		
		// Persistence should be skipped (no INSERT INTO scans for this domain in this cycle)
		const persistenceCall = tenant.calls.find(c => c.sql.includes('INSERT INTO scans'));
		expect(persistenceCall).toBeUndefined();
	});

	it('should perform full scan when force_refresh is true', async () => {
		const e = env as TestEnv;
		e.BV_WEB_INTERNAL_KEY = TEST_INTERNAL_KEY;
		e.REQUIRE_INTERNAL_AUTH = 'true';

		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
		});
		const tenant = makeMockD1();

		e.TENANT_REGISTRY_DB = registry.db;
		e[TEST_TENANT_BINDING] = tenant.db;

		vi.mocked(handleToolsCall).mockResolvedValue({ isError: false, result: {} } as unknown as Awaited<ReturnType<typeof handleToolsCall>>);

		const req = new Request('https://api.blackveil.local/internal/tenants/scan', {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ domains: ['test.com'], force_refresh: true }),
		});

		const ctx = createExecutionContext();
		const res = await worker.fetch(req, e, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(200);
		expect(handleToolsCall).toHaveBeenCalled();
	});
});
