// SPDX-License-Identifier: BUSL-1.1
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import worker from '../../src';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';
import * as discovery from '../../src/tools/discover-brand-domains';

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

describe('Tenant Discovery Route Integration', () => {
	beforeEach(() => {
		resetTenantResolverCache();
		vi.restoreAllMocks();
	});

	it('should return 400 for invalid request body', async () => {
		const e = env as TestEnv;
		e.BV_WEB_INTERNAL_KEY = TEST_INTERNAL_KEY;
		e.REQUIRE_INTERNAL_AUTH = 'true';

		const req = new Request('https://api.blackveil.local/internal/tenants/discover', {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ signals: ['invalid-signal'] }),
		});

		const ctx = createExecutionContext();
		const res = await worker.fetch(req, e, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(400);
		const body = await res.json() as { error: string };
		expect(body.error).toContain('Invalid signals');
	});

	it('should successfully run discovery and return candidates', async () => {
		const e = env as TestEnv;
		e.BV_WEB_INTERNAL_KEY = TEST_INTERNAL_KEY;
		e.REQUIRE_INTERNAL_AUTH = 'true';

		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
		});
		const tenant = makeMockD1({
			['SELECT domain FROM domains WHERE watch = 1 LIMIT 10']: [{ domain: 'seed.com' }],
		});

		e.TENANT_REGISTRY_DB = registry.db;
		e[TEST_TENANT_BINDING] = tenant.db;

		// Mock the discovery tool to avoid real DNS/network calls
		const mockResult = {
			findings: [
				{ metadata: { candidate: 'candidate.com', combinedConfidence: 0.9, signals: ['san'] } },
				{ metadata: { summary: true } }
			]
		};
		const discoverSpy = vi.spyOn(discovery, 'discoverBrandDomains').mockResolvedValue(mockResult as unknown as Awaited<ReturnType<typeof discovery.discoverBrandDomains>>);

		const req = new Request('https://api.blackveil.local/internal/tenants/discover', {
			method: 'POST',
			headers: {
				'Authorization': `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ seed_domains: ['seed.com'], auto_import: true }),
		});

		const ctx = createExecutionContext();
		const res = await worker.fetch(req, e, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(200);
		const body = await res.json() as { seeds: number; candidates: Array<{ domain: string }>; imported: number };
		expect(body.seeds).toBe(1);
		expect(body.candidates).toHaveLength(1);
		expect(body.candidates[0].domain).toBe('candidate.com');
		expect(body.imported).toBe(1);

		expect(discoverSpy).toHaveBeenCalledWith('seed.com', expect.anything());
		
		// Verify auto-import call
		const upsertCall = tenant.calls.find(c => c.sql.includes('INSERT INTO domains'));
		expect(upsertCall).toBeDefined();
		expect(upsertCall.binds[0]).toBe('candidate.com');
		expect(upsertCall.binds[1]).toBe('discovery');
	});
});
