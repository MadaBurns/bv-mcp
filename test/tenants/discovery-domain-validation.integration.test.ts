// SPDX-License-Identifier: BUSL-1.1

/**
 * FINDING #8 (P3): the `/internal/tenants/discover` route's `auto_import` path
 * upserts candidate domains and accepts `seed_domains` WITHOUT the route-level
 * `validateDomain` / `sanitizeDomain` (SSRF / blocklist) checks that `/portfolio`
 * and `/scan` apply. These tests assert:
 *   (a) an invalid / SSRF seed_domain is rejected at route entry
 *   (b) an invalid / SSRF candidate domain is never persisted by auto_import
 */

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import worker from '../../src';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';
import * as discovery from '../../src/tools/discover-brand-domains';

const TEST_INTERNAL_KEY = 'tenant-orchestrator-internal-key';
const TEST_TENANT_ID = 'tenant-1';
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';
const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, active FROM sub_tenants WHERE id = ? LIMIT 1';

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

function buildEnv() {
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
	} as TestEnv;
	return { customEnv, tenantCalls: tenant.calls };
}

function makeReq(body: unknown): Request {
	return new Request('https://api.blackveil.local/internal/tenants/discover', {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
			'X-Tenant': TEST_TENANT_ID,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(body),
	});
}

async function send(req: Request, customEnv: TestEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

describe('FINDING #8: /discover domain validation', () => {
	beforeEach(() => {
		resetTenantResolverCache();
		vi.restoreAllMocks();
	});

	it('rejects an SSRF / invalid seed_domain at route entry with 400', async () => {
		const { customEnv } = buildEnv();
		// 127.0.0.1 is an IP literal — validateDomain rejects IP addresses (SSRF guard).
		const res = await send(makeReq({ seed_domains: ['127.0.0.1'] }), customEnv);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/Invalid domain/);
	});

	it('does not persist an invalid / SSRF candidate domain via auto_import', async () => {
		const { customEnv, tenantCalls } = buildEnv();
		// discoverBrandDomains yields a high-confidence candidate that is an IP literal
		// (would be an SSRF target if blindly upserted).
		vi.spyOn(discovery, 'discoverBrandDomains').mockResolvedValue({
			findings: [{ metadata: { candidate: '169.254.169.254', combinedConfidence: 0.99, signals: ['san'] } }],
		} as unknown as Awaited<ReturnType<typeof discovery.discoverBrandDomains>>);

		const res = await send(makeReq({ seed_domains: ['example.com'], auto_import: true }), customEnv);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { imported: number };
		expect(body.imported).toBe(0);

		// The malicious candidate must never reach an INSERT INTO domains upsert.
		const upsertWithBad = tenantCalls.find(
			(c) => c.sql.includes('INSERT INTO domains') && c.binds[0] === '169.254.169.254',
		);
		expect(upsertWithBad).toBeUndefined();
	});

	it('drops an invalid / SSRF DB-read seed (watch=1) and only discovers valid ones', async () => {
		// FINDING #4: when seed_domains is omitted, seeds are read from the tenant DB
		// (SELECT domain FROM domains WHERE watch=1). Those DB-read seeds must clear
		// the same validateDomain/sanitizeDomain gate as the other two paths — an
		// invalid/SSRF seed is dropped (skipped), never handed to discoverBrandDomains.
		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
		});
		const tenant = makeMockD1({
			'SELECT domain FROM domains WHERE watch = 1 LIMIT 10': [{ domain: '169.254.169.254' }, { domain: 'good.com' }],
		});
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		} as TestEnv;

		const spy = vi
			.spyOn(discovery, 'discoverBrandDomains')
			.mockResolvedValue({ findings: [] } as unknown as Awaited<ReturnType<typeof discovery.discoverBrandDomains>>);

		// No seed_domains → DB-read path.
		const res = await send(makeReq({}), customEnv);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { seeds: number };
		// Only the valid seed survives the validation gate.
		expect(body.seeds).toBe(1);

		const calledDomains = spy.mock.calls.map((call) => call[0]);
		expect(calledDomains).toContain('good.com');
		expect(calledDomains).not.toContain('169.254.169.254');
	});

	it('still imports a valid high-confidence candidate (no regression)', async () => {
		const { customEnv, tenantCalls } = buildEnv();
		vi.spyOn(discovery, 'discoverBrandDomains').mockResolvedValue({
			findings: [{ metadata: { candidate: 'candidate.com', combinedConfidence: 0.95, signals: ['san'] } }],
		} as unknown as Awaited<ReturnType<typeof discovery.discoverBrandDomains>>);

		const res = await send(makeReq({ seed_domains: ['example.com'], auto_import: true }), customEnv);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { imported: number };
		expect(body.imported).toBe(1);
		const upsert = tenantCalls.find((c) => c.sql.includes('INSERT INTO domains') && c.binds[0] === 'candidate.com');
		expect(upsert).toBeDefined();
	});
});
