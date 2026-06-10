// SPDX-License-Identifier: BUSL-1.1

/**
 * FINDING #5 (P2, BOLA): a single shared BV_WEB_INTERNAL_KEY authenticates all
 * /internal/tenants/* calls, and the X-Tenant header alone selects the tenant —
 * nothing binds the caller's credential to an authorized tenant scope.
 *
 * The fix is ADDITIVE / OPT-IN so the live single-key bv-web flow is unchanged:
 *   - When NO scoping signal is configured, behaviour is exactly as before.
 *   - When a scoping signal IS present (TENANT_KEY_SCOPE env map keyed by
 *     sha256(bearer), OR an X-Tenant-Scope header), the resolved tenant MUST be
 *     within the caller's allowed scope or the route returns 403.
 *
 * These tests assert all three contracts (a) cross-tenant 403, (b) in-scope 200,
 * (c) no-scope-configured = no regression.
 */

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import worker from '../../src';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';

const TEST_INTERNAL_KEY = 'tenant-orchestrator-internal-key';
// sha256(TEST_INTERNAL_KEY), precomputed — the key the TENANT_KEY_SCOPE map is keyed on.
const TEST_KEY_HASH = 'd98e0aceefca229728fdbdd7fa479f224a7a31cb53bde4f083c1a181015e79b2';
const TENANT_A = 'tenant-1';
const TENANT_B = 'tenant-2';
const BINDING_A = 'TENANT_DB_TENANT_1';
const BINDING_B = 'TENANT_DB_TENANT_2';
const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, active FROM sub_tenants WHERE id = ? LIMIT 1';

type TestEnv = typeof env & {
	BV_WEB_INTERNAL_KEY?: string;
	REQUIRE_INTERNAL_AUTH?: string;
	TENANT_KEY_SCOPE?: string;
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
					// Registry lookup is keyed by the bound id (binds[0]) so a single
					// mock can answer for multiple tenants.
					if (sql === REGISTRY_LOOKUP_SQL) {
						const id = binds[0] as string;
						return { id, super_tenant_id: `super-${id}`, d1_db_id: `d1-${id}`, active: 1 } as unknown as T;
					}
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
					return { success: true, meta: { changes: 1, rows_written: 1 } } as unknown as D1Response;
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
	} as unknown as D1Database;
	return { db, calls };
}

function buildEnv(extra: Partial<TestEnv> = {}): TestEnv {
	const registry = makeMockD1();
	const tenantA = makeMockD1();
	const tenantB = makeMockD1();
	return {
		...env,
		BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
		REQUIRE_INTERNAL_AUTH: 'true',
		TENANT_REGISTRY_DB: registry.db,
		[BINDING_A]: tenantA.db,
		[BINDING_B]: tenantB.db,
		...extra,
	} as TestEnv;
}

function portfolioReq(tenant: string, headers: Record<string, string> = {}): Request {
	return new Request('https://api.blackveil.local/internal/tenants/portfolio', {
		method: 'POST',
		headers: {
			Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
			'X-Tenant': tenant,
			'Content-Type': 'application/json',
			...headers,
		},
		body: JSON.stringify({ domains: ['example.com'] }),
	});
}

async function send(req: Request, customEnv: TestEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

beforeEach(() => resetTenantResolverCache());
afterEach(() => resetTenantResolverCache());

describe('FINDING #5: opt-in tenant-scope assertion (BOLA)', () => {
	it('(a) env TENANT_KEY_SCOPE: a key scoped to tenant A is 403 when requesting tenant B', async () => {
		const customEnv = buildEnv({ TENANT_KEY_SCOPE: JSON.stringify({ [TEST_KEY_HASH]: [TENANT_A] }) });
		const res = await send(portfolioReq(TENANT_B), customEnv);
		expect(res.status).toBe(403);
	});

	it('(b) env TENANT_KEY_SCOPE: the matching tenant succeeds', async () => {
		const customEnv = buildEnv({ TENANT_KEY_SCOPE: JSON.stringify({ [TEST_KEY_HASH]: [TENANT_A] }) });
		const res = await send(portfolioReq(TENANT_A), customEnv);
		expect(res.status).toBe(200);
	});

	it('(a2) X-Tenant-Scope header: requesting a tenant outside the header scope is 403', async () => {
		const customEnv = buildEnv();
		const res = await send(portfolioReq(TENANT_B, { 'X-Tenant-Scope': TENANT_A }), customEnv);
		expect(res.status).toBe(403);
	});

	it('(b2) X-Tenant-Scope header: requesting a tenant inside the header scope succeeds', async () => {
		const customEnv = buildEnv();
		const res = await send(portfolioReq(TENANT_A, { 'X-Tenant-Scope': `${TENANT_A},${TENANT_B}` }), customEnv);
		expect(res.status).toBe(200);
	});

	it('(c) NO scope configured: current single-key behaviour is preserved (no regression)', async () => {
		const customEnv = buildEnv();
		const res = await send(portfolioReq(TENANT_B), customEnv);
		expect(res.status).toBe(200);
	});

	it('an attacker-supplied X-Tenant-Scope header cannot widen the credential-bound env cap', async () => {
		// env map locks this bearer to TENANT_A; the attacker also sends an
		// X-Tenant-Scope header naming TENANT_B. The header must only ever NARROW
		// the credential cap, never widen it — so the request for TENANT_B is 403.
		const customEnv = buildEnv({ TENANT_KEY_SCOPE: JSON.stringify({ [TEST_KEY_HASH]: [TENANT_A] }) });
		const res = await send(portfolioReq(TENANT_B, { 'X-Tenant-Scope': TENANT_B }), customEnv);
		expect(res.status).toBe(403);
	});

	it('a key absent from the TENANT_KEY_SCOPE map is unrestricted (map only constrains listed keys)', async () => {
		// The single shared prod key may not appear in a partial scope map; absence
		// must NOT lock it out (backward-compat) — only keys present in the map are
		// constrained to their listed tenants.
		const customEnv = buildEnv({ TENANT_KEY_SCOPE: JSON.stringify({ 'some-other-key-hash': [TENANT_A] }) });
		const res = await send(portfolioReq(TENANT_B), customEnv);
		expect(res.status).toBe(200);
	});
});
