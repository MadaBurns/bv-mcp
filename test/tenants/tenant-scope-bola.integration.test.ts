// SPDX-License-Identifier: BUSL-1.1

/**
 * FINDING #5 (P2, BOLA): a dedicated BV_MCP_TENANT_KEY authenticates
 * /internal/tenants/* calls, and the X-Tenant header alone selects the tenant —
 * nothing binds the caller's credential to an authorized tenant scope.
 *
 * The fix is fail-closed: every call needs either a credential-bound
 * TENANT_KEY_SCOPE entry or a matching X-Tenant-Scope assertion. Malformed,
 * truncated, missing, and absent-key mappings deny access.
 *
 * These tests assert cross-tenant denial, in-scope access, missing-scope denial,
 * and mandatory bearer enforcement even when the legacy opt-out is set.
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
const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';

type TestEnv = typeof env & {
	BV_MCP_TENANT_KEY?: string;
	BV_MCP_BRAND_WEBHOOK_KEY?: string;
	BV_WEB_INTERNAL_KEY?: string;
	BV_MOBILE_INTERNAL_KEY?: string;
	BV_MCP_OAUTH_MINT_KEY?: string;
	BV_MCP_OAUTH_REVOKE_KEY?: string;
	BV_MCP_TOOL_DELEGATION_KEY?: string;
	BV_MCP_WATCH_CLEANUP_KEY?: string;
	BV_MCP_M365_KEY?: string;
	OAUTH_SIGNING_SECRET?: string;
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
		BV_MCP_TENANT_KEY: TEST_INTERNAL_KEY,
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

describe('FINDING #5: fail-closed tenant-scope assertion (BOLA)', () => {
	it('rejects a tenant bearer shorter than the 32-byte capability floor', async () => {
		const customEnv = buildEnv({ BV_MCP_TENANT_KEY: 'too-short' });
		const res = await send(portfolioReq(TENANT_A, { 'X-Tenant-Scope': TENANT_A }), customEnv);
		expect(res.status).toBe(503);
	});

	it.each([
		'BV_WEB_INTERNAL_KEY',
		'BV_MOBILE_INTERNAL_KEY',
		'BV_MCP_OAUTH_MINT_KEY',
		'BV_MCP_OAUTH_REVOKE_KEY',
		'BV_MCP_TOOL_DELEGATION_KEY',
		'BV_MCP_WATCH_CLEANUP_KEY',
		'BV_MCP_M365_KEY',
		'BV_MCP_BRAND_WEBHOOK_KEY',
		'OAUTH_SIGNING_SECRET',
	] as const)('rejects a tenant bearer that aliases %s', async (peerKey) => {
		const customEnv = buildEnv({ [peerKey]: TEST_INTERNAL_KEY });
		const res = await send(portfolioReq(TENANT_A, { 'X-Tenant-Scope': TENANT_A }), customEnv);
		expect(res.status).toBe(503);
	});

	it('requires the dedicated bearer even when REQUIRE_INTERNAL_AUTH=false', async () => {
		const customEnv = buildEnv({ REQUIRE_INTERNAL_AUTH: 'false' });
		const req = portfolioReq(TENANT_A, { 'X-Tenant-Scope': TENANT_A });
		req.headers.delete('Authorization');
		const res = await send(req, customEnv);
		expect(res.status).toBe(401);
	});

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

	it('(b2) explicitly global orchestrator key: X-Tenant-Scope may select an in-header tenant', async () => {
		const customEnv = buildEnv();
		const res = await send(portfolioReq(TENANT_A, { 'X-Tenant-Scope': `${TENANT_A},${TENANT_B}` }), customEnv);
		expect(res.status).toBe(200);
	});

	it('(c) no scope signal is configured: access is denied', async () => {
		const customEnv = buildEnv();
		const res = await send(portfolioReq(TENANT_B), customEnv);
		expect(res.status).toBe(403);
	});

	it('an attacker-supplied X-Tenant-Scope header cannot widen the credential-bound env cap', async () => {
		// env map locks this bearer to TENANT_A; the attacker also sends an
		// X-Tenant-Scope header naming TENANT_B. The header must only ever NARROW
		// the credential cap, never widen it — so the request for TENANT_B is 403.
		const customEnv = buildEnv({ TENANT_KEY_SCOPE: JSON.stringify({ [TEST_KEY_HASH]: [TENANT_A] }) });
		const res = await send(portfolioReq(TENANT_B, { 'X-Tenant-Scope': TENANT_B }), customEnv);
		expect(res.status).toBe(403);
	});

	it('rejects a truncated 16-char analytics hash as an authorization key', async () => {
		const sixteen = TEST_KEY_HASH.slice(0, 16);
		const customEnv = buildEnv({ TENANT_KEY_SCOPE: JSON.stringify({ [sixteen]: [TENANT_A] }) });
		const res = await send(portfolioReq(TENANT_A), customEnv);
		expect(res.status).toBe(403);
	});

	it('denies a bearer absent from the TENANT_KEY_SCOPE map', async () => {
		const customEnv = buildEnv({ TENANT_KEY_SCOPE: JSON.stringify({ ['f'.repeat(64)]: [TENANT_A] }) });
		const res = await send(portfolioReq(TENANT_B), customEnv);
		expect(res.status).toBe(403);
	});

	it('denies malformed TENANT_KEY_SCOPE instead of failing open', async () => {
		const customEnv = buildEnv({ TENANT_KEY_SCOPE: '{not-json' });
		const res = await send(portfolioReq(TENANT_A, { 'X-Tenant-Scope': TENANT_A }), customEnv);
		expect(res.status).toBe(403);
	});
});
