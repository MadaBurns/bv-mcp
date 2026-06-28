// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 4 (WFP routing) — TDD contract spec for the per-tenant `TenantDbHandle`
 * returned by `resolveTenant()` / `resolveTenantUncached()`.
 *
 * Layer: Unit (Vitest, Workers pool). Asserts the ship-dark routing contract:
 *   - `routing_mode` unset → `'convention'` static-binding handle (today's behavior).
 *   - `routing_mode='rest'` (+ account/token) → a `D1ByIdClient`.
 *   - `routing_mode='dispatch'` (+ namespace) → a `'dispatch'` handle.
 *   - `dispatch`/`rest` with the needed binding/token ABSENT → fail-safe to
 *     `'convention'` (dark — nothing set ⇒ byte-for-byte today).
 *   - a call-site routes SQL through `tenant.db` to the underlying static binding.
 *   - the cache-bypassing `resolveTenantUncached()` builds the same backend.
 *
 * Mock isolation: dynamic `import()` inside each test fn; cache reset per-test.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type { ResolverEnv } from '../../src/tenants/tenant-resolver';

const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';
const ACTIVE_PROBE_SQL = 'SELECT active FROM sub_tenants WHERE id = ? LIMIT 1';
const TEST_TENANT_ID = 'tenant-1';
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';

/** Minimal registry mock returning a configurable `routing_mode` + `d1_db_id`. */
function makeRegistry(routingMode: string | null, d1DbId = 'db-uuid'): D1Database {
	const db = {
		prepare(sql: string) {
			const stmt = {
				bind() {
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					if (sql === REGISTRY_LOOKUP_SQL) {
						return {
							id: TEST_TENANT_ID,
							super_tenant_id: 'super-1',
							d1_db_id: d1DbId,
							routing_mode: routingMode,
							active: 1,
						} as unknown as T;
					}
					if (sql === ACTIVE_PROBE_SQL) {
						return { active: 1 } as unknown as T;
					}
					return null;
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
	} as unknown as D1Database;
	return db;
}

/** A fake per-tenant static D1 binding whose `prepare()` records calls + returns canned rows. */
function makeTenantBinding(rows: Record<string, unknown>[]) {
	const calls: { sql: string; params: unknown[] }[] = [];
	const db = {
		prepare(sql: string) {
			let bound: unknown[] = [];
			const stmt = {
				bind(...values: unknown[]) {
					bound = values;
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					calls.push({ sql, params: bound });
					return (rows[0] ?? null) as T | null;
				},
				async all<T = unknown>() {
					calls.push({ sql, params: bound });
					return { success: true, results: rows, meta: {} } as unknown as D1Result<T>;
				},
				async run<T = unknown>() {
					calls.push({ sql, params: bound });
					return { success: true, results: [], meta: {} } as unknown as D1Result<T>;
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
	} as unknown as D1Database;
	return { db, calls };
}

describe('Phase 4 — resolveTenant backend selection (ship-dark)', () => {
	beforeEach(async () => {
		const { resetTenantResolverCache } = await import('../../src/tenants/tenant-resolver');
		resetTenantResolverCache();
	});

	it("defaults to a 'convention' static-binding handle when routing_mode is unset", async () => {
		const { resolveTenant } = await import('../../src/tenants/tenant-resolver');
		const env = {
			TENANT_REGISTRY_DB: makeRegistry(null),
			[TEST_TENANT_BINDING]: {} as D1Database,
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('convention');
		expect(tenant.dbBinding).toBe(TEST_TENANT_BINDING);
	});

	it("returns a D1ByIdClient ('rest' backend) when routing_mode='rest' with account + token present", async () => {
		const { resolveTenant } = await import('../../src/tenants/tenant-resolver');
		const { D1ByIdClient } = await import('../../src/tenants/d1-rest-client');
		const env = {
			TENANT_REGISTRY_DB: makeRegistry('rest', 'db-rest-uuid'),
			CF_ACCOUNT_ID: 'acct-123',
			CF_D1_API_TOKEN: 'tok-xyz',
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('rest');
		expect(tenant.db).toBeInstanceOf(D1ByIdClient);
	});

	it("returns a 'dispatch' handle when routing_mode='dispatch' and the dispatch namespace is bound", async () => {
		const { resolveTenant } = await import('../../src/tenants/tenant-resolver');
		const env = {
			TENANT_REGISTRY_DB: makeRegistry('dispatch'),
			TENANT_DISPATCH_NAMESPACE: { get: () => ({ fetch: async () => new Response('{}') }) } as unknown as DispatchNamespace,
			// A static binding also exists; dispatch must still win when the namespace is present.
			[TEST_TENANT_BINDING]: {} as D1Database,
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('dispatch');
	});

	it("fails safe to 'convention' when routing_mode='dispatch' but the namespace is absent (dark)", async () => {
		const { resolveTenant } = await import('../../src/tenants/tenant-resolver');
		const env = {
			TENANT_REGISTRY_DB: makeRegistry('dispatch'),
			[TEST_TENANT_BINDING]: {} as D1Database,
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('convention');
	});

	it("fails safe to 'convention' when routing_mode='rest' but the API token is absent (dark)", async () => {
		const { resolveTenant } = await import('../../src/tenants/tenant-resolver');
		const env = {
			TENANT_REGISTRY_DB: makeRegistry('rest'),
			CF_ACCOUNT_ID: 'acct-123',
			// CF_D1_API_TOKEN intentionally missing.
			[TEST_TENANT_BINDING]: {} as D1Database,
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('convention');
	});
});

describe('Phase 4 — call-site routes through tenant.db', () => {
	beforeEach(async () => {
		const { resetTenantResolverCache } = await import('../../src/tenants/tenant-resolver');
		resetTenantResolverCache();
	});

	it('issues SQL through the convention handle to the underlying static binding', async () => {
		const { resolveTenant } = await import('../../src/tenants/tenant-resolver');
		const binding = makeTenantBinding([{ domain: 'example.com' }]);
		const env = {
			TENANT_REGISTRY_DB: makeRegistry(null),
			[TEST_TENANT_BINDING]: binding.db,
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		const row = await tenant.db.prepare('SELECT domain FROM domains WHERE domain = ?').bind('example.com').first<{ domain: string }>();

		expect(row).toEqual({ domain: 'example.com' });
		expect(binding.calls).toEqual([{ sql: 'SELECT domain FROM domains WHERE domain = ?', params: ['example.com'] }]);
	});

	it('resolveTenantUncached builds the same convention backend without seeding the cache', async () => {
		const { resolveTenantUncached } = await import('../../src/tenants/tenant-resolver');
		const env = {
			TENANT_REGISTRY_DB: makeRegistry(null),
			[TEST_TENANT_BINDING]: {} as D1Database,
		} as ResolverEnv;

		const tenant = await resolveTenantUncached(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('convention');
	});
});
