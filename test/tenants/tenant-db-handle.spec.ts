// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 4 (WFP routing) unit tests for the per-tenant `TenantDbHandle` returned
 * by `resolveTenant()` and the `D1ByIdClient` REST fallback.
 *
 * Layer: Unit. Covers backend selection by `sub_tenants.routing_mode`, the
 * fail-safe fall-back to the static convention binding when the dispatch
 * namespace / REST token is absent (ship-dark), the REST client's request
 * shape + result parsing, and a call-site round-trip through the handle surface.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { resolveTenant, resolveTenantUncached, resetTenantResolverCache, type ResolverEnv } from '../../src/tenants/tenant-resolver';
import { D1ByIdClient } from '../../src/tenants/d1-rest-client';

const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';
const ACTIVE_PROBE_SQL = 'SELECT active FROM sub_tenants WHERE id = ? LIMIT 1';
const TEST_TENANT_ID = 'tenant-1';
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';

/** Minimal registry mock that returns a configurable `routing_mode` + `d1_db_id`. */
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

/** A fake per-tenant D1 binding whose `prepare()` records calls + returns canned rows. */
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

describe('Phase 4 — tenant DB handle routing', () => {
	beforeEach(() => {
		resetTenantResolverCache();
	});

	it("returns a 'convention' static-binding handle when routing_mode is unset (today's behavior)", async () => {
		const env = {
			TENANT_REGISTRY_DB: makeRegistry(null),
			[TEST_TENANT_BINDING]: {} as D1Database,
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('convention');
		expect(tenant.dbBinding).toBe(TEST_TENANT_BINDING);
	});

	it("returns a D1ByIdClient ('rest' backend) when routing_mode='rest' and token+account present", async () => {
		const env = {
			TENANT_REGISTRY_DB: makeRegistry('rest', 'db-rest-uuid'),
			CF_ACCOUNT_ID: 'acct-123',
			CF_D1_API_TOKEN: 'tok-xyz',
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('rest');
		expect(tenant.db).toBeInstanceOf(D1ByIdClient);
	});

	it("returns a 'dispatch' handle when routing_mode='dispatch' and the namespace is bound", async () => {
		const env = {
			TENANT_REGISTRY_DB: makeRegistry('dispatch'),
			TENANT_DISPATCH_NAMESPACE: { get: () => ({ fetch: async () => new Response('{}') }) } as unknown as DispatchNamespace,
			// A static binding also exists — but dispatch must win because the namespace is present.
			[TEST_TENANT_BINDING]: {} as D1Database,
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('dispatch');
	});

	it("falls back to 'convention' when routing_mode='dispatch' but the namespace binding is absent (fail-safe, dark)", async () => {
		const env = {
			TENANT_REGISTRY_DB: makeRegistry('dispatch'),
			[TEST_TENANT_BINDING]: {} as D1Database,
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('convention');
	});

	it("falls back to 'convention' when routing_mode='rest' but the API token is absent (fail-safe, dark)", async () => {
		const env = {
			TENANT_REGISTRY_DB: makeRegistry('rest'),
			CF_ACCOUNT_ID: 'acct-123',
			// CF_D1_API_TOKEN missing
			[TEST_TENANT_BINDING]: {} as D1Database,
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('convention');
	});

	it('routes SQL through the convention handle to the underlying static binding (call-site round-trip)', async () => {
		const binding = makeTenantBinding([{ domain: 'example.com' }]);
		const env = {
			TENANT_REGISTRY_DB: makeRegistry(null),
			[TEST_TENANT_BINDING]: binding.db,
		} as ResolverEnv;

		const tenant = await resolveTenant(env, TEST_TENANT_ID);
		const row = await tenant.db.prepare('SELECT domain FROM domains WHERE domain = ?').bind('example.com').first<{ domain: string }>();
		expect(row).toEqual({ domain: 'example.com' });
		expect(binding.calls).toHaveLength(1);
		expect(binding.calls[0]).toEqual({ sql: 'SELECT domain FROM domains WHERE domain = ?', params: ['example.com'] });
	});

	it('resolveTenantUncached builds the same backend without populating the cache', async () => {
		const env = {
			TENANT_REGISTRY_DB: makeRegistry(null),
			[TEST_TENANT_BINDING]: {} as D1Database,
		} as ResolverEnv;

		const tenant = await resolveTenantUncached(env, TEST_TENANT_ID);
		expect(tenant.db.backend).toBe('convention');
	});
});

describe('Phase 4 — D1ByIdClient REST transport', () => {
	function fakeFetch(captured: { url?: string; init?: RequestInit }, payload: unknown, ok = true, status = 200) {
		return (async (url: string | URL | Request, init?: RequestInit) => {
			captured.url = String(url);
			captured.init = init;
			return {
				ok,
				status,
				json: async () => payload,
			} as unknown as Response;
		}) as unknown as typeof fetch;
	}

	it('builds the correct REST request and parses .all() results', async () => {
		const captured: { url?: string; init?: RequestInit } = {};
		const payload = { success: true, result: [{ results: [{ id: 'a' }, { id: 'b' }] }] };
		const client = new D1ByIdClient('db-uuid', 'acct-123', 'tok-xyz', fakeFetch(captured, payload));

		const res = await client.prepare('SELECT id FROM t WHERE k = ?').bind('v1').all<{ id: string }>();

		expect(res.results).toEqual([{ id: 'a' }, { id: 'b' }]);
		expect(captured.url).toBe('https://api.cloudflare.com/client/v4/accounts/acct-123/d1/database/db-uuid/query');
		expect(captured.init?.method).toBe('POST');
		expect((captured.init?.headers as Record<string, string>).authorization).toBe('Bearer tok-xyz');
		expect((captured.init?.headers as Record<string, string>)['content-type']).toBe('application/json');
		expect(JSON.parse(captured.init?.body as string)).toEqual({ sql: 'SELECT id FROM t WHERE k = ?', params: ['v1'] });
	});

	it('.first() returns the first row and .first(col) extracts the column', async () => {
		const captured: { url?: string; init?: RequestInit } = {};
		const payload = { success: true, result: [{ results: [{ id: 'a', name: 'first' }] }] };
		const client = new D1ByIdClient('db-uuid', 'acct-123', 'tok-xyz', fakeFetch(captured, payload));

		expect(await client.prepare('SELECT * FROM t').first()).toEqual({ id: 'a', name: 'first' });
		expect(await client.prepare('SELECT * FROM t').first<string>('name')).toBe('first');
	});

	it('.first() returns null on an empty result set', async () => {
		const captured: { url?: string; init?: RequestInit } = {};
		const payload = { success: true, result: [{ results: [] }] };
		const client = new D1ByIdClient('db-uuid', 'acct-123', 'tok-xyz', fakeFetch(captured, payload));
		expect(await client.prepare('SELECT * FROM t WHERE 0').first()).toBeNull();
	});

	it('throws tenant_db_rest_failed on a non-2xx response', async () => {
		const captured: { url?: string; init?: RequestInit } = {};
		const client = new D1ByIdClient('db-uuid', 'acct-123', 'tok-xyz', fakeFetch(captured, { success: false }, false, 403));
		await expect(client.prepare('SELECT 1').run()).rejects.toThrow(/tenant_db_rest_failed:403/);
	});
});
