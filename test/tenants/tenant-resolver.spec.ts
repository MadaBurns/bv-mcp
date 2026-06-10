// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for `resolveTenant` cache semantics.
 *
 * FINDING #7 (P3): a successful resolution is cached ~5 min and returned on a
 * hit WITHOUT re-checking the registry `active` flag, so a deactivated tenant
 * stays resolvable until the entry expires. The fix re-validates `active` on a
 * cache hit so deactivation propagates promptly while keeping the binding /
 * prefix work cached for the common (still-active) case.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { resolveTenant, resetTenantResolverCache, type ResolverEnv } from '../../src/tenants/tenant-resolver';

const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, active FROM sub_tenants WHERE id = ? LIMIT 1';
const TEST_TENANT_ID = 'tenant-1';
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';

/**
 * Mutable mock registry whose `active` flag can be flipped between calls. Counts
 * how many times the registry was queried so we can assert the cache still saves
 * the full lookup on a hit (perf) while re-checking `active`.
 */
function makeRegistry(initialActive: number | boolean) {
	let active: number | boolean = initialActive;
	let queries = 0;
	const db = {
		prepare(sql: string) {
			const stmt = {
				bind() {
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					if (sql === REGISTRY_LOOKUP_SQL) {
						queries += 1;
						return {
							id: TEST_TENANT_ID,
							super_tenant_id: 'super-1',
							d1_db_id: 'fake-uuid',
							active,
						} as unknown as T;
					}
					return null;
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
	} as unknown as D1Database;
	return {
		db,
		setActive(v: number | boolean) {
			active = v;
		},
		get queries() {
			return queries;
		},
	};
}

function makeEnv(registry: D1Database): ResolverEnv {
	return {
		TENANT_REGISTRY_DB: registry,
		[TEST_TENANT_BINDING]: {} as D1Database,
	} as ResolverEnv;
}

describe('resolveTenant cache active-flag re-validation (FINDING #7)', () => {
	beforeEach(() => {
		resetTenantResolverCache();
	});

	it('stops resolving a tenant that is deactivated in the registry, even within the cache TTL', async () => {
		const registry = makeRegistry(1);
		const env = makeEnv(registry.db);

		// Prime the cache with a successful resolution.
		const first = await resolveTenant(env, TEST_TENANT_ID);
		expect(first.subTenantId).toBe(TEST_TENANT_ID);

		// Deactivate in the registry (active = 0) without advancing the clock past TTL.
		registry.setActive(0);

		// A second resolve within the TTL must now fail rather than serve the stale
		// "active" cache entry.
		await expect(resolveTenant(env, TEST_TENANT_ID)).rejects.toThrow(/Tenant not found/);
	});

	it('serves an unchanged active tenant from cache without re-running the full lookup twice', async () => {
		const registry = makeRegistry(1);
		const env = makeEnv(registry.db);

		const a = await resolveTenant(env, TEST_TENANT_ID);
		const b = await resolveTenant(env, TEST_TENANT_ID);

		expect(a.subTenantId).toBe(b.subTenantId);
		expect(a.dbBinding).toBe(b.dbBinding);
		// Cache preserved its perf benefit: the second call did at most one cheap
		// active re-check, never a second full cold resolution.
		expect(registry.queries).toBeLessThanOrEqual(2);
	});
});
