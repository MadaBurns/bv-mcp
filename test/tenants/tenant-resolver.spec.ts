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

const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';
const ACTIVE_PROBE_SQL = 'SELECT active FROM sub_tenants WHERE id = ? LIMIT 1';
const TEST_TENANT_ID = 'tenant-1';
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';

/**
 * Mutable mock registry whose `active` flag can be flipped between calls.
 *
 * It answers BOTH the cold full-row lookup (`REGISTRY_LOOKUP_SQL`) and the
 * cheap cache-hit active probe (`ACTIVE_PROBE_SQL`), counting each separately so
 * a perf test can assert that cache hits do NOT issue another full-row read.
 *
 * `throwOnProbe` makes the active probe throw (simulating a transient D1
 * hiccup on the recheck path) so the availability (#3) test can assert the
 * resolver fails open to the cached value rather than dropping it.
 */
function makeRegistry(initialActive: number | boolean) {
	let active: number | boolean = initialActive;
	let throwOnProbe = false;
	let fullRowQueries = 0;
	let probeQueries = 0;
	const db = {
		prepare(sql: string) {
			const stmt = {
				bind() {
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					if (sql === REGISTRY_LOOKUP_SQL) {
						fullRowQueries += 1;
						return {
							id: TEST_TENANT_ID,
							super_tenant_id: 'super-1',
							d1_db_id: 'fake-uuid',
							routing_mode: null,
							active,
						} as unknown as T;
					}
					if (sql === ACTIVE_PROBE_SQL) {
						probeQueries += 1;
						if (throwOnProbe) {
							throw new Error('D1_ERROR: transient registry hiccup');
						}
						return { active } as unknown as T;
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
		setThrowOnProbe(v: boolean) {
			throwOnProbe = v;
		},
		get fullRowQueries() {
			return fullRowQueries;
		},
		get probeQueries() {
			return probeQueries;
		},
		/** Total registry reads of any kind. */
		get queries() {
			return fullRowQueries + probeQueries;
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

	// FINDING #2 (perf): the cache-hit recheck must NOT issue a full-row registry
	// read per hit. A burst of N hits within the TTL may do cheap `active` probes,
	// but the expensive full-row lookup must run exactly once (the cold resolve).
	it('does not issue a full-row registry read on cache hits (perf invariant)', async () => {
		const registry = makeRegistry(1);
		const env = makeEnv(registry.db);

		await resolveTenant(env, TEST_TENANT_ID); // cold resolve → 1 full-row read
		const HITS = 5;
		for (let i = 0; i < HITS; i += 1) {
			await resolveTenant(env, TEST_TENANT_ID); // cache hits
		}

		// The expensive full-row lookup fired only on the cold miss; every hit used
		// the cheap indexed `active` probe instead.
		expect(registry.fullRowQueries).toBe(1);
	});

	// FINDING #3 (availability): if the cache-hit active recheck throws transiently
	// (D1 hiccup), the still-valid cached tenant must be SERVED (fail-open), not
	// dropped and re-resolved into the same failing read.
	it('serves the cached tenant when the active recheck read throws transiently', async () => {
		const registry = makeRegistry(1);
		const env = makeEnv(registry.db);

		// Prime the cache with a successful resolution.
		const first = await resolveTenant(env, TEST_TENANT_ID);
		expect(first.subTenantId).toBe(TEST_TENANT_ID);

		// Make the recheck probe throw on the next call (transient registry blip).
		registry.setThrowOnProbe(true);

		// Must still serve the cached value rather than failing the tenant.
		const second = await resolveTenant(env, TEST_TENANT_ID);
		expect(second.subTenantId).toBe(TEST_TENANT_ID);
		expect(second.dbBinding).toBe(first.dbBinding);

		// And the entry must NOT have been dropped: a subsequent call (recheck now
		// healthy again) still resolves without a second cold full-row read.
		registry.setThrowOnProbe(false);
		const third = await resolveTenant(env, TEST_TENANT_ID);
		expect(third.subTenantId).toBe(TEST_TENANT_ID);
		expect(registry.fullRowQueries).toBe(1);
	});
});
