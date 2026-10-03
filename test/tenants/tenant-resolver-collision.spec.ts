// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-289: `acme-corp` and `acme_corp` are both valid under TENANT_ID_REGEX but
 * normalize to the same binding suffix (`TENANT_DB_ACME_CORP`), so if both
 * registry rows are active, one tenant would read/write the other's D1. The
 * resolver must refuse a tenant whose normalized id collides with another
 * ACTIVE registry row. The mock registry emulates the semantics (normalized-id
 * comparison across rows), not a particular SQL string.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { resolveTenant, resolveTenantUncached, resetTenantResolverCache, type ResolverEnv } from '../../src/tenants/tenant-resolver';

const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';
const ACTIVE_PROBE_SQL = 'SELECT active FROM sub_tenants WHERE id = ? LIMIT 1';

type Row = { id: string; super_tenant_id: string; d1_db_id: string; routing_mode: string | null; active: number };
const normalize = (id: string) => id.replaceAll('-', '_').toUpperCase();

function makeCollisionRegistry(rows: Row[]): D1Database {
	return {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					if (sql === REGISTRY_LOOKUP_SQL || sql === ACTIVE_PROBE_SQL) {
						return (rows.find((r) => r.id === binds[0]) as unknown as T | undefined) ?? null;
					}
					if (/upper\(replace\(id/i.test(sql)) {
						// Any ACTIVE row, other than the requested id, whose normalized id equals the requested one.
						const other = rows.find((r) => r.active && r.id !== binds[1] && normalize(r.id) === binds[0]);
						return (other ? { id: other.id } : null) as unknown as T | null;
					}
					return null;
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
	} as unknown as D1Database;
}

const row = (id: string, active = 1): Row => ({ id, super_tenant_id: 'super-1', d1_db_id: 'fake-uuid', routing_mode: null, active });
const collisionEnv = (registry: D1Database) => ({ TENANT_REGISTRY_DB: registry, TENANT_DB_ACME_CORP: {} as D1Database }) as ResolverEnv;

describe('resolveTenant normalized-id collision denial (SQ-289)', () => {
	beforeEach(() => {
		resetTenantResolverCache();
	});

	it('refuses BOTH colliding tenants when acme-corp and acme_corp are both active', async () => {
		const env = collisionEnv(makeCollisionRegistry([row('acme-corp'), row('acme_corp')]));
		await expect(resolveTenant(env, 'acme-corp')).rejects.toThrow(/^Tenant not found/);
		await expect(resolveTenant(env, 'acme_corp')).rejects.toThrow(/^Tenant not found/);
		await expect(resolveTenantUncached(env, 'acme_corp')).rejects.toThrow(/^Tenant not found/);
	});

	it('still resolves a tenant whose colliding sibling is inactive', async () => {
		const env = collisionEnv(makeCollisionRegistry([row('acme-corp'), row('acme_corp', 0)]));
		const resolved = await resolveTenant(env, 'acme-corp');
		expect(resolved.subTenantId).toBe('acme-corp');
		expect(resolved.dbBinding).toBe('TENANT_DB_ACME_CORP');
	});

	it('still resolves a tenant with no colliding sibling', async () => {
		const env = collisionEnv(makeCollisionRegistry([row('acme-corp'), row('other-corp')]));
		const resolved = await resolveTenant(env, 'acme-corp');
		expect(resolved.subTenantId).toBe('acme-corp');
	});
});
