// SPDX-License-Identifier: BUSL-1.1

/**
 * Tenant-prefix-stamping adapter for Cloudflare D1.
 *
 * Each tenant Worker has a `TENANT_PREFIX` env injected by the platform
 * deployer. Adapters auto-stamp tenant scoping so callers don't have to thread
 * `tenant_id` through every call.
 *
 * Per-tenant D1 binding is itself isolated (one DB per sub-tenant), so
 * `prepare(sql)` is passed through unchanged. The adapter only adds tenant
 * scoping for SHARED-registry queries via `selectAll(table)` which renders
 * `SELECT * FROM <prefix>_<table>`.
 *
 * Defence-in-depth: prefix and table identifiers are validated at construction
 * / call time against `[A-Za-z0-9_]+` to prevent SQL injection. We never
 * interpolate caller-supplied values; only validated identifiers reach the
 * SQL string.
 */

const SAFE_IDENTIFIER = /^[A-Za-z0-9_]+$/;

export interface TenantD1 {
	readonly prefix: string;
	prepare(sql: string): D1PreparedStatement;
	selectAll(table: string): D1PreparedStatement;
}

/**
 * Wrap a D1 binding with tenant-prefix-stamping for shared-registry queries.
 *
 * @param binding - underlying D1 database binding
 * @param prefix - tenant identifier (must match `[A-Za-z0-9_]+`)
 * @throws if `prefix` is empty or contains unsafe characters
 */
export function tenantD1(binding: D1Database, prefix: string): TenantD1 {
	if (!prefix || !SAFE_IDENTIFIER.test(prefix)) {
		throw new Error(`tenantD1: invalid prefix "${prefix}" (must match [A-Za-z0-9_]+)`);
	}

	return {
		prefix,
		prepare(sql: string): D1PreparedStatement {
			return binding.prepare(sql);
		},
		selectAll(table: string): D1PreparedStatement {
			if (!table || !SAFE_IDENTIFIER.test(table)) {
				throw new Error(`tenantD1: invalid table name "${table}" (must match [A-Za-z0-9_]+)`);
			}
			return binding.prepare(`SELECT * FROM ${prefix}_${table}`);
		},
	};
}
