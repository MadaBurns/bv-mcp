import { describe, it, expect } from 'vitest';
import { getTableConfig } from 'drizzle-orm/sqlite-core';
import { superTenants, subTenants, tenantKeys, billingEvents } from '../../../src/csc/db/schema/registry';

/**
 * Unit tests for the shared registry D1 schema (CSC-Scalable-Architecture-Design.md §3.1).
 *
 * The schema is the contract between the registry-DB migration SQL and the
 * adapter / handler code that reads/writes it. Drift here = silent prod bugs,
 * so we lock the table names, column names, types, NOT NULLs, and indexes.
 */

function columnMap(table: ReturnType<typeof getTableConfig>) {
	return Object.fromEntries(table.columns.map((c) => [c.name, c]));
}

describe('registry schema — super_tenants', () => {
	const t = getTableConfig(superTenants);
	const cols = columnMap(t);

	it('table is named super_tenants', () => {
		expect(t.name).toBe('super_tenants');
	});

	it('has the documented columns', () => {
		expect(Object.keys(cols).sort()).toEqual(
			['active', 'api_key_hash', 'created_at', 'd1_binding_prefix', 'id', 'metadata', 'name', 'rate_limit_per_minute'].sort(),
		);
	});

	it('id is TEXT primary key', () => {
		expect(cols.id.primary).toBe(true);
		expect(cols.id.dataType).toBe('string');
		expect(cols.id.notNull).toBe(true);
	});

	it('required NOT NULL columns', () => {
		expect(cols.name.notNull).toBe(true);
		expect(cols.api_key_hash.notNull).toBe(true);
		expect(cols.d1_binding_prefix.notNull).toBe(true);
		expect(cols.created_at.notNull).toBe(true);
	});

	it('integer / boolean fields have correct dataType', () => {
		// SQLite booleans are stored as integers in drizzle-orm
		expect(cols.active.dataType).toBe('boolean');
		expect(cols.rate_limit_per_minute.dataType).toBe('number');
		expect(cols.created_at.dataType).toBe('number');
	});

	it('metadata is optional JSON-as-text', () => {
		expect(cols.metadata.notNull).toBe(false);
		expect(cols.metadata.dataType).toBe('string');
	});
});

describe('registry schema — sub_tenants', () => {
	const t = getTableConfig(subTenants);
	const cols = columnMap(t);

	it('table is named sub_tenants', () => {
		expect(t.name).toBe('sub_tenants');
	});

	it('has the documented columns', () => {
		expect(Object.keys(cols).sort()).toEqual(
			[
				'active',
				'created_at',
				'd1_db_id',
				'domain_count',
				'id',
				'name',
				'scan_quota_per_month',
				'scan_schedule',
				'super_tenant_id',
			].sort(),
		);
	});

	it('id is TEXT primary key', () => {
		expect(cols.id.primary).toBe(true);
		expect(cols.id.notNull).toBe(true);
	});

	it('super_tenant_id is NOT NULL FK target', () => {
		expect(cols.super_tenant_id.notNull).toBe(true);
		// Foreign-key relation declared at the table level
		expect(t.foreignKeys.length).toBeGreaterThan(0);
		const fk = t.foreignKeys[0].reference();
		expect(fk.foreignTable === superTenants).toBe(true);
	});

	it('d1_db_id is required (per-tenant DB UUID)', () => {
		expect(cols.d1_db_id.notNull).toBe(true);
	});
});

describe('registry schema — tenant_keys', () => {
	const t = getTableConfig(tenantKeys);
	const cols = columnMap(t);

	it('table is named tenant_keys', () => {
		expect(t.name).toBe('tenant_keys');
	});

	it('has the documented columns', () => {
		expect(Object.keys(cols).sort()).toEqual(
			['expires_at', 'key_hash', 'last_used_at', 'revoked_at', 'scope', 'sub_tenant_id', 'super_tenant_id'].sort(),
		);
	});

	it('key_hash is the primary key', () => {
		expect(cols.key_hash.primary).toBe(true);
		expect(cols.key_hash.notNull).toBe(true);
	});

	it('sub_tenant_id is nullable (super-tenant-wide keys)', () => {
		expect(cols.sub_tenant_id.notNull).toBe(false);
	});

	it('scope is required', () => {
		expect(cols.scope.notNull).toBe(true);
	});
});

describe('registry schema — billing_events', () => {
	const t = getTableConfig(billingEvents);
	const cols = columnMap(t);

	it('table is named billing_events', () => {
		expect(t.name).toBe('billing_events');
	});

	it('has the documented columns', () => {
		expect(Object.keys(cols).sort()).toEqual(
			['cost_cents', 'count', 'event_type', 'id', 'occurred_at', 'sub_tenant_id', 'super_tenant_id'].sort(),
		);
	});

	it('id is the primary key', () => {
		expect(cols.id.primary).toBe(true);
	});

	it('count and occurred_at are NOT NULL', () => {
		expect(cols.count.notNull).toBe(true);
		expect(cols.occurred_at.notNull).toBe(true);
	});

	it('declares idx_billing_lookup composite index on (super_tenant_id, occurred_at)', () => {
		const indexes = t.indexes;
		const target = indexes.find((i) => i.config.name === 'idx_billing_lookup');
		expect(target).toBeDefined();
		const cfg = target!.config;
		expect(cfg.columns.map((c) => (c as { name: string }).name)).toEqual(['super_tenant_id', 'occurred_at']);
	});
});
