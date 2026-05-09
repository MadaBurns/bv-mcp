import { describe, it, expect, vi } from 'vitest';
import { tenantD1 } from '../../src/tenants/adapters/tenant-d1';

/**
 * Unit tests for the tenant-D1 adapter.
 *
 * Per tenant-Scalable-Architecture-Design.md §2.3: each tenant Worker has a
 * `TENANT_PREFIX` env injected by the platform deployer; adapters auto-stamp
 * tenant scoping so we don't have to thread `tenant_id` through every call.
 *
 * Per-tenant D1 binding is itself isolated (one DB per sub-tenant), so
 * `prepare(sql)` is passed through unchanged. The adapter only adds tenant
 * scoping for SHARED-registry queries via `selectAll(table)`.
 */

function fakeD1Binding() {
	const prepared: string[] = [];
	const binding = {
		prepare(sql: string) {
			prepared.push(sql);
			return { __sql: sql } as unknown as D1PreparedStatement;
		},
	} as unknown as D1Database;
	return { binding, prepared };
}

describe('tenantD1 adapter', () => {
	it('passes prepare() through unchanged and prefixes selectAll()', () => {
		const { binding, prepared } = fakeD1Binding();
		const adapter = tenantD1(binding, 'tenant');

		adapter.prepare('SELECT * FROM scans WHERE id = ?');
		adapter.selectAll('billing_events');

		expect(prepared).toEqual(['SELECT * FROM scans WHERE id = ?', 'SELECT * FROM tenant_billing_events']);
		expect(adapter.prefix).toBe('tenant');
	});

	it('rejects empty / unsafe prefix at construction (cross-tenant leak guard)', () => {
		const { binding } = fakeD1Binding();
		expect(() => tenantD1(binding, '')).toThrow(/prefix/i);
		expect(() => tenantD1(binding, 'tenant; DROP')).toThrow(/prefix/i);
		expect(() => tenantD1(binding, "tenant'foo")).toThrow(/prefix/i);
	});

	it('rejects unsafe table names without performing any I/O (SQL injection guard)', () => {
		const { binding, prepared } = fakeD1Binding();
		const adapter = tenantD1(binding, 'tenant');
		const spy = vi.spyOn(binding, 'prepare');

		expect(() => adapter.selectAll('domains; DROP TABLE users--')).toThrow(/invalid table/i);
		expect(() => adapter.selectAll("foo'bar")).toThrow(/invalid table/i);
		expect(() => adapter.selectAll('foo bar')).toThrow(/invalid table/i);
		expect(spy).not.toHaveBeenCalled();
		expect(prepared).toEqual([]);
	});

	it('isolates two adapters with different prefixes', () => {
		const { binding: b1, prepared: p1 } = fakeD1Binding();
		const { binding: b2, prepared: p2 } = fakeD1Binding();

		tenantD1(b1, 'tenant').selectAll('domains');
		tenantD1(b2, 'acme').selectAll('domains');

		expect(p1).toEqual(['SELECT * FROM tenant_domains']);
		expect(p2).toEqual(['SELECT * FROM acme_domains']);
	});

	it('forwards binding errors from prepare() rather than swallowing them', () => {
		const failing = {
			prepare() {
				throw new Error('D1_ERROR: prepare failed');
			},
		} as unknown as D1Database;
		const adapter = tenantD1(failing, 'tenant');
		expect(() => adapter.prepare('SELECT 1')).toThrow(/D1_ERROR/);
	});
});
