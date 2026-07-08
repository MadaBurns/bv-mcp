import { describe, it, expect } from 'vitest';
import { getTableConfig } from 'drizzle-orm/sqlite-core';
import { domains, scans, findings, alerts } from '../../../src/tenants/db/schema/tenant';

/**
 * Unit tests for the per-sub-tenant D1 schema (tenant-Scalable-Architecture-Design.md §3.2).
 *
 * Each sub-tenant gets its own D1 database. These four tables live there.
 * Indexes encode our access patterns (latest scan per domain, active alerts,
 * batch cycle queries). Locking them in a test prevents the indexes from
 * silently disappearing during a refactor.
 */

function columnMap(table: ReturnType<typeof getTableConfig>) {
	return Object.fromEntries(table.columns.map((c) => [c.name, c]));
}

describe('tenant schema — domains', () => {
	const t = getTableConfig(domains);
	const cols = columnMap(t);

	it('table is named domains', () => {
		expect(t.name).toBe('domains');
	});

	it('has the documented columns', () => {
		expect(Object.keys(cols).sort()).toEqual(
			[
				'added_at',
				'discovery_confidence',
				'discovery_signals',
				'domain',
				'fingerprint',
				'fingerprint_at',
				'is_candidate',
				'last_grade',
				'last_scanned_at',
				'last_score',
				'source',
				'watch',
				'watch_interval_hours',
			].sort(),
		);
	});

	it('domain is the primary key', () => {
		expect(cols.domain.primary).toBe(true);
		expect(cols.domain.notNull).toBe(true);
	});

	it('source and added_at are NOT NULL', () => {
		expect(cols.source.notNull).toBe(true);
		expect(cols.added_at.notNull).toBe(true);
	});

	it('watch defaults to true', () => {
		expect(cols.watch.dataType).toBe('boolean');
		expect(cols.watch.hasDefault).toBe(true);
	});

	it('discovery_confidence is REAL (number)', () => {
		expect(cols.discovery_confidence.dataType).toBe('number');
	});
});

describe('tenant schema — scans', () => {
	const t = getTableConfig(scans);
	const cols = columnMap(t);

	it('table is named scans', () => {
		expect(t.name).toBe('scans');
	});

	it('has the documented columns', () => {
		expect(Object.keys(cols).sort()).toEqual(
			[
				'cycle_id',
				'domain',
				'finding_count',
				'grade',
				'id',
				'maturity_stage',
				'result_json',
				'scan_at',
				'score',
			].sort(),
		);
	});

	it('id is the primary key', () => {
		expect(cols.id.primary).toBe(true);
	});

	it('domain and scan_at are NOT NULL', () => {
		expect(cols.domain.notNull).toBe(true);
		expect(cols.scan_at.notNull).toBe(true);
	});

	it('FK to domains(domain)', () => {
		expect(t.foreignKeys.length).toBeGreaterThan(0);
		const fk = t.foreignKeys[0].reference();
		expect(fk.foreignTable === domains).toBe(true);
	});

	it('declares idx_scans_domain_time on (domain, scan_at desc)', () => {
		const idx = t.indexes.find((i) => i.config.name === 'idx_scans_domain_time');
		expect(idx).toBeDefined();
	});

	it('declares idx_scans_cycle on cycle_id', () => {
		const idx = t.indexes.find((i) => i.config.name === 'idx_scans_cycle');
		expect(idx).toBeDefined();
	});

	it('declares UNIQUE idx_scans_cycle_domain_unique on (cycle_id, domain) — guards against queue-redelivery duplicate inserts', () => {
		const idx = t.indexes.find((i) => i.config.name === 'idx_scans_cycle_domain_unique');
		expect(idx).toBeDefined();
		expect(idx?.config.unique).toBe(true);
	});
});

describe('tenant schema — findings', () => {
	const t = getTableConfig(findings);
	const cols = columnMap(t);

	it('table is named findings', () => {
		expect(t.name).toBe('findings');
	});

	it('has the documented columns', () => {
		expect(Object.keys(cols).sort()).toEqual(
			['category', 'detail', 'domain', 'id', 'metadata', 'scan_id', 'severity', 'title'].sort(),
		);
	});

	it('id is the primary key', () => {
		expect(cols.id.primary).toBe(true);
	});

	it('NOT NULL columns: scan_id, domain, category, severity, title', () => {
		expect(cols.scan_id.notNull).toBe(true);
		expect(cols.domain.notNull).toBe(true);
		expect(cols.category.notNull).toBe(true);
		expect(cols.severity.notNull).toBe(true);
		expect(cols.title.notNull).toBe(true);
	});

	it('FK to scans(id)', () => {
		expect(t.foreignKeys.length).toBeGreaterThan(0);
		const fk = t.foreignKeys[0].reference();
		expect(fk.foreignTable === scans).toBe(true);
	});

	it('declares idx_findings_domain_severity', () => {
		const idx = t.indexes.find((i) => i.config.name === 'idx_findings_domain_severity');
		expect(idx).toBeDefined();
	});

	it('declares idx_findings_scan_id for cycle report and alert joins', () => {
		const idx = t.indexes.find((i) => i.config.name === 'idx_findings_scan_id');
		expect(idx).toBeDefined();
	});
});

describe('tenant schema — alerts', () => {
	const t = getTableConfig(alerts);
	const cols = columnMap(t);

	it('table is named alerts', () => {
		expect(t.name).toBe('alerts');
	});

	it('has the documented columns', () => {
		expect(Object.keys(cols).sort()).toEqual(
			['alert_type', 'delivered_at', 'delivered_to', 'detail', 'domain', 'id', 'resolved_at', 'triggered_at'].sort(),
		);
	});

	it('id is the primary key', () => {
		expect(cols.id.primary).toBe(true);
	});

	it('NOT NULL columns: domain, alert_type, triggered_at', () => {
		expect(cols.domain.notNull).toBe(true);
		expect(cols.alert_type.notNull).toBe(true);
		expect(cols.triggered_at.notNull).toBe(true);
	});

	it('declares idx_alerts_active partial index on triggered_at', () => {
		const idx = t.indexes.find((i) => i.config.name === 'idx_alerts_active');
		expect(idx).toBeDefined();
	});
});

describe('tenant schema — barrel re-exports', () => {
	it('src/tenants/db/index.ts re-exports both schemas', async () => {
		const mod = await import('../../../src/tenants/db');
		expect(mod.superTenants).toBeDefined();
		expect(mod.subTenants).toBeDefined();
		expect(mod.tenantKeys).toBeDefined();
		expect(mod.billingEvents).toBeDefined();
		expect(mod.domains).toBeDefined();
		expect(mod.scans).toBeDefined();
		expect(mod.findings).toBeDefined();
		expect(mod.alerts).toBeDefined();
	});
});
