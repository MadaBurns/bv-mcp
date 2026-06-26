// test/audits/access-log-migration.audit.test.ts
import { describe, expect, it } from 'vitest';

const sqlFiles = import.meta.glob('../../scripts/intelligence/sql/0002_mcp_access_log_enrich.sql', {
	query: '?raw', import: 'default', eager: true,
}) as Record<string, string>;
const sql = Object.values(sqlFiles)[0] ?? '';

const EXPECTED_COLUMNS = [
	'city', 'region', 'latitude', 'longitude', 'asn', 'as_org', 'ptr_hostname',
	'key_hash', 'client_type', 'colo', 'session_hash', 'method', 'transport', 'status',
];

describe('0002 access-log enrich migration', () => {
	it('adds every enrichment column', () => {
		for (const col of EXPECTED_COLUMNS) {
			expect(sql).toMatch(new RegExp(`ADD COLUMN ${col}\\b`));
		}
	});
	it('adds the report-dimension indexes', () => {
		expect(sql).toContain('idx_mcp_access_log_key_created');
		expect(sql).toContain('idx_mcp_access_log_country');
	});
	it('creates the forensics audit table in INTELLIGENCE_DB (not the tenants registry)', () => {
		expect(sql).toMatch(/CREATE TABLE IF NOT EXISTS mcp_access_log_audit\b/);
		expect(sql).toContain('idx_mcp_access_log_audit_created');
	});
});
