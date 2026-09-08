// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { assessClientIpHeaders, clientIpHeaderAuditSql } from '../../scripts/audits/client-ip-header-audit.mjs';

describe('public client-IP header audit', () => {
	it('detects missing-header regressions using aggregate counts', () => {
		expect(assessClientIpHeaders({ total: 100, missing: 25 })).toMatchObject({ status: 'degraded', exitCode: 1, missingRatio: 0.25 });
		expect(assessClientIpHeaders({ total: 100, missing: 5 })).toMatchObject({ status: 'healthy', exitCode: 0 });
	});
	it.each([undefined, {}, { total: 0, missing: 0 }, { total: 10, missing: 0 }, { total: 20, missing: 21 }, { total: 20, missing: -1 }])(
		'never calls absent, sparse, or invalid observations healthy',
		(row) => {
			expect(assessClientIpHeaders(row)).toMatchObject({ status: 'unknown', exitCode: 2 });
		},
	);
	it('queries only public aggregate observations in a bounded window', () => {
		const sql = clientIpHeaderAuditSql(24);
		expect(sql).toContain("COALESCE(source, 'public') = 'public'");
		expect(sql).toContain("'-24 hours'");
		expect(sql).not.toMatch(/SELECT\s+\*/i);
	});
	it('executes against epoch-second timestamps and excludes internal/old rows', () => {
		const db = new DatabaseSync(':memory:');
		try {
			db.exec('CREATE TABLE mcp_access_log (created_at INTEGER, source TEXT, ip_masked TEXT)');
			const insert = db.prepare('INSERT INTO mcp_access_log VALUES (?, ?, ?)');
			const now = Math.floor(Date.now() / 1000);
			insert.run(now, 'public', 'no-cf-header');
			insert.run(now, null, 'masked');
			insert.run(now, 'internal', 'no-cf-header');
			insert.run(now - 7200, 'public', 'no-cf-header');
			expect({ ...db.prepare(clientIpHeaderAuditSql(1)).get() }).toEqual({ total: 2, missing: 1 });
		} finally {
			db.close();
		}
	});
	it.each([0, 169, NaN, 1.5, "1'); DELETE FROM mcp_access_log;--"])('rejects an invalid window', (hours) => {
		expect(() => clientIpHeaderAuditSql(hours as number)).toThrow();
	});
});
