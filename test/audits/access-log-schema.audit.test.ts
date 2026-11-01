// SPDX-License-Identifier: BUSL-1.1
//
// SQ-187: the access-log column contract (scripts/access-log/columns.mjs) is a hand-kept copy of what the
// Worker writes, read by the deploy preflight and the operator copy script under bare node. These audits pin
// it to the Worker's real insert SQL and pin the new-database baseline to the live schema it reproduces.
import { describe, expect, it } from 'vitest';

import { ACCESS_LOG_AUDIT_COLUMNS, ACCESS_LOG_COLUMNS, ACCESS_LOG_INSERT_COLUMNS } from '../../scripts/access-log/columns.mjs';
import internalSource from '../../src/internal.ts?raw';

const baselineFiles = import.meta.glob('../../scripts/access-log/sql/0001_baseline.sql', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;
const baseline = Object.values(baselineFiles)[0] ?? '';

const dropFiles = import.meta.glob('../../scripts/access-log/sql/0002_drop_unused_indexes.sql', {
	query: '?raw',
	import: 'default',
	eager: true,
}) as Record<string, string>;
const dropMigration = Object.values(dropFiles)[0] ?? '';

/** The live index set recorded from bv-intelligence (SQ-183 plan section 2). */
const LIVE_INDEXES = [
	'idx_mcp_access_log_country',
	'idx_mcp_access_log_created',
	'idx_mcp_access_log_domain',
	'idx_mcp_access_log_ip_hash',
	'idx_mcp_access_log_ip_masked',
	'idx_mcp_access_log_key_created',
	'idx_mcp_access_log_audit_created',
];

describe('access-log column contract lockstep', () => {
	it('mirrors ACCESS_LOG_COLUMNS in src/mcp/execute.ts, in order', async () => {
		const { accessLogInsertSql } = await import('../../src/mcp/execute');
		const match = accessLogInsertSql().match(/^INSERT INTO mcp_access_log \(([^)]*)\) VALUES \(([^)]*)\)$/);
		expect(match, 'accessLogInsertSql() shape changed; update this audit and scripts/access-log/columns.mjs together').not.toBeNull();
		const columns = match![1].split(',').map((column) => column.trim());
		expect([...ACCESS_LOG_INSERT_COLUMNS]).toEqual(columns);
		expect(match![2].split(',')).toHaveLength(columns.length);
		expect([...ACCESS_LOG_COLUMNS]).toEqual(['id', 'created_at', ...columns]);
	});

	it('covers every column the forensics and erase routes write to mcp_access_log_audit', () => {
		const inserts = [...internalSource.matchAll(/INSERT INTO mcp_access_log_audit \(([^)]*)\)/g)];
		expect(inserts.length, 'src/internal.ts no longer writes mcp_access_log_audit where this audit expects').toBeGreaterThan(0);
		for (const [, list] of inserts) {
			const written = list.split(',').map((column) => column.trim());
			expect(written.filter((column) => !ACCESS_LOG_AUDIT_COLUMNS.includes(column))).toEqual([]);
		}
	});
});

describe('scripts/access-log/sql/0001_baseline.sql reproduces the live schema', () => {
	it('names its target binding and database', () => {
		expect(baseline).toContain('Target binding: INTELLIGENCE_DB');
		expect(baseline).toContain('mcp-access-log-v1');
	});

	it('keeps the live NOT NULL on ip_masked that the repo migration chain dropped', () => {
		expect(baseline).toContain('ip_masked TEXT NOT NULL');
	});

	it('creates exactly the seven live indexes', () => {
		const created = [...baseline.matchAll(/CREATE INDEX (\w+)/g)].map((match) => match[1]);
		expect(created.sort()).toEqual([...LIVE_INDEXES].sort());
	});

	it('declares every contract column in its table', () => {
		const table = (name: string) => baseline.match(new RegExp(`CREATE TABLE ${name} \\(([\\s\\S]*?)\\);`))?.[1] ?? '';
		for (const column of ACCESS_LOG_COLUMNS) expect(table('mcp_access_log')).toMatch(new RegExp(`\\b${column} [A-Z]`));
		for (const column of ACCESS_LOG_AUDIT_COLUMNS) expect(table('mcp_access_log_audit')).toMatch(new RegExp(`\\b${column} [A-Z]`));
	});

	it('is a plain baseline: no IF NOT EXISTS, no rollup table', () => {
		const statements = baseline.replace(/^--.*$/gm, '');
		expect(statements).not.toMatch(/IF NOT EXISTS/i);
		expect(statements).not.toContain('mcp_access_rollup');
	});
});

describe('scripts/access-log/sql/0002_drop_unused_indexes.sql (SQ-500)', () => {
	const statements = dropMigration.replace(/^--.*$/gm, '');
	const dropped = [...statements.matchAll(/DROP INDEX IF EXISTS (\w+);/g)].map((match) => match[1]);

	it('drops exactly the three indexes no query uses, idempotently', () => {
		expect(dropped.sort()).toEqual(['idx_mcp_access_log_country', 'idx_mcp_access_log_domain', 'idx_mcp_access_log_ip_masked']);
		// Anything but an idempotent DROP INDEX would make a re-run fail or change data.
		expect(statements.replace(/DROP INDEX IF EXISTS \w+;/g, '').trim()).toBe('');
	});

	it('only drops indexes the baseline creates, and keeps the ones the retention/usage/forensics/erase queries need', () => {
		const baselineIndexes = [...baseline.matchAll(/CREATE INDEX (\w+)/g)].map((match) => match[1]);
		for (const name of dropped) expect(baselineIndexes).toContain(name);
		const kept = baselineIndexes.filter((name) => !dropped.includes(name)).sort();
		expect(kept).toEqual(['idx_mcp_access_log_audit_created', 'idx_mcp_access_log_created', 'idx_mcp_access_log_ip_hash', 'idx_mcp_access_log_key_created']);
	});

	it('no mcp_access_log statement in src/internal.ts filters on a dropped index column', () => {
		// The reader audit this migration rests on: no mcp_access_log statement in the Worker filters on
		// country, domain or ip_masked. A new WHERE on one of them must bring its index back first.
		expect(internalSource).not.toMatch(/FROM mcp_access_log[^`]*WHERE[^`]*\b(country|domain|ip_masked)\s*(=|IN|LIKE)/i);
	});
});
