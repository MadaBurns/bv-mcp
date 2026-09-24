// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for `scripts/tenants/check-schema-drift.mjs`.
 *
 * The script never statically imports `node:*` (mirrors provision-tenant.mjs),
 * so it is safe to import inside `@cloudflare/vitest-pool-workers`. Every
 * side-effecting operation funnels through an injected `deps` object — no
 * real wrangler calls, no real fs reads, no network. Fixtures are small
 * inline SQL strings styled on the real migration files' drizzle-kit output
 * shape (backtick identifiers, `--> statement-breakpoint` separators), not
 * the real files, so parsing coverage is decoupled from migration content.
 */

import { describe, it, expect } from 'vitest';
import {
	parseJsonc,
	classifyBinding,
	listD1Databases,
	deriveExpectedSchema,
	listSqlFiles,
	compareSchema,
	fetchLiveSchema,
	assertReadOnlySql,
	parseWranglerRows,
	createWranglerRunner,
	runSchemaDriftCheck,
	TABLES_AND_INDEXES_SQL,
	TABLE_NAME_RE,
	columnsSqlForTable,
	INTERNAL_TABLE_PREFIXES,
	isInternalTable,
} from '../../scripts/tenants/check-schema-drift.mjs';

const CREATE_SUB_TENANTS = [
	'CREATE TABLE `sub_tenants` (',
	'\t`id` text PRIMARY KEY NOT NULL,',
	'\t`super_tenant_id` text NOT NULL,',
	'\t`name` text NOT NULL,',
	'\tFOREIGN KEY (`super_tenant_id`) REFERENCES `super_tenants`(`id`) ON UPDATE no action ON DELETE no action',
	');',
].join('\n');

const CREATE_FINDINGS = [
	'CREATE TABLE `findings` (',
	'\t`id` text PRIMARY KEY NOT NULL,',
	'\t`scan_id` text NOT NULL,',
	'\t`domain` text NOT NULL',
	');',
	'--> statement-breakpoint',
	'CREATE INDEX `idx_findings_domain` ON `findings` (`domain`);',
].join('\n');

const ADD_ROUTING_MODE = "ALTER TABLE `sub_tenants` ADD `routing_mode` text DEFAULT 'convention';";

const ADD_SCAN_ID_INDEX = 'CREATE INDEX `idx_findings_scan_id` ON `findings` (`scan_id`);';

describe('parseJsonc', () => {
	it('strips // and /* */ comments outside strings and parses the remainder', () => {
		const source = ['{', '  // a comment', '  "a": 1,', '  "b": "http://not-a-comment" /* block */', '}'].join('\n');
		expect(parseJsonc(source)).toEqual({ a: 1, b: 'http://not-a-comment' });
	});
});

describe('classifyBinding', () => {
	it('maps TENANT_REGISTRY_DB to the registry migration set', () => {
		expect(classifyBinding('TENANT_REGISTRY_DB')).toBe('registry');
	});
	it('maps any TENANT_DB_* binding to the tenant migration set', () => {
		expect(classifyBinding('TENANT_DB_TENANT_PILOT_1')).toBe('tenant');
		expect(classifyBinding('TENANT_DB_ACME')).toBe('tenant');
	});
	it('returns null for a binding with no known migration source', () => {
		expect(classifyBinding('BRAND_AUDIT_DB')).toBeNull();
		expect(classifyBinding(undefined)).toBeNull();
	});
});

describe('listD1Databases', () => {
	it('returns the d1_databases array, or [] when absent', () => {
		expect(listD1Databases({ d1_databases: [{ binding: 'X' }] })).toEqual([{ binding: 'X' }]);
		expect(listD1Databases({})).toEqual([]);
		expect(listD1Databases(null)).toEqual([]);
	});
});

describe('applyMigrationSql / deriveExpectedSchema', () => {
	it('derives table columns from CREATE TABLE, skipping FOREIGN KEY constraint lines', () => {
		const schema = deriveExpectedSchema([CREATE_SUB_TENANTS]);
		expect(schema.tables.get('sub_tenants')).toEqual(new Set(['id', 'super_tenant_id', 'name']));
	});

	it('derives named indexes from CREATE INDEX, including a --> statement-breakpoint-separated one', () => {
		const schema = deriveExpectedSchema([CREATE_FINDINGS]);
		expect(schema.indexes.get('idx_findings_domain')).toBe('findings');
	});

	it('folds an ALTER TABLE ADD column into an existing table across migration files', () => {
		const schema = deriveExpectedSchema([CREATE_SUB_TENANTS, ADD_ROUTING_MODE]);
		expect(schema.tables.get('sub_tenants')?.has('routing_mode')).toBe(true);
	});

	it('folds a later migration file adding an index onto an earlier CREATE TABLE', () => {
		const schema = deriveExpectedSchema([CREATE_FINDINGS, ADD_SCAN_ID_INDEX]);
		expect(schema.indexes.get('idx_findings_scan_id')).toBe('findings');
	});

	it('is additive across an unparseable/unknown statement — never silently drops what it did parse', () => {
		const schema = deriveExpectedSchema([CREATE_SUB_TENANTS, '-- just a comment, not a recognized statement shape']);
		expect(schema.tables.get('sub_tenants')?.has('id')).toBe(true);
	});
});

describe('listSqlFiles', () => {
	it('lists only .sql files in lexicographic order, ignoring a meta/ dir entry', () => {
		const fakeFs = { readdirSync: () => ['0001_b.sql', 'meta', '0000_a.sql', 'README.md'] };
		expect(listSqlFiles(fakeFs, '/repo/migrations/tenant')).toEqual([
			'/repo/migrations/tenant/0000_a.sql',
			'/repo/migrations/tenant/0001_b.sql',
		]);
	});
});

describe('compareSchema', () => {
	it('reports no drift when live matches expected exactly', () => {
		const expected = deriveExpectedSchema([CREATE_SUB_TENANTS, ADD_ROUTING_MODE]);
		const live = {
			tables: new Set(['sub_tenants']),
			indexes: new Set(),
			columnsByTable: new Map([['sub_tenants', new Set(['id', 'super_tenant_id', 'name', 'routing_mode'])]]),
		};
		const result = compareSchema(expected, live);
		expect(result).toEqual({ ok: true, missingTables: [], missingColumns: [], missingIndexes: [] });
	});

	it('reports the exact production drift this ticket measured: missing routing_mode column', () => {
		const expected = deriveExpectedSchema([CREATE_SUB_TENANTS, ADD_ROUTING_MODE]);
		const live = {
			tables: new Set(['sub_tenants']),
			indexes: new Set(),
			// routing_mode never applied — mirrors the measured prod state.
			columnsByTable: new Map([['sub_tenants', new Set(['id', 'super_tenant_id', 'name'])]]),
		};
		const result = compareSchema(expected, live);
		expect(result.ok).toBe(false);
		expect(result.missingColumns).toEqual([{ table: 'sub_tenants', column: 'routing_mode' }]);
	});

	it('reports the exact production drift this ticket measured: missing idx_findings_scan_id index', () => {
		const expected = deriveExpectedSchema([CREATE_FINDINGS, ADD_SCAN_ID_INDEX]);
		const live = {
			tables: new Set(['findings']),
			// idx_findings_domain present (from the base migration), idx_findings_scan_id never applied.
			indexes: new Set(['idx_findings_domain']),
			columnsByTable: new Map([['findings', new Set(['id', 'scan_id', 'domain'])]]),
		};
		const result = compareSchema(expected, live);
		expect(result.ok).toBe(false);
		expect(result.missingIndexes).toEqual([{ name: 'idx_findings_scan_id', table: 'findings' }]);
	});

	it('does not flag a missing column for a table that does not exist live — only the table itself', () => {
		const expected = deriveExpectedSchema([CREATE_SUB_TENANTS]);
		const live = { tables: new Set(), indexes: new Set(), columnsByTable: new Map() };
		const result = compareSchema(expected, live);
		expect(result.missingTables).toEqual(['sub_tenants']);
		expect(result.missingColumns).toEqual([]);
	});

	it('does not flag an extra live object (e.g. _cf_KV) that is outside the migration set', () => {
		const expected = deriveExpectedSchema([CREATE_SUB_TENANTS]);
		const live = {
			tables: new Set(['sub_tenants', '_cf_KV']),
			indexes: new Set(),
			columnsByTable: new Map([['sub_tenants', new Set(['id', 'super_tenant_id', 'name'])]]),
		};
		expect(compareSchema(expected, live).ok).toBe(true);
	});
});

describe('columnsSqlForTable', () => {
	it('pins the exact per-table pragma_table_info query shape', () => {
		expect(columnsSqlForTable('sub_tenants')).toBe("SELECT name FROM pragma_table_info('sub_tenants')");
		expect(columnsSqlForTable('findings')).toBe("SELECT name FROM pragma_table_info('findings')");
	});

	it('rejects a table name that is not a bare identifier — including an attempt to smuggle in the old join form', () => {
		// The join form this checker used to run against sqlite_master + pragma_table_info(m.name) —
		// D1 measured-refuses it (SQLITE_AUTH); this function must never be able to build it either.
		expect(() => columnsSqlForTable("m WHERE m.type = 'table'")).toThrow(/unsafe table name/);
		expect(() => columnsSqlForTable('sub_tenants JOIN other')).toThrow(/unsafe table name/);
		expect(() => columnsSqlForTable("sub_tenants'); DROP TABLE x; --")).toThrow(/unsafe table name/);
		expect(() => columnsSqlForTable('')).toThrow(/unsafe table name/);
		expect(() => columnsSqlForTable(undefined)).toThrow(/unsafe table name/);
	});

	it('TABLE_NAME_RE accepts only bare identifiers', () => {
		const bareIdentifiers = ['sub_tenants', '_private1'];
		const unsafeNames = ['sub tenants', "sub_tenants'", '1table'];
		for (const name of bareIdentifiers) expect(TABLE_NAME_RE.test(name)).toBe(true);
		for (const name of unsafeNames) expect(TABLE_NAME_RE.test(name)).toBe(false);
	});
});

describe('assertReadOnlySql', () => {
	it('accepts the live-schema query constants, including a per-table columns query', () => {
		expect(() => assertReadOnlySql(TABLES_AND_INDEXES_SQL)).not.toThrow();
		expect(() => assertReadOnlySql(columnsSqlForTable('sub_tenants'))).not.toThrow();
	});

	it('rejects DDL', () => {
		expect(() => assertReadOnlySql("ALTER TABLE sub_tenants ADD routing_mode text DEFAULT 'convention'")).toThrow();
		expect(() => assertReadOnlySql('CREATE INDEX idx_x ON findings (scan_id)')).toThrow();
		expect(() => assertReadOnlySql('DROP TABLE findings')).toThrow();
	});

	it('rejects mutating statements and a non-SELECT statement', () => {
		expect(() => assertReadOnlySql("INSERT INTO sub_tenants (id) VALUES ('x')")).toThrow();
		expect(() => assertReadOnlySql('UPDATE sub_tenants SET routing_mode = 1')).toThrow();
		expect(() => assertReadOnlySql('DELETE FROM sub_tenants')).toThrow();
		expect(() => assertReadOnlySql('not sql at all')).toThrow();
	});
});

describe('parseWranglerRows', () => {
	it('extracts results from a successful wrangler --json response', () => {
		const output = JSON.stringify([{ success: true, results: [{ a: 1 }] }]);
		expect(parseWranglerRows(output)).toEqual([{ a: 1 }]);
	});

	it('throws on an unrecognized shape', () => {
		expect(() => parseWranglerRows(JSON.stringify({ nope: true }))).toThrow();
	});
});

describe('createWranglerRunner', () => {
	it('routes every query through assertReadOnlySql before the injected exec function', () => {
		const calls: string[] = [];
		const runner = createWranglerRunner((database: string, configPath: string, sql: string) => {
			calls.push(sql);
			return JSON.stringify([{ success: true, results: [{ ok: 1 }] }]);
		});
		expect(runner('TENANT_REGISTRY_DB', 'wrangler.production.jsonc', TABLES_AND_INDEXES_SQL)).toEqual([{ ok: 1 }]);
		expect(calls).toEqual([TABLES_AND_INDEXES_SQL]);
	});

	it('never reaches the injected exec function for a DDL statement', () => {
		const runner = createWranglerRunner(() => {
			throw new Error('exec should never be called for DDL');
		});
		expect(() => runner('TENANT_REGISTRY_DB', 'wrangler.production.jsonc', 'DROP TABLE sub_tenants')).toThrow(
			/refusing/,
		);
	});
});

describe('isInternalTable', () => {
	it('flags Cloudflare/SQLite-internal bookkeeping tables by prefix', () => {
		expect(INTERNAL_TABLE_PREFIXES).toEqual(['_cf_', 'sqlite_']);
		expect(isInternalTable('_cf_KV')).toBe(true);
		expect(isInternalTable('sqlite_sequence')).toBe(true);
		expect(isInternalTable('sub_tenants')).toBe(false);
		expect(isInternalTable('findings')).toBe(false);
	});
});

describe('fetchLiveSchema', () => {
	it('skips a Cloudflare-internal table (e.g. _cf_KV): issues no column query for it and omits it from the returned tables', () => {
		const calls: string[] = [];
		const deps = {
			runWranglerQuery: (_database: string, _config: string, sql: string) => {
				calls.push(sql);
				if (sql === TABLES_AND_INDEXES_SQL) {
					return [
						{ type: 'table', name: '_cf_KV' },
						{ type: 'table', name: 'sub_tenants' },
					];
				}
				// D1 refuses pragma_table_info('_cf_KV') with SQLITE_AUTH — if fetchLiveSchema
				// ever stops skipping internal tables, this mock throws instead of the real
				// query result masking the regression.
				if (sql === columnsSqlForTable('_cf_KV')) throw new Error('must never query columns for an internal table');
				if (sql === columnsSqlForTable('sub_tenants')) return [{ name: 'id' }];
				throw new Error(`unexpected query shape: ${sql}`);
			},
		};
		const live = fetchLiveSchema(deps, 'TENANT_REGISTRY_DB', 'wrangler.production.jsonc');
		expect(live.tables).toEqual(new Set(['sub_tenants']));
		expect(live.tables.has('_cf_KV')).toBe(false);
		expect(calls).toEqual([TABLES_AND_INDEXES_SQL, "SELECT name FROM pragma_table_info('sub_tenants')"]);
	});

	it('fetches tables/indexes with one query, then issues one literal per-table pragma_table_info query for columns — never the join form', () => {
		const calls: string[] = [];
		const deps = {
			runWranglerQuery: (_database: string, _config: string, sql: string) => {
				calls.push(sql);
				if (sql === TABLES_AND_INDEXES_SQL) {
					return [
						{ type: 'table', name: 'sub_tenants' },
						{ type: 'table', name: 'super_tenants' },
						{ type: 'index', name: 'idx_x' },
					];
				}
				// A mock that only understands the two known literal per-table queries: any
				// join-style query (the form D1 measured-refuses) falls through and throws,
				// so this test fails if fetchLiveSchema ever reverts to a joined query.
				if (sql === columnsSqlForTable('sub_tenants')) return [{ name: 'id' }, { name: 'routing_mode' }];
				if (sql === columnsSqlForTable('super_tenants')) return [{ name: 'id' }];
				throw new Error(`unexpected query shape (not a literal per-table pragma_table_info select): ${sql}`);
			},
		};
		const live = fetchLiveSchema(deps, 'TENANT_REGISTRY_DB', 'wrangler.production.jsonc');
		expect(live.tables).toEqual(new Set(['sub_tenants', 'super_tenants']));
		expect(live.indexes).toEqual(new Set(['idx_x']));
		expect(live.columnsByTable.get('sub_tenants')).toEqual(new Set(['id', 'routing_mode']));
		expect(live.columnsByTable.get('super_tenants')).toEqual(new Set(['id']));
		expect(calls).toEqual([
			TABLES_AND_INDEXES_SQL,
			"SELECT name FROM pragma_table_info('sub_tenants')",
			"SELECT name FROM pragma_table_info('super_tenants')",
		]);
	});
});

// ---- full orchestration, fixture-only (no network) ----------------------------

function makeConfig(bindings: string[]) {
	return JSON.stringify({
		d1_databases: bindings.map((binding) => ({ binding, database_name: `${binding.toLowerCase()}-db` })),
	});
}

function makeOrchestrationDeps(opts: {
	config: string;
	migrationFiles: Record<'registry' | 'tenant', Record<string, string>>;
	liveByBinding: Record<string, { objects: unknown[]; columnsByTable: Record<string, unknown[]> }>;
}) {
	const stdout: string[] = [];
	const stderr: string[] = [];
	const fs = {
		readFileSync: (p: string, _enc: string) => {
			if (p === 'wrangler.production.jsonc') return opts.config;
			for (const set of ['registry', 'tenant'] as const) {
				const dir = `/repo/migrations/${set}`;
				if (p.startsWith(dir + '/')) {
					const name = p.slice(dir.length + 1);
					const text = opts.migrationFiles[set][name];
					if (text !== undefined) return text;
				}
			}
			throw new Error(`unmocked read: ${p}`);
		},
		readdirSync: (dir: string) => {
			for (const set of ['registry', 'tenant'] as const) {
				if (dir === `/repo/migrations/${set}`) return Object.keys(opts.migrationFiles[set]).sort();
			}
			throw new Error(`unmocked readdir: ${dir}`);
		},
	};
	const runWranglerQuery = (database: string, _config: string, sql: string) => {
		const live = opts.liveByBinding[database];
		if (!live) throw new Error(`unexpected binding ${database}`);
		if (sql === TABLES_AND_INDEXES_SQL) return live.objects;
		// Only a literal single-table pragma_table_info query is understood — the join form
		// this checker used to run (and D1 measured-refuses) has no match here and throws,
		// so a regression back to it fails every orchestration test below.
		const match = /^SELECT name FROM pragma_table_info\('([A-Za-z_][A-Za-z0-9_]*)'\)$/.exec(sql);
		if (match) return live.columnsByTable[match[1]] ?? [];
		throw new Error(`unexpected query shape: ${sql}`);
	};
	return {
		deps: {
			fs,
			runWranglerQuery,
			migrationsDir: { registry: '/repo/migrations/registry', tenant: '/repo/migrations/tenant' },
			stdout: (s: string) => stdout.push(s),
			stderr: (s: string) => stderr.push(s),
		},
		stdout,
		stderr,
	};
}

describe('runSchemaDriftCheck — full orchestration against fixtures', () => {
	const migrationFiles = {
		registry: { '0000_a.sql': CREATE_SUB_TENANTS, '0001_b.sql': ADD_ROUTING_MODE },
		tenant: { '0000_a.sql': CREATE_FINDINGS, '0001_b.sql': ADD_SCAN_ID_INDEX },
	};

	it('exits 0 and reports OK when every checked database matches its migrations', () => {
		const { deps, stdout } = makeOrchestrationDeps({
			config: makeConfig(['TENANT_REGISTRY_DB', 'TENANT_DB_PILOT_1']),
			migrationFiles,
			liveByBinding: {
				TENANT_REGISTRY_DB: {
					objects: [{ type: 'table', name: 'sub_tenants' }],
					columnsByTable: {
						sub_tenants: [{ name: 'id' }, { name: 'super_tenant_id' }, { name: 'name' }, { name: 'routing_mode' }],
					},
				},
				TENANT_DB_PILOT_1: {
					objects: [
						{ type: 'table', name: 'findings' },
						{ type: 'index', name: 'idx_findings_domain' },
						{ type: 'index', name: 'idx_findings_scan_id' },
					],
					columnsByTable: {
						findings: [{ name: 'id' }, { name: 'scan_id' }, { name: 'domain' }],
					},
				},
			},
		});

		const code = runSchemaDriftCheck({ config: 'wrangler.production.jsonc' }, deps);
		expect(code).toBe(0);
		expect(stdout.join('')).toContain('OK — matches registry migrations');
		expect(stdout.join('')).toContain('OK — matches tenant migrations');
	});

	it('exits 1 and names each missing object when a DB is missing its migrations, and skips unknown bindings', () => {
		const { deps, stdout } = makeOrchestrationDeps({
			config: makeConfig(['TENANT_REGISTRY_DB', 'TENANT_DB_PILOT_1', 'BRAND_AUDIT_DB']),
			migrationFiles,
			liveByBinding: {
				TENANT_REGISTRY_DB: {
					objects: [{ type: 'table', name: 'sub_tenants' }],
					// routing_mode not applied — mirrors the measured prod state.
					columnsByTable: {
						sub_tenants: [{ name: 'id' }, { name: 'super_tenant_id' }, { name: 'name' }],
					},
				},
				TENANT_DB_PILOT_1: {
					objects: [{ type: 'table', name: 'findings' }, { type: 'index', name: 'idx_findings_domain' }],
					// idx_findings_scan_id not applied — mirrors the measured prod state.
					columnsByTable: {
						findings: [{ name: 'id' }, { name: 'scan_id' }, { name: 'domain' }],
					},
				},
			},
		});

		const code = runSchemaDriftCheck({ config: 'wrangler.production.jsonc' }, deps);
		const report = stdout.join('');
		expect(code).toBe(1);
		expect(report).toContain('skip BRAND_AUDIT_DB: no known migration source');
		expect(report).toContain('MISSING COLUMN: sub_tenants.routing_mode');
		expect(report).toContain('MISSING INDEX: idx_findings_scan_id (on table findings)');
	});

	it('exits 0 with a note when no bindings in the config have a known migration source', () => {
		const { deps, stdout } = makeOrchestrationDeps({
			config: makeConfig(['BRAND_AUDIT_DB']),
			migrationFiles,
			liveByBinding: {},
		});
		const code = runSchemaDriftCheck({ config: 'wrangler.production.jsonc' }, deps);
		expect(code).toBe(0);
		expect(stdout.join('')).toContain('nothing to check');
	});

	it('exits 2 when the config file cannot be read', () => {
		const deps = {
			fs: {
				readFileSync: () => {
					throw new Error('ENOENT');
				},
				readdirSync: () => [],
			},
			runWranglerQuery: () => [],
			migrationsDir: { registry: '/repo/migrations/registry', tenant: '/repo/migrations/tenant' },
			stdout: () => {},
			stderr: () => {},
		};
		const code = runSchemaDriftCheck({ config: 'wrangler.production.jsonc' }, deps);
		expect(code).toBe(2);
	});

	it('exits 2 when the config file is not valid JSONC', () => {
		const deps = {
			fs: {
				readFileSync: () => '{ not valid json',
				readdirSync: () => [],
			},
			runWranglerQuery: () => [],
			migrationsDir: { registry: '/repo/migrations/registry', tenant: '/repo/migrations/tenant' },
			stdout: () => {},
			stderr: () => {},
		};
		const code = runSchemaDriftCheck({ config: 'wrangler.production.jsonc' }, deps);
		expect(code).toBe(2);
	});

	it('exits 1 and reports the failure when a live query throws (e.g. wrangler/auth failure)', () => {
		const { deps, stderr } = makeOrchestrationDeps({
			config: makeConfig(['TENANT_REGISTRY_DB']),
			migrationFiles,
			liveByBinding: {},
		});
		deps.runWranglerQuery = () => {
			throw new Error('wrangler auth error');
		};
		const code = runSchemaDriftCheck({ config: 'wrangler.production.jsonc' }, deps);
		expect(code).toBe(1);
		expect(stderr.join('')).toContain('failed to query live schema');
	});
});
