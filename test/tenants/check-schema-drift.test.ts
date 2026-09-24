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
	COLUMNS_SQL,
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

describe('assertReadOnlySql', () => {
	it('accepts the two live-schema query constants', () => {
		expect(() => assertReadOnlySql(TABLES_AND_INDEXES_SQL)).not.toThrow();
		expect(() => assertReadOnlySql(COLUMNS_SQL)).not.toThrow();
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
		const runner = createWranglerRunner((database, configPath, sql) => {
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

describe('fetchLiveSchema', () => {
	it('splits the two query result sets into tables/indexes/columnsByTable', () => {
		const deps = {
			runWranglerQuery: (_database: string, _config: string, sql: string) => {
				if (sql === TABLES_AND_INDEXES_SQL) {
					return [
						{ type: 'table', name: 'sub_tenants' },
						{ type: 'index', name: 'idx_x' },
					];
				}
				return [{ tbl: 'sub_tenants', col: 'id' }];
			},
		};
		const live = fetchLiveSchema(deps, 'TENANT_REGISTRY_DB', 'wrangler.production.jsonc');
		expect(live.tables).toEqual(new Set(['sub_tenants']));
		expect(live.indexes).toEqual(new Set(['idx_x']));
		expect(live.columnsByTable.get('sub_tenants')).toEqual(new Set(['id']));
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
	liveByBinding: Record<string, { objects: unknown[]; columns: unknown[] }>;
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
		return sql === TABLES_AND_INDEXES_SQL ? live.objects : live.columns;
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
					columns: [
						{ tbl: 'sub_tenants', col: 'id' },
						{ tbl: 'sub_tenants', col: 'super_tenant_id' },
						{ tbl: 'sub_tenants', col: 'name' },
						{ tbl: 'sub_tenants', col: 'routing_mode' },
					],
				},
				TENANT_DB_PILOT_1: {
					objects: [
						{ type: 'table', name: 'findings' },
						{ type: 'index', name: 'idx_findings_domain' },
						{ type: 'index', name: 'idx_findings_scan_id' },
					],
					columns: [
						{ tbl: 'findings', col: 'id' },
						{ tbl: 'findings', col: 'scan_id' },
						{ tbl: 'findings', col: 'domain' },
					],
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
					columns: [
						{ tbl: 'sub_tenants', col: 'id' },
						{ tbl: 'sub_tenants', col: 'super_tenant_id' },
						{ tbl: 'sub_tenants', col: 'name' },
					],
				},
				TENANT_DB_PILOT_1: {
					objects: [{ type: 'table', name: 'findings' }, { type: 'index', name: 'idx_findings_domain' }],
					// idx_findings_scan_id not applied — mirrors the measured prod state.
					columns: [
						{ tbl: 'findings', col: 'id' },
						{ tbl: 'findings', col: 'scan_id' },
						{ tbl: 'findings', col: 'domain' },
					],
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
