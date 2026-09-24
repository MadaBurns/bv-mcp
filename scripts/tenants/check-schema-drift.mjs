#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

/**
 * scripts/tenants/check-schema-drift.mjs
 *
 * Read-only drift checker: for the registry D1 and every per-tenant D1 listed
 * in a wrangler production config, compares the schema derived from the raw
 * SQL migration files under `src/tenants/db/migrations/{registry,tenant}/`
 * against the LIVE schema (`sqlite_master` + `pragma_table_info`). Migrations
 * here are applied as raw SQL files by `provision-tenant.mjs` at provisioning
 * time — there is no `d1_migrations` / `__drizzle_migrations` ledger, so
 * nothing else re-checks what a live database actually has.
 *
 * This script only ever runs SELECT against `sqlite_master` / the
 * `pragma_table_info` table-valued function — see `assertReadOnlySql` below,
 * which every query is routed through before it can reach `wrangler d1
 * execute`. It NEVER executes DDL and never applies a migration.
 *
 * Why raw SQL files instead of the drizzle `meta/*_snapshot.json` files: the
 * tenant migration set's `meta/_journal.json` only has entries for
 * 0000/0001 — `0002_findings_scan_id_index.sql` exists on disk with no
 * matching snapshot/journal entry, so deriving the expected schema from meta
 * snapshots would silently miss exactly the drift this checker exists to
 * catch. The raw `.sql` files are the actual migration set of record (they're
 * what `provision-tenant.mjs` applies), so they're parsed directly instead.
 *
 * Only bindings this script knows how to derive an expected schema for are
 * checked: `TENANT_REGISTRY_DB` (registry migrations) and any `TENANT_DB_*`
 * binding (tenant migrations). Other D1 bindings (e.g. `BRAND_AUDIT_DB`,
 * which is hand-schema'd via `src/lib/db/brand-audit-schema.ts`, not this
 * migrations directory) are reported as skipped, not silently ignored.
 *
 * Usage:
 *   node scripts/tenants/check-schema-drift.mjs [--config wrangler.production.jsonc]
 *   npm run check:tenant-schema
 *
 * Exit codes:
 *   0 — every checked database matches its migrations (or nothing to check)
 *   1 — at least one table/column/index is missing, or a live query failed
 *   2 — usage/config error (config file missing or unparsable)
 *
 * Test surface: every side-effecting operation funnels through an injected
 * `deps` object (`deps.fs`, `deps.runWranglerQuery`, `deps.stdout/stderr`) —
 * see `test/tenants/check-schema-drift.test.ts`, which exercises the pure
 * parsing/comparison functions plus the full orchestration against fixtures,
 * no network. We avoid static `import`s from `node:*` (mirrors
 * `provision-tenant.mjs`) so this module stays importable under
 * `@cloudflare/vitest-pool-workers`, which has no Node built-ins; the CLI
 * bootstrap at the bottom dynamic-imports them only when run directly.
 */

// -- JSONC config parsing -------------------------------------------------------

/**
 * Strip JSONC comments (// line + /* block) outside string literals, then
 * JSON.parse. Byte-for-byte copy of `parseJsonc` in
 * `scripts/inject-private-config.cjs` — that file is CommonJS and this script
 * must stay a plain-node-importable ESM module (see file header), so it can't
 * be `require()`d from here. Keep both in sync if either changes.
 */
export function parseJsonc(source) {
	let out = '';
	let i = 0;
	let inString = false;
	let stringQuote = '';
	while (i < source.length) {
		const ch = source[i];
		const next = source[i + 1];
		if (inString) {
			out += ch;
			if (ch === '\\' && i + 1 < source.length) {
				out += source[i + 1];
				i += 2;
				continue;
			}
			if (ch === stringQuote) {
				inString = false;
			}
			i += 1;
			continue;
		}
		if (ch === '"' || ch === "'") {
			inString = true;
			stringQuote = ch;
			out += ch;
			i += 1;
			continue;
		}
		if (ch === '/' && next === '/') {
			while (i < source.length && source[i] !== '\n') i += 1;
			continue;
		}
		if (ch === '/' && next === '*') {
			i += 2;
			while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) i += 1;
			i += 2;
			continue;
		}
		out += ch;
		i += 1;
	}
	return JSON.parse(out);
}

// -- binding classification -----------------------------------------------------

const TENANT_BINDING_PREFIX = 'TENANT_DB_';

/** Which migration set (if any) a D1 binding's expected schema is derived from. */
export function classifyBinding(binding) {
	if (binding === 'TENANT_REGISTRY_DB') return 'registry';
	if (typeof binding === 'string' && binding.startsWith(TENANT_BINDING_PREFIX)) return 'tenant';
	return null;
}

/** Pull the `d1_databases` array out of a parsed wrangler config (empty if absent). */
export function listD1Databases(config) {
	return Array.isArray(config?.d1_databases) ? config.d1_databases : [];
}

// -- migration SQL -> expected schema --------------------------------------------

/**
 * Fold the DDL statements in one migration file's text into `schema`
 * (mutated in place, also returned). Handles the three statement shapes
 * drizzle-kit emits for this project's migrations, each on its own
 * `--> statement-breakpoint`-delimited chunk:
 *   CREATE TABLE `t` (\n\t`col` type ...,\n\tFOREIGN KEY (...) ...\n);
 *   CREATE [UNIQUE] INDEX `idx` ON `t` (`col`[,`col2`]) [WHERE ...];
 *   ALTER TABLE `t` ADD `col` type ...;
 * Column/constraint lines inside a CREATE TABLE body are one per source line;
 * only lines starting with a backtick-quoted identifier are columns (a
 * `FOREIGN KEY (...)` constraint line is not). Anything unrecognized is
 * skipped rather than guessed — an unparsed statement can only ever cause
 * this checker to under-report drift for that specific column/index, never
 * to falsely certify one as present, since results are additive.
 */
export function applyMigrationSql(schema, sqlText) {
	const statements = sqlText
		.split('--> statement-breakpoint')
		.map((s) => s.trim())
		.filter(Boolean);
	for (const stmt of statements) {
		const createTable = stmt.match(/^CREATE TABLE `([a-zA-Z0-9_]+)`\s*\(([\s\S]*)\)\s*;?\s*$/i);
		if (createTable) {
			const [, tableName, body] = createTable;
			const cols = schema.tables.get(tableName) ?? new Set();
			for (const rawLine of body.split('\n')) {
				const colMatch = rawLine.trim().match(/^`([a-zA-Z0-9_]+)`/);
				if (colMatch) cols.add(colMatch[1]);
			}
			schema.tables.set(tableName, cols);
			continue;
		}
		const createIndex = stmt.match(/^CREATE\s+(?:UNIQUE\s+)?INDEX\s+`([a-zA-Z0-9_]+)`\s+ON\s+`([a-zA-Z0-9_]+)`/i);
		if (createIndex) {
			const [, indexName, tableName] = createIndex;
			schema.indexes.set(indexName, tableName);
			continue;
		}
		const alterAdd = stmt.match(/^ALTER TABLE `([a-zA-Z0-9_]+)`\s+ADD\s+`([a-zA-Z0-9_]+)`/i);
		if (alterAdd) {
			const [, tableName, colName] = alterAdd;
			const cols = schema.tables.get(tableName) ?? new Set();
			cols.add(colName);
			schema.tables.set(tableName, cols);
			continue;
		}
	}
	return schema;
}

/** Fold an ordered list of migration file texts into one expected schema. */
export function deriveExpectedSchema(sqlTexts) {
	const schema = { tables: new Map(), indexes: new Map() };
	for (const text of sqlTexts) applyMigrationSql(schema, text);
	return schema;
}

/** List `.sql` files in a migrations dir, lexicographic order (mirrors `listMigrationFiles` in provision-tenant.mjs). */
export function listSqlFiles(fs, dir) {
	return fs
		.readdirSync(dir)
		.filter((name) => name.endsWith('.sql'))
		.sort()
		.map((name) => `${dir}/${name}`);
}

// -- live schema fetch (read-only) -----------------------------------------------

// Only ever SELECT against sqlite_master / the pragma_table_info table-valued
// function. D1 refuses a correlated join of `pragma_table_info(m.name)`
// against `sqlite_master` ("not authorized: SQLITE_AUTH [code: 7500]" —
// measured directly against production 2026-09-24), so column introspection
// cannot pull every table's columns in one query. Instead it runs one literal
// `SELECT name FROM pragma_table_info('<table>')` per table, built by
// `columnsSqlForTable` below, which refuses to interpolate anything that
// isn't a bare SQL identifier.
export const TABLES_AND_INDEXES_SQL = "SELECT type, name, tbl_name FROM sqlite_master WHERE type IN ('table','index')";

/** A bare SQL identifier: what `columnsSqlForTable` requires before interpolating a table name into SQL text. */
export const TABLE_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Build the literal per-table column-introspection query for `table`. Throws
 * if `table` isn't a bare identifier matching `TABLE_NAME_RE` — this is the
 * only thing standing between a live table name and string interpolation
 * into SQL text, so it must reject anything that could smuggle in a join,
 * a second statement, or any other SQL syntax.
 */
export function columnsSqlForTable(table) {
	if (typeof table !== 'string' || !TABLE_NAME_RE.test(table)) {
		throw new Error(`refusing to build a columns query for an unsafe table name: ${JSON.stringify(table)}`);
	}
	return `SELECT name FROM pragma_table_info('${table}')`;
}

const DDL_KEYWORDS = /\b(CREATE|ALTER|DROP|INSERT|UPDATE|DELETE|REPLACE|ATTACH|DETACH|PRAGMA(?!_table_info\())\b/i;

/**
 * Refuse anything that isn't a bare read-only SELECT. Every query this
 * checker issues is one of the two constants above, but every query is
 * still routed through this guard before reaching `wrangler d1 execute` —
 * defense in depth against ever executing DDL, and directly unit-testable.
 */
export function assertReadOnlySql(sql) {
	if (typeof sql !== 'string' || !/^\s*SELECT\b/i.test(sql)) {
		throw new Error('refusing to run non-SELECT SQL against a live database');
	}
	if (DDL_KEYWORDS.test(sql)) {
		throw new Error('refusing SQL that contains a DDL/mutation keyword');
	}
}

/** Parse `wrangler d1 execute --json` stdout into the single statement's result rows. */
export function parseWranglerRows(output) {
	const parsed = JSON.parse(output);
	if (Array.isArray(parsed) && parsed.length >= 1 && parsed[0]?.success === true) {
		return Array.isArray(parsed[0].results) ? parsed[0].results : [];
	}
	throw new Error('unexpected wrangler d1 execute --json output shape');
}

/** Compose a low-level exec function into a guarded, parsed query runner. */
export function createWranglerRunner(execWrangler) {
	return (database, configPath, sql) => {
		assertReadOnlySql(sql);
		return parseWranglerRows(execWrangler(database, configPath, sql));
	};
}

/**
 * Fetch the live tables/indexes/columns for one D1 database. Tables and
 * indexes come from one `sqlite_master` query; columns are fetched with one
 * `pragma_table_info` query per live table (see `columnsSqlForTable` above —
 * D1 refuses the single-query join form).
 */
export function fetchLiveSchema(deps, database, configPath) {
	const objRows = deps.runWranglerQuery(database, configPath, TABLES_AND_INDEXES_SQL);
	const tables = new Set();
	const indexes = new Set();
	for (const row of objRows) {
		if (row.type === 'table') tables.add(row.name);
		else if (row.type === 'index') indexes.add(row.name);
	}
	const columnsByTable = new Map();
	for (const table of tables) {
		const colRows = deps.runWranglerQuery(database, configPath, columnsSqlForTable(table));
		const cols = new Set();
		for (const row of colRows) cols.add(row.name);
		columnsByTable.set(table, cols);
	}
	return { tables, indexes, columnsByTable };
}

// -- comparison -------------------------------------------------------------------

/**
 * Compare a derived expected schema against a live schema snapshot. Only
 * reports MISSING objects (expected but absent live) — an extra live table
 * outside the migration set (e.g. Cloudflare's own `_cf_KV`) is not drift
 * this checker is responsible for.
 */
export function compareSchema(expected, live) {
	const missingTables = [];
	const missingColumns = [];
	const missingIndexes = [];
	for (const [table, cols] of expected.tables) {
		if (!live.tables.has(table)) {
			missingTables.push(table);
			continue;
		}
		const liveCols = live.columnsByTable.get(table) ?? new Set();
		for (const col of cols) {
			if (!liveCols.has(col)) missingColumns.push({ table, column: col });
		}
	}
	for (const [indexName, table] of expected.indexes) {
		if (!live.indexes.has(indexName)) missingIndexes.push({ name: indexName, table });
	}
	return {
		ok: missingTables.length === 0 && missingColumns.length === 0 && missingIndexes.length === 0,
		missingTables,
		missingColumns,
		missingIndexes,
	};
}

// -- orchestration ------------------------------------------------------------------

/**
 * Run the full drift check. Returns the process exit code.
 *
 * `deps` shape:
 *   fs.readFileSync(path, 'utf8') -> string
 *   fs.readdirSync(dir) -> string[]
 *   runWranglerQuery(database, configPath, sql) -> row[] (throws on failure)
 *   migrationsDir -> { registry: absPath, tenant: absPath }
 *   stdout(s), stderr(s) -> void
 */
export function runSchemaDriftCheck(opts, deps) {
	const configPath = opts.config ?? 'wrangler.production.jsonc';

	let configText;
	try {
		configText = deps.fs.readFileSync(configPath, 'utf8');
	} catch (err) {
		deps.stderr(`Failed to read ${configPath}: ${err?.message ?? err}\n`);
		return 2;
	}

	let config;
	try {
		config = parseJsonc(configText);
	} catch (err) {
		deps.stderr(`Failed to parse ${configPath} as JSONC: ${err?.message ?? err}\n`);
		return 2;
	}

	const targets = [];
	for (const entry of listD1Databases(config)) {
		const binding = entry?.binding;
		const set = classifyBinding(binding);
		if (!set) {
			deps.stdout(`skip ${binding ?? '(unnamed binding)'}: no known migration source for this checker\n`);
			continue;
		}
		targets.push({ binding, set });
	}

	if (targets.length === 0) {
		deps.stdout(`No registry or tenant D1 bindings found in ${configPath}; nothing to check.\n`);
		return 0;
	}

	const expectedBySet = new Map();
	for (const set of new Set(targets.map((t) => t.set))) {
		const dir = deps.migrationsDir[set];
		const files = listSqlFiles(deps.fs, dir);
		const texts = files.map((f) => deps.fs.readFileSync(f, 'utf8'));
		expectedBySet.set(set, deriveExpectedSchema(texts));
	}

	let anyMissing = false;
	for (const { binding, set } of targets) {
		deps.stdout(`\n${binding} (${set} schema):\n`);
		let live;
		try {
			live = fetchLiveSchema(deps, binding, configPath);
		} catch (err) {
			deps.stderr(`  failed to query live schema: ${err?.message ?? err}\n`);
			anyMissing = true;
			continue;
		}
		const result = compareSchema(expectedBySet.get(set), live);
		if (result.ok) {
			deps.stdout(`  OK — matches ${set} migrations\n`);
			continue;
		}
		anyMissing = true;
		for (const t of result.missingTables) deps.stdout(`  MISSING TABLE: ${t}\n`);
		for (const c of result.missingColumns) deps.stdout(`  MISSING COLUMN: ${c.table}.${c.column}\n`);
		for (const idx of result.missingIndexes) deps.stdout(`  MISSING INDEX: ${idx.name} (on table ${idx.table})\n`);
	}

	return anyMissing ? 1 : 0;
}

// -- CLI bootstrap -------------------------------------------------------------

// Only run the CLI when invoked directly (node scripts/tenants/check-schema-drift.mjs ...).
// When imported by a test, the `node:*` modules are NOT loaded — keeping the
// module compatible with the @cloudflare/vitest-pool-workers runtime.
const isDirectInvocation = (() => {
	try {
		if (typeof process === 'undefined' || !process?.argv?.[1]) return false;
		const entry = process.argv[1];
		return import.meta.url === `file://${entry}`;
	} catch {
		return false;
	}
})();

if (isDirectInvocation) {
	const [{ execFileSync }, fsMod, pathMod, urlMod] = await Promise.all([
		import('node:child_process'),
		import('node:fs'),
		import('node:path'),
		import('node:url'),
	]);

	const __filename = urlMod.fileURLToPath(import.meta.url);
	const __dirname = pathMod.dirname(__filename);
	const repoRoot = pathMod.resolve(__dirname, '..', '..');
	const wranglerBin = pathMod.join(repoRoot, 'node_modules', 'wrangler', 'bin', 'wrangler.js');

	const argv = process.argv.slice(2);
	let config;
	for (let i = 0; i < argv.length; i += 1) {
		if (argv[i] === '--config') config = argv[i + 1];
		if (argv[i] === '--help' || argv[i] === '-h') {
			process.stdout.write(
				'Usage: node scripts/tenants/check-schema-drift.mjs [--config wrangler.production.jsonc]\n' +
					'Read-only: compares live production D1 schema against the tenant/registry migration files.\n',
			);
			process.exit(0);
		}
	}

	const execWrangler = (database, configPath, sql) =>
		execFileSync(process.execPath, [wranglerBin, 'd1', 'execute', database, '--config', configPath, '--remote', '--json', '--command', sql], {
			encoding: 'utf8',
			timeout: 60_000,
			stdio: ['ignore', 'pipe', 'pipe'],
		});

	const deps = {
		fs: {
			readFileSync: (p, enc) => fsMod.readFileSync(p, enc),
			readdirSync: (p) => fsMod.readdirSync(p),
		},
		runWranglerQuery: createWranglerRunner(execWrangler),
		migrationsDir: {
			registry: pathMod.join(repoRoot, 'src', 'tenants', 'db', 'migrations', 'registry'),
			tenant: pathMod.join(repoRoot, 'src', 'tenants', 'db', 'migrations', 'tenant'),
		},
		stdout: (s) => process.stdout.write(s),
		stderr: (s) => process.stderr.write(s),
	};

	process.exitCode = runSchemaDriftCheck({ config }, deps);
}
