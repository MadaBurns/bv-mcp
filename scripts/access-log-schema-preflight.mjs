// SPDX-License-Identifier: BUSL-1.1
//
// Deploy gate: refuse to ship while the database behind INTELLIGENCE_DB lacks the access-log schema.
//
// Every access-log write (the inline insert in src/mcp/execute.ts, the internal-path insert, the queue
// consumer, the forensics/erase audit rows) runs fire-and-forget. Pointing the binding at an unmigrated
// database therefore makes every insert throw where nothing surfaces it: total, silent row loss with no
// alert. That is exactly the state a database_id repoint in the private overlay can produce (SQ-187:
// bv-intelligence -> mcp-access-log-v1), so the check runs against the generated deploy config, before
// `wrangler deploy`, on all three doors (deploy:prod, deploy:prod:staged, scripts/deploy-private.mjs).
//
// Read-only: one SELECT over pragma_table_info for both tables. Skipped only when the config binds no
// INTELLIGENCE_DB at all (a BSL self-host), where the access log is a documented no-op.
// Pattern: scripts/brand-audit-schema-preflight.mjs.

import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

import { parseJsonc } from './brand-audit-schema-preflight.mjs';
import { ACCESS_LOG_AUDIT_COLUMNS, ACCESS_LOG_AUDIT_TABLE, ACCESS_LOG_COLUMNS, ACCESS_LOG_TABLE } from './access-log/columns.mjs';

export const ACCESS_LOG_BINDING = 'INTELLIGENCE_DB';

export const REQUIRED_ACCESS_LOG_SCHEMA = Object.freeze({
	[ACCESS_LOG_TABLE]: ACCESS_LOG_COLUMNS,
	[ACCESS_LOG_AUDIT_TABLE]: ACCESS_LOG_AUDIT_COLUMNS,
});

export const ACCESS_LOG_PREFLIGHT_SQL = Object.keys(REQUIRED_ACCESS_LOG_SCHEMA)
	.map((table) => `SELECT '${table}' AS table_name, name FROM pragma_table_info('${table}')`)
	.join(' UNION ALL ');

/** The INTELLIGENCE_DB entry of a Wrangler config, or null when the deployment does not bind one. */
export function resolveAccessLogBinding(config) {
	const bindings = Array.isArray(config?.d1_databases) ? config.d1_databases : [];
	const binding = bindings.find((candidate) => candidate?.binding === ACCESS_LOG_BINDING);
	if (!binding) return null;
	const database = binding.database_name ?? binding.database_id;
	if (typeof database !== 'string' || database.trim() === '') {
		throw new Error(`${ACCESS_LOG_BINDING} is declared without a database_name or database_id`);
	}
	return { binding: ACCESS_LOG_BINDING, database };
}

export function assertAccessLogSchema(rawOutput) {
	let parsed;
	try {
		parsed = JSON.parse(rawOutput);
	} catch {
		throw new Error('Access-log schema preflight returned invalid JSON');
	}
	const statements = Array.isArray(parsed) ? parsed : [parsed];
	if (statements.length === 0 || statements.some((statement) => statement?.success !== true)) {
		throw new Error('Access-log schema preflight query failed');
	}
	const present = new Map(Object.keys(REQUIRED_ACCESS_LOG_SCHEMA).map((table) => [table, new Set()]));
	for (const row of statements.flatMap((statement) => (Array.isArray(statement.results) ? statement.results : []))) {
		present.get(row?.table_name)?.add(row?.name);
	}
	const problems = Object.entries(REQUIRED_ACCESS_LOG_SCHEMA).flatMap(([table, columns]) => {
		const found = present.get(table);
		if (found.size === 0) return [`table ${table} does not exist`];
		const missing = columns.filter((column) => !found.has(column));
		return missing.length > 0 ? [`${table} is missing column(s): ${missing.join(', ')}`] : [];
	});
	if (problems.length > 0) {
		throw new Error(
			`${ACCESS_LOG_BINDING} is not migrated (${problems.join('; ')}). Every access-log insert would fail silently. Apply scripts/access-log/sql/0001_baseline.sql to that database before deploying.`,
		);
	}
}

export function runAccessLogSchemaPreflight(configPath, dependencies = {}) {
	const read = dependencies.readFileSync ?? readFileSync;
	const spawn = dependencies.spawnSync ?? spawnSync;
	const config = parseJsonc(read(configPath, 'utf8'));
	const resolved = resolveAccessLogBinding(config);
	if (!resolved) return { skipped: true };
	const wranglerCliPath = dependencies.wranglerCliPath ?? createRequire(import.meta.url).resolve('wrangler');
	// Resolve through the BINDING name, not the database name: that is exactly the database this config
	// hands the Worker, even mid-repoint when a stale database_name still sits next to a new database_id.
	const result = spawn(
		process.execPath,
		[
			wranglerCliPath,
			'd1',
			'execute',
			resolved.binding,
			'--remote',
			'--config',
			configPath,
			'--command',
			ACCESS_LOG_PREFLIGHT_SQL,
			'--json',
		],
		{ encoding: 'utf8' },
	);
	if (result.error) throw result.error;
	if (result.status !== 0) {
		throw new Error(`Access-log schema preflight failed (${result.status ?? 'no exit status'}): ${result.stderr || 'no stderr'}`);
	}
	assertAccessLogSchema(result.stdout);
	return { database: resolved.database };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
	const configFlag = process.argv.indexOf('--config');
	const configPath = configFlag >= 0 ? process.argv[configFlag + 1] : undefined;
	if (!configPath) {
		console.error('Usage: node scripts/access-log-schema-preflight.mjs --config <wrangler-config.jsonc>');
		process.exit(1);
	}
	try {
		const outcome = runAccessLogSchemaPreflight(configPath);
		if (outcome.skipped) {
			console.log(`Access-log schema preflight skipped: ${configPath} binds no ${ACCESS_LOG_BINDING} (the access log is a no-op).`);
		} else {
			console.log(`Access-log schema preflight passed for ${outcome.database}.`);
		}
	} catch (error) {
		console.error(`FATAL: ${error instanceof Error ? error.message : String(error)}`);
		process.exit(1);
	}
}
