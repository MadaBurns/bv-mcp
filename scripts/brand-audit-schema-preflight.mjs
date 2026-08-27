// SPDX-License-Identifier: BUSL-1.1

import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

export const REQUIRED_BRAND_AUDIT_WATCH_COLUMNS = ['last_classification_result_json', 'pending_webhook_json'];

const PREFLIGHT_SQL =
	"SELECT name FROM pragma_table_info('brand_audit_watches') WHERE name IN ('last_classification_result_json', 'pending_webhook_json') ORDER BY name";

/** Strip JSONC comments outside strings. Wrangler config does not use trailing commas. */
export function parseJsonc(source) {
	let output = '';
	let index = 0;
	let inString = false;
	while (index < source.length) {
		const char = source[index];
		const next = source[index + 1];
		if (inString) {
			output += char;
			if (char === '\\' && index + 1 < source.length) {
				output += source[index + 1];
				index += 2;
				continue;
			}
			if (char === '"') inString = false;
			index += 1;
			continue;
		}
		if (char === '"') {
			inString = true;
			output += char;
			index += 1;
			continue;
		}
		if (char === '/' && next === '/') {
			while (index < source.length && source[index] !== '\n') index += 1;
			continue;
		}
		if (char === '/' && next === '*') {
			index += 2;
			while (index < source.length && !(source[index] === '*' && source[index + 1] === '/')) index += 1;
			if (index >= source.length) throw new Error('Unterminated block comment in Wrangler config');
			index += 2;
			continue;
		}
		output += char;
		index += 1;
	}
	if (inString) throw new Error('Unterminated string in Wrangler config');
	return JSON.parse(output);
}

export function resolveBrandAuditDatabase(config) {
	const bindings = Array.isArray(config?.d1_databases) ? config.d1_databases : [];
	const binding = bindings.find((candidate) => candidate?.binding === 'BRAND_AUDIT_DB');
	const database = binding?.database_name ?? binding?.database_id;
	if (typeof database !== 'string' || database.trim() === '') {
		throw new Error('BRAND_AUDIT_DB is missing from the deployment Wrangler config');
	}
	return database;
}

export function assertRequiredBrandAuditColumns(rawOutput) {
	let parsed;
	try {
		parsed = JSON.parse(rawOutput);
	} catch {
		throw new Error('Brand-audit schema preflight returned invalid JSON');
	}
	const statements = Array.isArray(parsed) ? parsed : [parsed];
	if (statements.length === 0 || statements.some((statement) => statement?.success !== true)) {
		throw new Error('Brand-audit schema preflight query failed');
	}
	const present = new Set(
		statements.flatMap((statement) => (Array.isArray(statement.results) ? statement.results : [])).map((row) => row?.name),
	);
	const missing = REQUIRED_BRAND_AUDIT_WATCH_COLUMNS.filter((column) => !present.has(column));
	if (missing.length > 0) {
		throw new Error(
			`BRAND_AUDIT_DB is missing required brand_audit_watches column(s): ${missing.join(', ')}. Apply scripts/brand-audit/sql/0001_watch_webhook_outbox.sql before deploying.`,
		);
	}
}

export function runBrandAuditSchemaPreflight(configPath, dependencies = {}) {
	const read = dependencies.readFileSync ?? readFileSync;
	const spawn = dependencies.spawnSync ?? spawnSync;
	const require = createRequire(import.meta.url);
	const wranglerCliPath = dependencies.wranglerCliPath ?? require.resolve('wrangler');
	const config = parseJsonc(read(configPath, 'utf8'));
	const database = resolveBrandAuditDatabase(config);
	const result = spawn(
		process.execPath,
		[
			wranglerCliPath,
			'd1',
			'execute',
			database,
			'--remote',
			'--config',
			configPath,
			'--command',
			PREFLIGHT_SQL,
			'--json',
		],
		{ encoding: 'utf8' },
	);
	if (result.error) throw result.error;
	if (result.status !== 0) {
		throw new Error(`Brand-audit schema preflight failed (${result.status ?? 'no exit status'}): ${result.stderr || 'no stderr'}`);
	}
	assertRequiredBrandAuditColumns(result.stdout);
	return { database };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
	const configFlag = process.argv.indexOf('--config');
	const configPath = configFlag >= 0 ? process.argv[configFlag + 1] : undefined;
	if (!configPath) {
		console.error('Usage: node scripts/brand-audit-schema-preflight.mjs --config <wrangler-config.jsonc>');
		process.exit(1);
	}
	try {
		const { database } = runBrandAuditSchemaPreflight(configPath);
		console.log(`Brand-audit schema preflight passed for ${database}.`);
	} catch (error) {
		console.error(`FATAL: ${error instanceof Error ? error.message : String(error)}`);
		process.exit(1);
	}
}
