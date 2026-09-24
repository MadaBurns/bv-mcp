// SPDX-License-Identifier: BUSL-1.1

import { readFileSync } from 'node:fs';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
	ACCESS_LOG_PREFLIGHT_SQL,
	assertAccessLogSchema,
	resolveAccessLogBinding,
	runAccessLogSchemaPreflight,
} from '../../scripts/access-log-schema-preflight.mjs';
import { ACCESS_LOG_AUDIT_COLUMNS, ACCESS_LOG_COLUMNS } from '../../scripts/access-log/columns.mjs';

const CONFIG = JSON.stringify({
	d1_databases: [
		{ binding: 'BRAND_AUDIT_DB', database_name: 'brand-audit-prod', database_id: 'brand-id' },
		{ binding: 'INTELLIGENCE_DB', database_name: 'mcp-access-log-v1', database_id: 'access-log-id' },
	],
});

let miniflare: Miniflare | undefined;

afterEach(async () => {
	await miniflare?.dispose();
	miniflare = undefined;
});

/** A real (workerd) D1, with each statement of the given migration files applied in order. */
async function d1With(...sqlFiles: string[]): Promise<D1Database> {
	miniflare = new Miniflare(
		convertV4MiniflareOptions({
			modules: true,
			script: 'export default { fetch() { return new Response("ok") } }',
			d1Databases: { DB: `access-log-preflight-${crypto.randomUUID()}` },
		}),
	);
	const db = (await miniflare.getD1Database('DB')) as unknown as D1Database;
	for (const file of sqlFiles) {
		const statements = readFileSync(file, 'utf8')
			.replace(/^\s*--.*$/gm, '')
			.split(';')
			.map((statement) => statement.trim())
			.filter(Boolean);
		for (const statement of statements) await db.prepare(statement).run();
	}
	return db;
}

/** The preflight query run against that D1, shaped like `wrangler d1 execute --json` output. */
async function preflightOutput(db: D1Database): Promise<string> {
	const { results } = await db.prepare(ACCESS_LOG_PREFLIGHT_SQL).all();
	return JSON.stringify([{ success: true, results }]);
}

/** runAccessLogSchemaPreflight with wrangler replaced by the given output; returns the spawn mock. */
function runWith(stdout: string, config = CONFIG) {
	const spawnSync = vi.fn((_command: string, _args: string[]) => ({ status: 0, stdout, stderr: '' }));
	const run = () =>
		runAccessLogSchemaPreflight('wrangler.production.jsonc', {
			readFileSync: () => config,
			spawnSync,
			wranglerCliPath: '/safe/wrangler-cli.js',
		});
	return { run, spawnSync };
}

describe('access-log remote schema preflight', () => {
	it('checks the database behind the INTELLIGENCE_DB binding with one read-only remote query', () => {
		const { run, spawnSync } = runWith(
			JSON.stringify([
				{
					success: true,
					results: [
						...ACCESS_LOG_COLUMNS.map((name) => ({ table_name: 'mcp_access_log', name })),
						...ACCESS_LOG_AUDIT_COLUMNS.map((name) => ({ table_name: 'mcp_access_log_audit', name })),
					],
				},
			]),
		);
		expect(run()).toEqual({ database: 'mcp-access-log-v1' });
		expect(spawnSync).toHaveBeenCalledTimes(1);
		const [, args] = spawnSync.mock.calls[0];
		expect(args.slice(1, 4)).toEqual(['d1', 'execute', 'INTELLIGENCE_DB']);
		expect(args).toContain('--remote');
		expect(args).toContain('--json');
		expect(args[args.indexOf('--config') + 1]).toBe('wrangler.production.jsonc');
		expect(args[args.indexOf('--command') + 1]).toBe(ACCESS_LOG_PREFLIGHT_SQL);
		expect(ACCESS_LOG_PREFLIGHT_SQL).toMatch(/^SELECT /);
		expect(args).not.toContain('--file');
	});

	it('passes against a real D1 migrated with scripts/access-log/sql/0001_baseline.sql', async () => {
		const db = await d1With('scripts/access-log/sql/0001_baseline.sql');
		const { run } = runWith(await preflightOutput(db));
		expect(run()).toEqual({ database: 'mcp-access-log-v1' });
	});

	it('blocks the deploy against a real, unmigrated D1', async () => {
		const db = await d1With();
		const { run } = runWith(await preflightOutput(db));
		expect(run).toThrow(/INTELLIGENCE_DB is not migrated/);
		expect(run).toThrow(/table mcp_access_log does not exist; table mcp_access_log_audit does not exist/);
		expect(run).toThrow(/scripts\/access-log\/sql\/0001_baseline\.sql/);
	});

	it('blocks the deploy against a real D1 carrying only the first legacy migration', async () => {
		const db = await d1With('scripts/intelligence/sql/0001_mcp_access_log.sql');
		const { run } = runWith(await preflightOutput(db));
		expect(run).toThrow(/mcp_access_log is missing column\(s\): city, .*key_hash.*, source/);
		expect(run).toThrow(/table mcp_access_log_audit does not exist/);
	});

	it('names each missing column rather than passing on a partial table', () => {
		const present = ACCESS_LOG_COLUMNS.filter((name) => name !== 'source' && name !== 'created_at');
		expect(() =>
			assertAccessLogSchema(
				JSON.stringify([
					{
						success: true,
						results: [
							...present.map((name) => ({ table_name: 'mcp_access_log', name })),
							...ACCESS_LOG_AUDIT_COLUMNS.map((name) => ({ table_name: 'mcp_access_log_audit', name })),
						],
					},
				]),
			),
		).toThrow(/mcp_access_log is missing column\(s\): created_at, source/);
	});

	it('skips, without querying, only when the deployment binds no INTELLIGENCE_DB', () => {
		const { run, spawnSync } = runWith('', JSON.stringify({ d1_databases: [{ binding: 'BRAND_AUDIT_DB', database_id: 'x' }] }));
		expect(run()).toEqual({ skipped: true });
		expect(spawnSync).not.toHaveBeenCalled();
		expect(resolveAccessLogBinding({})).toBeNull();
		expect(() => resolveAccessLogBinding({ d1_databases: [{ binding: 'INTELLIGENCE_DB' }] })).toThrow(/database_name or database_id/);
	});

	it('fails closed on a Wrangler error or unreadable output', () => {
		const failing = vi.fn(() => ({ status: 1, stdout: '', stderr: 'Authentication error' }));
		expect(() =>
			runAccessLogSchemaPreflight('wrangler.production.jsonc', {
				readFileSync: () => CONFIG,
				spawnSync: failing,
				wranglerCliPath: '/safe/wrangler-cli.js',
			}),
		).toThrow(/preflight failed \(1\): Authentication error/);
		expect(() => assertAccessLogSchema('not-json')).toThrow(/invalid JSON/);
		expect(() => assertAccessLogSchema(JSON.stringify([{ success: false, results: [] }]))).toThrow(/query failed/);
		expect(() => assertAccessLogSchema(JSON.stringify([]))).toThrow(/query failed/);
	});
});
