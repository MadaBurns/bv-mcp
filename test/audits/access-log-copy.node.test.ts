// SPDX-License-Identifier: BUSL-1.1
//
// scripts/access-log/copy-from-intelligence.mjs (SQ-187): the operator copy from bv-intelligence to
// mcp-access-log-v1. The end-to-end cases walk the cut-over runbook against two real (workerd) D1s.

import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { ACCESS_LOG_AUDIT_COLUMNS, ACCESS_LOG_COLUMNS } from '../../scripts/access-log/columns.mjs';
import {
	MAX_ROWS_PER_STATEMENT,
	MAX_STATEMENT_BYTES,
	assertReadOnlySql,
	buildInsertStatements,
	erasureDeleteSql,
	parseArgs,
	prepareOutDir,
	runCopy,
	runReplayErasures,
	runVerify,
	sqlLiteral,
	wranglerQuery,
	writeSqlFiles,
} from '../../scripts/access-log/copy-from-intelligence.mjs';

type Row = Record<string, string | number | null>;

describe('sqlLiteral', () => {
	it('doubles single quotes and wraps strings, so hostile text stays a literal', () => {
		expect(sqlLiteral("O'Brien")).toBe("'O''Brien'");
		expect(sqlLiteral('')).toBe("''");
		expect(sqlLiteral("'); DROP TABLE mcp_access_log; --")).toBe("'''); DROP TABLE mcp_access_log; --'");
		expect(sqlLiteral('back\\slash "double"')).toBe('\'back\\slash "double"\'');
	});

	it('writes NULL for null and integers verbatim', () => {
		expect(sqlLiteral(null)).toBe('NULL');
		expect(sqlLiteral(0)).toBe('0');
		expect(sqlLiteral(46431)).toBe('46431');
		expect(sqlLiteral(-12)).toBe('-12');
		expect(sqlLiteral(4294967295)).toBe('4294967295');
		expect(sqlLiteral(1.5)).toBe('1.5');
	});

	it('refuses any value it cannot copy exactly', () => {
		expect(() => sqlLiteral(undefined)).toThrow(/undefined/);
		expect(() => sqlLiteral(2 ** 53)).toThrow(/safe range/);
		expect(() => sqlLiteral(Number.NaN)).toThrow(/non-finite/);
		expect(() => sqlLiteral(true)).toThrow(/boolean/);
		expect(() => sqlLiteral('a\u0000b')).toThrow(/NUL/);
	});
});

describe('read-only guard', () => {
	it('lets only a single SELECT through', () => {
		expect(() => assertReadOnlySql('SELECT id FROM mcp_access_log WHERE id > 0 ORDER BY id LIMIT 5')).not.toThrow();
		for (const sql of [
			'INSERT INTO mcp_access_log (id) VALUES (1)',
			'DELETE FROM mcp_access_log',
			'SELECT 1; DELETE FROM mcp_access_log',
			'DROP TABLE mcp_access_log',
			'UPDATE mcp_access_log SET domain = 1',
		]) {
			expect(() => assertReadOnlySql(sql), sql).toThrow(/single SELECT/);
		}
	});

	it('runs wrangler by database name with no --config and never spawns for a write', () => {
		const spawnSync = vi.fn((_command: string, _args: string[], _options: { cwd: string }) => ({
			status: 0,
			stdout: JSON.stringify([{ success: true, results: [{ id: 1 }] }]),
			stderr: '',
		}));
		expect(wranglerQuery('bv-intelligence', 'SELECT id FROM mcp_access_log', { spawnSync, wranglerCliPath: '/w.js' })).toEqual([{ id: 1 }]);
		const [, args, options] = spawnSync.mock.calls[0];
		expect(args.slice(0, 5)).toEqual(['/w.js', 'd1', 'execute', 'bv-intelligence', '--remote']);
		expect(args).not.toContain('--config');
		expect(args).not.toContain('--file');
		expect(readdirSync(options.cwd)).toContain('wrangler.jsonc');
		expect(() => wranglerQuery('bv-intelligence', 'DELETE FROM mcp_access_log', { spawnSync, wranglerCliPath: '/w.js' })).toThrow();
		expect(spawnSync).toHaveBeenCalledTimes(1);
	});
});

describe('buildInsertStatements', () => {
	const row = (id: number, domain = 'example.com'): Row => ({ id, created_at: 1_750_000_000 + id, domain });

	it(`holds at most ${MAX_ROWS_PER_STATEMENT} rows per statement`, () => {
		const rows = Array.from({ length: 450 }, (_, index) => row(index + 1));
		const statements = buildInsertStatements('t', ['id', 'created_at', 'domain'], rows);
		expect(statements.map((statement: string) => statement.match(/\(\d+, /g)!.length)).toEqual([200, 200, 50]);
	});

	it('splits on bytes first when rows are wide, staying under the D1 100 KB statement cap', () => {
		const rows = Array.from({ length: 150 }, (_, index) => row(index + 1, 'x'.repeat(2000)));
		const statements = buildInsertStatements('t', ['id', 'created_at', 'domain'], rows);
		expect(statements.length).toBeGreaterThan(1);
		for (const statement of statements) {
			expect(Buffer.byteLength(statement)).toBeLessThanOrEqual(MAX_STATEMENT_BYTES);
			expect(Buffer.byteLength(statement)).toBeLessThan(100_000);
		}
	});

	it('refuses a row that lacks a column instead of writing NULL for it', () => {
		expect(() => buildInsertStatements('t', ['id', 'domain'], [{ id: 1 }])).toThrow(/no domain column/);
	});
});

describe('erasureDeleteSql', () => {
	it('replays the subject filter, bounded to rows that existed when the erasure ran', () => {
		expect(
			erasureDeleteSql({
				id: 'a',
				created_at: 1_760_000_000,
				scope: JSON.stringify({ ipHashFilter: "i_o'x", keyHashFilter: 'k_1', deleted: 2 }),
			}),
		).toBe("DELETE FROM mcp_access_log WHERE ip_hash = 'i_o''x' AND key_hash = 'k_1' AND created_at <= 1760000000;");
	});

	it('never emits an unfiltered DELETE', () => {
		expect(() => erasureDeleteSql({ id: 'a', created_at: 1, scope: '{"ipHashFilter":null,"keyHashFilter":null}' })).toThrow(/unfiltered/);
		expect(() => erasureDeleteSql({ id: 'a', created_at: 1, scope: 'not json' })).toThrow(/unparseable/);
		expect(() => erasureDeleteSql({ id: 'a', created_at: 1, scope: '{"ipHashFilter":7}' })).toThrow(/invalid ipHashFilter/);
	});
});

describe('parseArgs', () => {
	it('accepts each mode with its own options and the default databases', () => {
		expect(parseArgs(['--bulk', '--out', 'out/bulk'])).toEqual({
			mode: 'bulk',
			outDir: 'out/bulk',
			source: 'bv-intelligence',
			target: 'mcp-access-log-v1',
		});
		expect(parseArgs(['--delta', '--from-id', '46431', '--out', 'd'])).toMatchObject({ mode: 'delta', fromId: 46431 });
		expect(parseArgs(['--verify', '--to-id', '9', '--since', '100'])).toMatchObject({ mode: 'verify', toId: 9, since: 100 });
		expect(parseArgs(['--replay-erasures', '--since', '100', '--out', 'e'])).toMatchObject({ mode: 'replay-erasures', since: 100 });
	});

	it('refuses ambiguous, incomplete or self-targeting invocations', () => {
		expect(() => parseArgs(['--bulk', '--verify', '--out', 'x'])).toThrow(/exactly one/);
		expect(() => parseArgs(['--delta', '--out', 'x'])).toThrow(/requires --from-id/);
		expect(() => parseArgs(['--verify', '--out', 'x'])).toThrow(/does not take --out/);
		expect(() => parseArgs(['--delta', '--from-id', '-1', '--out', 'x'])).toThrow(/non-negative integer/);
		expect(() => parseArgs(['--verify', '--source', 'same', '--target', 'same'])).toThrow(/must be different/);
	});
});

// --- end to end against real D1 -------------------------------------------------------------------------

let miniflare: Miniflare | undefined;

afterEach(async () => {
	await miniflare?.dispose();
	miniflare = undefined;
});

const baselineStatements = readFileSync('scripts/access-log/sql/0001_baseline.sql', 'utf8')
	.replace(/^\s*--.*$/gm, '')
	.split(';')
	.map((statement) => statement.trim())
	.filter(Boolean);

/** Split a generated .sql file on the semicolons outside string literals ('' toggles twice). */
function splitStatements(sql: string): string[] {
	const statements: string[] = [];
	let current = '';
	let quoted = false;
	for (const char of sql) {
		current += char;
		if (char === "'") quoted = !quoted;
		else if (char === ';' && !quoted) {
			statements.push(current.trim());
			current = '';
		}
	}
	if (current.trim()) statements.push(current.trim());
	return statements;
}

async function twoDatabases() {
	miniflare = new Miniflare(
		convertV4MiniflareOptions({
			modules: true,
			script: 'export default { fetch() { return new Response("ok") } }',
			d1Databases: { SOURCE: `al-source-${crypto.randomUUID()}`, TARGET: `al-target-${crypto.randomUUID()}` },
		}),
	);
	const dbs: Record<string, D1Database> = {
		SOURCE: (await miniflare.getD1Database('SOURCE')) as unknown as D1Database,
		TARGET: (await miniflare.getD1Database('TARGET')) as unknown as D1Database,
	};
	for (const db of Object.values(dbs)) for (const statement of baselineStatements) await db.prepare(statement).run();
	const seen: Record<string, string[]> = { SOURCE: [], TARGET: [] };
	let clock = 1_760_000_000;
	const deps = {
		query: async (name: string, sql: string) => {
			seen[name].push(sql);
			return (await dbs[name].prepare(sql).all()).results;
		},
		prepareOutDir,
		writeFiles: writeSqlFiles,
		now: () => clock,
	};
	const scratch = mkdtempSync(join(tmpdir(), 'access-log-copy-'));
	return { dbs, seen, deps, scratch, setClock: (value: number) => (clock = value) };
}

/** Insert a source row with bound parameters: these values are the ground truth the copy must reproduce. */
async function seedAccessLog(db: D1Database, id: number, overrides: Row = {}) {
	const row: Row = {
		id,
		created_at: 1_750_000_000 + id * 3600,
		ip_hash: `i_${id}`,
		ip_masked: `masked-${id}`,
		tool_name: 'scan_domain',
		domain: 'example.com',
		country: 'NZ',
		user_agent: null,
		response_ms: 120 + id,
		rate_limited: 0,
		ip_ciphertext: null,
		ip_key_version: null,
		city: null,
		region: 'Auckland',
		latitude: '-36.8485',
		longitude: null,
		asn: 13335,
		as_org: 'Example AS',
		ptr_hostname: null,
		key_hash: null,
		client_type: 'claude_code',
		colo: 'AKL',
		session_hash: null,
		method: 'tools/call',
		transport: 'streamable_http',
		status: 'ok',
		source: 'public',
		...overrides,
	};
	await db
		.prepare(`INSERT INTO mcp_access_log (${ACCESS_LOG_COLUMNS.join(', ')}) VALUES (${ACCESS_LOG_COLUMNS.map(() => '?').join(', ')})`)
		.bind(...ACCESS_LOG_COLUMNS.map((column) => row[column]))
		.run();
}

async function seedAudit(db: D1Database, row: Row) {
	await db
		.prepare(
			`INSERT INTO mcp_access_log_audit (${ACCESS_LOG_AUDIT_COLUMNS.join(', ')}) VALUES (${ACCESS_LOG_AUDIT_COLUMNS.map(() => '?').join(', ')})`,
		)
		.bind(...ACCESS_LOG_AUDIT_COLUMNS.map((column) => row[column] ?? null))
		.run();
}

/** Apply every generated file to the target in glob order, as the printed operator loop does. */
async function applyFiles(db: D1Database, outDir: string) {
	const files = readdirSync(outDir).sort();
	const perFile: number[] = [];
	for (const file of files) {
		const statements = splitStatements(readFileSync(join(outDir, file), 'utf8'));
		perFile.push(statements.length);
		for (const statement of statements) await db.prepare(statement).run();
	}
	return perFile;
}

async function allRows(db: D1Database, table: string) {
	return (await db.prepare(`SELECT * FROM ${table} ORDER BY id`).all()).results;
}

describe('copy-from-intelligence against real D1', () => {
	it('walks bulk -> verify -> delta -> verify -> erasure replay with every id, value and type preserved', async () => {
		const { dbs, seen, deps, scratch, setClock } = await twoDatabases();
		const ids = Array.from({ length: 30 }, (_, index) => 101 + index).filter((id) => id !== 105 && id !== 111);
		for (const id of ids) await seedAccessLog(dbs.SOURCE, id);
		await seedAccessLog(dbs.SOURCE, 140, {
			domain: "'; DROP TABLE mcp_access_log; --",
			user_agent: 'Mozilla/5.0 (it\'s "quoted"; with \\ backslash)\nsecond line',
			city: 'Zürich ☃ 東京',
			as_org: '',
			asn: 4294967295,
			rate_limited: 1,
			response_ms: 0,
			key_hash: 'k_subject',
			ip_hash: 'i_subject',
			source: 'internal',
		});
		await seedAccessLog(dbs.SOURCE, 141, { ip_hash: 'i_subject', created_at: 1_760_000_100 });
		await seedAudit(dbs.SOURCE, {
			id: 'audit-1',
			created_at: 1_759_000_000,
			actor: 'internal_bearer',
			action: 'analytics.forensics.decrypt',
			ip_hash: null,
			scope: '{"window":"x"}',
			outcome: 'success',
		});

		// Bulk: 7-row pages so the keyset pager crosses several pages, one file per page.
		const bulk = await runCopy({ mode: 'bulk', source: 'SOURCE', target: 'TARGET', outDir: join(scratch, 'bulk'), pageSize: 7 }, deps);
		expect(bulk).toMatchObject({ rows: 30, minId: 101, maxId: 141, auditRows: 1, files: 6, startedAt: 1_760_000_000 });
		expect(bulk.apply).toContain('--file "$f"');
		expect(bulk.next!.idFloor).toContain('VALUES (100141,');
		await applyFiles(dbs.TARGET, bulk.outDir);
		expect(await allRows(dbs.TARGET, 'mcp_access_log')).toEqual(await allRows(dbs.SOURCE, 'mcp_access_log'));
		expect(await allRows(dbs.TARGET, 'mcp_access_log_audit')).toEqual(await allRows(dbs.SOURCE, 'mcp_access_log_audit'));
		const typed = await dbs.TARGET.prepare(
			'SELECT typeof(asn) AS asn, typeof(latitude) AS latitude, typeof(created_at) AS created FROM mcp_access_log WHERE id = 140',
		).first();
		expect(typed).toEqual({ asn: 'integer', latitude: 'text', created: 'integer' });
		expect(await dbs.TARGET.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'mcp_access_log'").first('seq')).toBe(141);

		expect((await runVerify({ source: 'SOURCE', target: 'TARGET', toId: bulk.maxId }, deps)).ok).toBe(true);

		// Id floor (runbook step 4), then the cut-over: the target takes its own writes above the floor while
		// the old version drains a few more rows and one erasure into the source.
		for (const statement of splitStatements(bulk.next!.idFloor.match(/--command "(.*)"$/)![1])) await dbs.TARGET.prepare(statement).run();
		await dbs.TARGET.prepare(
			"INSERT INTO mcp_access_log (ip_hash, ip_masked, tool_name, domain, created_at) VALUES ('i_subject', 'm', 't', 'd', 1760000900)",
		).run();
		for (const id of [142, 143, 144]) await seedAccessLog(dbs.SOURCE, id, { created_at: 1_760_000_200 + id });
		await dbs.SOURCE.prepare("DELETE FROM mcp_access_log WHERE ip_hash = 'i_subject'").run();
		await seedAudit(dbs.SOURCE, {
			id: 'audit-2',
			created_at: 1_760_000_500,
			actor: 'internal_bearer',
			action: 'analytics.subject.erase',
			ip_hash: 'i_subject',
			scope: JSON.stringify({ ipHashFilter: 'i_subject', keyHashFilter: null, deleted: 2 }),
			outcome: 'success',
		});
		expect(await dbs.TARGET.prepare('SELECT MIN(id) AS id FROM mcp_access_log WHERE id > 141').first('id')).toBe(100142);

		// Delta: one statement per file, applied with --command because the target is live by now.
		setClock(1_760_001_000);
		const delta = await runCopy(
			{ mode: 'delta', source: 'SOURCE', target: 'TARGET', fromId: bulk.maxId, outDir: join(scratch, 'delta') },
			deps,
		);
		expect(delta).toMatchObject({ rows: 3, minId: 142, maxId: 144, auditRows: 2 });
		expect(delta.apply).toContain('--command "$(cat "$f")"');
		expect(await applyFiles(dbs.TARGET, delta.outDir)).toEqual([1, 1]);

		// Before the replay the target still holds the two rows the source erased: verify must say so.
		const beforeReplay = await runVerify({ source: 'SOURCE', target: 'TARGET', toId: 144 }, deps);
		expect(beforeReplay.ok).toBe(false);
		expect(beforeReplay.missingOnTarget.count).toBe(0);
		expect(beforeReplay.extraOnTarget.sample).toEqual([140, 141]);

		const replay = await runReplayErasures(
			{ source: 'SOURCE', target: 'TARGET', since: bulk.startedAt, outDir: join(scratch, 'erasures') },
			deps,
		);
		expect(replay).toMatchObject({ erasures: 1, statements: 1, files: 1 });
		await applyFiles(dbs.TARGET, replay.outDir);
		const afterReplay = await runVerify({ source: 'SOURCE', target: 'TARGET' }, deps);
		expect(afterReplay).toMatchObject({ ok: true, range: { fromId: 0, toId: 144, since: null } });
		// The replay is bounded to the erasure's moment: the subject's post-erasure target row survives.
		expect(await dbs.TARGET.prepare("SELECT created_at FROM mcp_access_log WHERE ip_hash = 'i_subject'").all()).toMatchObject({
			results: [{ created_at: 1_760_000_900 }],
		});

		// Nothing but SELECTs ever reached either database through the script.
		for (const sql of [...seen.SOURCE, ...seen.TARGET]) expect(sql).toMatch(/^SELECT /);
		expect(seen.SOURCE.length).toBeGreaterThan(0);
	});

	it('fails verification, naming the ids and days, when a copied row is missing on the target', async () => {
		const { dbs, deps, scratch } = await twoDatabases();
		for (const id of [1, 2, 3, 4]) await seedAccessLog(dbs.SOURCE, id);
		const bulk = await runCopy({ mode: 'bulk', source: 'SOURCE', target: 'TARGET', outDir: join(scratch, 'bulk') }, deps);
		await applyFiles(dbs.TARGET, bulk.outDir);
		await dbs.TARGET.prepare('DELETE FROM mcp_access_log WHERE id = 3').run();
		const result = await runVerify({ source: 'SOURCE', target: 'TARGET' }, deps);
		expect(result.ok).toBe(false);
		expect(result.missingOnTarget).toEqual({ count: 1, sample: [3] });
		expect(result.source).toMatchObject({ count: 4, sum_id: 10 });
		expect(result.target).toMatchObject({ count: 3, sum_id: 7 });
		expect(result.mismatchedDays).toEqual([{ day: '2025-06-15', source: 4, target: 3 }]);
	});

	it('refuses a non-empty output directory so stale files are never applied twice', async () => {
		const { deps, scratch } = await twoDatabases();
		writeFileSync(join(scratch, 'stale.sql'), 'SELECT 1;');
		await expect(runCopy({ mode: 'bulk', source: 'SOURCE', target: 'TARGET', outDir: scratch }, deps)).rejects.toThrow(/not empty/);
	});
});
