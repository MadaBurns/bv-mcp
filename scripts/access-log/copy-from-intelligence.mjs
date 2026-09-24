// SPDX-License-Identifier: BUSL-1.1
//
// Operator-run copy of the access log from bv-intelligence to mcp-access-log-v1 (SQ-187).
// Cut-over runbook: docs/operator-runbook.md section 3a. Copy-then-switch with every id preserved.
//
// READ-ONLY ON BOTH DATABASES. Every query goes through createReader(), which refuses anything but a single
// SELECT, so the script never writes the source - and it never writes the target either. It emits
// literal-value .sql files and prints the exact wrangler command that applies them to the target.
//
//   --bulk --out <dir>
//       Every source row (and every audit row) as INSERT files, one file per 5,000-row source page.
//   --delta --from-id <H> --out <dir>
//       Source rows with id > H (and every audit row, INSERT OR IGNORE), one statement per file, so each
//       file can be applied with --command: a --file import blocks the database, and by then it is live.
//   --verify [--from-id <N>] [--to-id <M>] [--since <unix-seconds>]
//       COUNT, SUM(id), MIN/MAX(created_at), per-day counts and the id sets of both sides over
//       N < id <= M (M defaults to the source MAX(id)) and created_at >= since. Exit 1 unless they match.
//   --replay-erasures --since <unix-seconds> --out <dir>
//       A DELETE for every analytics.subject.erase audit row created at or after --since, read from BOTH
//       databases, bounded to the rows that existed when that erasure ran.
//   Common: --source <name> (default bv-intelligence), --target <name> (default mcp-access-log-v1).
//
// Databases are addressed by NAME and resolved through the account API: wrangler runs from the repo root
// with no --config, deliberately. During the cut-over the private overlay is edited in place, and a config
// entry that still carries database_name "bv-intelligence" beside the NEW database_id would silently resolve
// the "source" to the target - a verify of the target against itself, reported green. Set
// CLOUDFLARE_ACCOUNT_ID when the wrangler login can see more than one account.

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ACCESS_LOG_AUDIT_COLUMNS, ACCESS_LOG_AUDIT_TABLE, ACCESS_LOG_COLUMNS, ACCESS_LOG_TABLE } from './columns.mjs';

export const DEFAULT_SOURCE = 'bv-intelligence';
export const DEFAULT_TARGET = 'mcp-access-log-v1';
/** Rows per keyset page read from a database. */
export const PAGE_SIZE = 5000;
/** Literal values dodge D1's 100-bound-parameter cap; this keeps each statement small anyway. */
export const MAX_ROWS_PER_STATEMENT = 200;
/** D1 caps one SQL statement at 100,000 bytes. */
export const MAX_STATEMENT_BYTES = 90_000;
/** Gap between the last bulk-copied id and the target's AUTOINCREMENT floor (runbook step 4). */
export const ID_FLOOR_GAP = 100_000;
export const ERASE_ACTION = 'analytics.subject.erase';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT = 'node scripts/access-log/copy-from-intelligence.mjs';

export class UsageError extends Error {}

/** A SQLite literal that reads back as exactly the value D1 returned. Refuses anything it cannot copy losslessly. */
export function sqlLiteral(value) {
	if (value === null) return 'NULL';
	if (typeof value === 'number') {
		if (!Number.isFinite(value)) throw new Error(`cannot copy the non-finite number ${value}`);
		if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
			throw new Error(`cannot copy the integer ${value} exactly: it is outside the safe range`);
		}
		return String(value);
	}
	if (typeof value === 'string') {
		if (value.includes('\u0000')) throw new Error('cannot copy a string containing a NUL character');
		return `'${value.replaceAll("'", "''")}'`;
	}
	throw new Error(`cannot copy a value of type ${value === undefined ? 'undefined' : typeof value}`);
}

export function assertReadOnlySql(sql) {
	if (typeof sql !== 'string' || !/^\s*SELECT\s/i.test(sql) || sql.includes(';')) {
		throw new Error(`refusing to run anything but a single SELECT: ${String(sql).slice(0, 80)}`);
	}
}

/** Wrap a (database, sql) => rows query so nothing but a single SELECT can reach either database. */
export function createReader(query) {
	return async (database, sql) => {
		assertReadOnlySql(sql);
		return query(database, sql);
	};
}

/** Multi-row INSERTs with explicit values for every column, each at most maxRows rows and maxBytes bytes. */
export function buildInsertStatements(table, columns, rows, options = {}) {
	const maxRows = options.maxRows ?? MAX_ROWS_PER_STATEMENT;
	const maxBytes = options.maxBytes ?? MAX_STATEMENT_BYTES;
	const head = `INSERT${options.orIgnore ? ' OR IGNORE' : ''} INTO ${table} (${columns.join(', ')}) VALUES `;
	const headBytes = Buffer.byteLength(head);
	const statements = [];
	let tuples = [];
	// Upper bound on the statement length: head + each tuple + 2 bytes for its ", " separator or ";" terminator.
	let bytes = headBytes;
	const flush = () => {
		if (tuples.length === 0) return;
		statements.push(`${head}${tuples.join(', ')};`);
		tuples = [];
		bytes = headBytes;
	};
	for (const row of rows) {
		const values = columns.map((column) => {
			if (!Object.hasOwn(row, column)) throw new Error(`row ${row.id} has no ${column} column`);
			return sqlLiteral(row[column]);
		});
		const tuple = `(${values.join(', ')})`;
		const tupleBytes = Buffer.byteLength(tuple) + 2;
		if (headBytes + tupleBytes > maxBytes) throw new Error(`row ${row.id} alone exceeds the ${maxBytes}-byte statement limit`);
		if (tuples.length >= maxRows || bytes + tupleBytes > maxBytes) flush();
		tuples.push(tuple);
		bytes += tupleBytes;
	}
	flush();
	return statements;
}

function nonNegativeInteger(value, name) {
	if (!Number.isSafeInteger(value) || value < 0) throw new UsageError(`${name} must be a non-negative integer`);
	return value;
}

export function accessLogPageSql(afterId, pageSize, toId) {
	const upper = toId === undefined ? '' : ` AND id <= ${nonNegativeInteger(toId, 'toId')}`;
	return `SELECT ${ACCESS_LOG_COLUMNS.join(', ')} FROM ${ACCESS_LOG_TABLE} WHERE id > ${nonNegativeInteger(afterId, 'afterId')}${upper} ORDER BY id LIMIT ${nonNegativeInteger(pageSize, 'pageSize')}`;
}

export function auditPageSql(afterId, pageSize) {
	return `SELECT ${ACCESS_LOG_AUDIT_COLUMNS.join(', ')} FROM ${ACCESS_LOG_AUDIT_TABLE} WHERE id > ${sqlLiteral(afterId)} ORDER BY id LIMIT ${nonNegativeInteger(pageSize, 'pageSize')}`;
}

/** Keyset pagination: yields pages of rows until a short page, advancing on the last row's cursor column. */
export async function* keysetPages(read, database, pageSql, cursorColumn, start, pageSize = PAGE_SIZE) {
	let cursor = start;
	for (;;) {
		const rows = await read(database, pageSql(cursor, pageSize));
		if (rows.length === 0) return;
		yield rows;
		if (rows.length < pageSize) return;
		const next = rows[rows.length - 1][cursorColumn];
		if (!(next > cursor)) throw new Error(`keyset cursor did not advance past ${cursor} on ${database}`);
		cursor = next;
	}
}

async function collect(iterable, map = (row) => row) {
	const out = [];
	for await (const page of iterable) for (const row of page) out.push(map(row));
	return out;
}

/** The DELETE an erase audit row ran, bounded to the rows that existed when it ran. Never unfiltered. */
export function erasureDeleteSql(auditRow) {
	let scope;
	try {
		scope = JSON.parse(auditRow.scope);
	} catch {
		throw new Error(`erase audit row ${auditRow.id} has an unparseable scope; replay it by hand`);
	}
	const filters = [];
	for (const [key, column] of [
		['ipHashFilter', 'ip_hash'],
		['keyHashFilter', 'key_hash'],
	]) {
		const value = scope?.[key] ?? null;
		if (value === null) continue;
		if (typeof value !== 'string' || value === '')
			throw new Error(`erase audit row ${auditRow.id} has an invalid ${key}; replay it by hand`);
		filters.push(`${column} = ${sqlLiteral(value)}`);
	}
	if (filters.length === 0) throw new Error(`erase audit row ${auditRow.id} names no subject; refusing to emit an unfiltered DELETE`);
	if (!Number.isSafeInteger(auditRow.created_at)) throw new Error(`erase audit row ${auditRow.id} has a non-integer created_at`);
	return `DELETE FROM ${ACCESS_LOG_TABLE} WHERE ${filters.join(' AND ')} AND created_at <= ${auditRow.created_at};`;
}

function applyCommand(target, outDir, viaFile) {
	const execute = viaFile ? `--yes --file "$f"` : `--command "$(cat "$f")"`;
	return `for f in "${outDir}"/*.sql; do npx wrangler d1 execute ${target} --remote ${execute} || { echo "FAILED at $f"; break; }; done`;
}

export function prepareOutDir(outDir) {
	if (existsSync(outDir) && readdirSync(outDir).length > 0) {
		throw new UsageError(`--out ${outDir} is not empty; use a fresh directory so stale files cannot be applied twice`);
	}
	mkdirSync(outDir, { recursive: true });
}

/** Write each group of statements to its own file, numbered so a shell glob applies them in order. */
export function writeSqlFiles(outDir, groups) {
	return groups.map((group, index) => {
		const path = join(outDir, `${String(index + 1).padStart(4, '0')}-${group.label}.sql`);
		writeFileSync(path, `${group.statements.join('\n')}\n`);
		return path;
	});
}

/** --bulk (fromId 0) and --delta (fromId H). */
export async function runCopy({ mode, source, target, fromId = 0, outDir, pageSize = PAGE_SIZE }, deps) {
	deps.prepareOutDir(outDir);
	const read = createReader(deps.query);
	const startedAt = deps.now();
	const perFile = mode === 'bulk';
	const groups = [];
	const addStatements = (label, statements) => {
		if (perFile) groups.push({ label, statements });
		else for (const statement of statements) groups.push({ label, statements: [statement] });
	};
	let rows = 0;
	let minId = null;
	let maxId = null;
	for await (const page of keysetPages(read, source, (after, size) => accessLogPageSql(after, size), 'id', fromId, pageSize)) {
		const first = page[0].id;
		const last = page[page.length - 1].id;
		addStatements(`${ACCESS_LOG_TABLE}-${first}-${last}`, buildInsertStatements(ACCESS_LOG_TABLE, ACCESS_LOG_COLUMNS, page));
		rows += page.length;
		minId ??= first;
		maxId = last;
	}
	let auditRows = 0;
	for await (const page of keysetPages(read, source, auditPageSql, 'id', '', pageSize)) {
		addStatements(
			ACCESS_LOG_AUDIT_TABLE,
			buildInsertStatements(ACCESS_LOG_AUDIT_TABLE, ACCESS_LOG_AUDIT_COLUMNS, page, { orIgnore: true }),
		);
		auditRows += page.length;
	}
	const files = deps.writeFiles(outDir, groups);
	const floor = maxId === null ? null : maxId + ID_FLOOR_GAP;
	return {
		mode,
		source,
		target,
		startedAt,
		fromId,
		rows,
		minId,
		maxId,
		auditRows,
		outDir,
		files: files.length,
		apply: files.length > 0 ? applyCommand(target, outDir, perFile) : null,
		// The rest of the runbook, filled in with this run's numbers (bulk only).
		next:
			mode === 'bulk' && floor !== null
				? {
						idFloor: `npx wrangler d1 execute ${target} --remote --command "INSERT INTO ${ACCESS_LOG_TABLE} (id, ip_hash, ip_masked, tool_name, domain) VALUES (${floor}, 'sentinel', 'sentinel', 'sentinel', 'sentinel'); DELETE FROM ${ACCESS_LOG_TABLE} WHERE id = ${floor}"`,
						checkFloor: `npx wrangler d1 execute ${target} --remote --command "SELECT seq FROM sqlite_sequence WHERE name = '${ACCESS_LOG_TABLE}'"`,
						verify: `${SCRIPT} --verify --to-id ${maxId} --since <unix-seconds inside the retention window>`,
						delta: `${SCRIPT} --delta --from-id ${maxId} --out <fresh dir>`,
						replayErasures: `${SCRIPT} --replay-erasures --since ${startedAt} --out <fresh dir>`,
					}
				: null,
	};
}

function isoDay(day) {
	return new Date(day * 86_400_000).toISOString().slice(0, 10);
}

function setDifference(left, right) {
	const other = new Set(right);
	return left.filter((value) => !other.has(value));
}

function sample(values) {
	return { count: values.length, sample: values.slice(0, 20) };
}

/** @param {{ source: string, target: string, fromId?: number, toId?: number, since?: number, pageSize?: number }} options */
export async function runVerify({ source, target, fromId = 0, toId, since, pageSize = PAGE_SIZE }, deps) {
	const read = createReader(deps.query);
	const upper = toId ?? (await read(source, `SELECT MAX(id) AS max_id FROM ${ACCESS_LOG_TABLE}`))[0]?.max_id ?? 0;
	const sinceClause = since === undefined ? '' : ` AND created_at >= ${nonNegativeInteger(since, 'since')}`;
	const where = `id > ${nonNegativeInteger(fromId, 'fromId')} AND id <= ${nonNegativeInteger(upper, 'toId')}${sinceClause}`;
	const measure = async (database) => {
		const [aggregate] = await read(
			database,
			`SELECT COUNT(*) AS count, COALESCE(SUM(id), 0) AS sum_id, MIN(created_at) AS min_created_at, MAX(created_at) AS max_created_at FROM ${ACCESS_LOG_TABLE} WHERE ${where}`,
		);
		const days = await read(
			database,
			`SELECT created_at / 86400 AS day, COUNT(*) AS count FROM ${ACCESS_LOG_TABLE} WHERE ${where} GROUP BY day ORDER BY day`,
		);
		const ids = await collect(
			keysetPages(
				read,
				database,
				(after, size) =>
					`SELECT id FROM ${ACCESS_LOG_TABLE} WHERE id > ${after} AND id <= ${upper}${sinceClause} ORDER BY id LIMIT ${size}`,
				'id',
				fromId,
				pageSize,
			),
			(row) => row.id,
		);
		const auditIds = await collect(
			keysetPages(
				read,
				database,
				(after, size) => `SELECT id FROM ${ACCESS_LOG_AUDIT_TABLE} WHERE id > ${sqlLiteral(after)} ORDER BY id LIMIT ${size}`,
				'id',
				'',
				pageSize,
			),
			(row) => row.id,
		);
		return { aggregate, days: new Map(days.map((row) => [row.day, row.count])), ids, auditIds };
	};
	const src = await measure(source);
	const tgt = await measure(target);
	const mismatchedDays = [...new Set([...src.days.keys(), ...tgt.days.keys()])]
		.sort((a, b) => a - b)
		.filter((day) => (src.days.get(day) ?? 0) !== (tgt.days.get(day) ?? 0))
		.map((day) => ({ day: isoDay(day), source: src.days.get(day) ?? 0, target: tgt.days.get(day) ?? 0 }));
	const missingOnTarget = setDifference(src.ids, tgt.ids);
	const extraOnTarget = setDifference(tgt.ids, src.ids);
	const auditMissingOnTarget = setDifference(src.auditIds, tgt.auditIds);
	const aggregatesMatch = ['count', 'sum_id', 'min_created_at', 'max_created_at'].every(
		(key) => src.aggregate?.[key] === tgt.aggregate?.[key],
	);
	return {
		mode: 'verify',
		ok:
			aggregatesMatch &&
			mismatchedDays.length === 0 &&
			missingOnTarget.length === 0 &&
			extraOnTarget.length === 0 &&
			auditMissingOnTarget.length === 0,
		range: { fromId, toId: upper, since: since ?? null },
		source: { database: source, ...src.aggregate, auditRows: src.auditIds.length },
		target: { database: target, ...tgt.aggregate, auditRows: tgt.auditIds.length },
		missingOnTarget: sample(missingOnTarget),
		extraOnTarget: sample(extraOnTarget),
		mismatchedDays,
		auditMissingOnTarget: sample(auditMissingOnTarget),
	};
}

export async function runReplayErasures({ source, target, since, outDir, pageSize = PAGE_SIZE }, deps) {
	deps.prepareOutDir(outDir);
	const read = createReader(deps.query);
	const erasures = new Map();
	for (const database of [source, target]) {
		const pageSql = (after, size) =>
			`SELECT id, created_at, ip_hash, scope FROM ${ACCESS_LOG_AUDIT_TABLE} WHERE action = '${ERASE_ACTION}' AND created_at >= ${nonNegativeInteger(since, 'since')} AND id > ${sqlLiteral(after)} ORDER BY id LIMIT ${size}`;
		for await (const page of keysetPages(read, database, pageSql, 'id', '', pageSize)) {
			for (const row of page) erasures.set(row.id, row);
		}
	}
	const statements = [...new Set([...erasures.values()].sort((a, b) => a.created_at - b.created_at).map(erasureDeleteSql))];
	const groups = [];
	for (let index = 0; index < statements.length; index += MAX_ROWS_PER_STATEMENT) {
		groups.push({ label: 'erasures', statements: statements.slice(index, index + MAX_ROWS_PER_STATEMENT) });
	}
	const files = deps.writeFiles(outDir, groups);
	return {
		mode: 'replay-erasures',
		source,
		target,
		since,
		erasures: erasures.size,
		statements: statements.length,
		outDir,
		files: files.length,
		apply: files.length > 0 ? applyCommand(target, outDir, false) : null,
	};
}

const MODES = { '--bulk': 'bulk', '--delta': 'delta', '--verify': 'verify', '--replay-erasures': 'replay-erasures' };
const VALUE_FLAGS = {
	'--out': 'outDir',
	'--from-id': 'fromId',
	'--to-id': 'toId',
	'--since': 'since',
	'--source': 'source',
	'--target': 'target',
};
const ALLOWED = {
	bulk: ['outDir'],
	delta: ['outDir', 'fromId'],
	verify: ['fromId', 'toId', 'since'],
	'replay-erasures': ['outDir', 'since'],
};
const REQUIRED = { bulk: ['outDir'], delta: ['outDir', 'fromId'], verify: [], 'replay-erasures': ['outDir', 'since'] };
const INTEGER_OPTIONS = new Set(['fromId', 'toId', 'since']);
const flagFor = (key) => Object.keys(VALUE_FLAGS).find((flag) => VALUE_FLAGS[flag] === key);

export function parseArgs(argv) {
	const options = { source: DEFAULT_SOURCE, target: DEFAULT_TARGET };
	const seen = new Set();
	let mode;
	for (let index = 0; index < argv.length; index += 1) {
		const flag = argv[index];
		if (MODES[flag]) {
			if (mode) throw new UsageError('give exactly one of --bulk, --delta, --verify, --replay-erasures');
			mode = MODES[flag];
			continue;
		}
		const key = VALUE_FLAGS[flag];
		const value = argv[index + 1];
		if (!key || value === undefined || value.startsWith('--') || seen.has(key))
			throw new UsageError(`unexpected or repeated argument: ${flag}`);
		seen.add(key);
		options[key] = INTEGER_OPTIONS.has(key) ? nonNegativeInteger(/^\d+$/.test(value) ? Number(value) : NaN, flag) : value;
		index += 1;
	}
	if (!mode) throw new UsageError('give exactly one of --bulk, --delta, --verify, --replay-erasures');
	for (const key of seen) {
		if (!['source', 'target', ...ALLOWED[mode]].includes(key)) throw new UsageError(`--${mode} does not take ${flagFor(key)}`);
	}
	for (const key of REQUIRED[mode]) {
		if (!seen.has(key)) throw new UsageError(`--${mode} requires ${flagFor(key)}`);
	}
	for (const key of ['source', 'target']) {
		if (!/^[A-Za-z0-9_-]+$/.test(options[key])) throw new UsageError(`--${key} must be a D1 database name (letters, digits, _ or -)`);
	}
	if (options.source === options.target) throw new UsageError('--source and --target must be different databases');
	return { mode, ...options };
}

export function parseWranglerRows(stdout) {
	let parsed;
	try {
		parsed = JSON.parse(stdout);
	} catch {
		throw new Error('wrangler returned invalid JSON');
	}
	const statements = Array.isArray(parsed) ? parsed : [parsed];
	if (statements.length !== 1 || statements[0]?.success !== true || !Array.isArray(statements[0].results)) {
		throw new Error('wrangler query did not succeed');
	}
	return statements[0].results;
}

export function wranglerQuery(database, sql, dependencies = {}) {
	assertReadOnlySql(sql);
	const spawn = dependencies.spawnSync ?? spawnSync;
	const wranglerCliPath = dependencies.wranglerCliPath ?? createRequire(import.meta.url).resolve('wrangler');
	const result = spawn(process.execPath, [wranglerCliPath, 'd1', 'execute', database, '--remote', '--json', '--command', sql], {
		cwd: REPO_ROOT,
		encoding: 'utf8',
		maxBuffer: 512 * 1024 * 1024,
		stdio: ['ignore', 'pipe', 'pipe'],
	});
	if (result.error) throw result.error;
	if (result.status !== 0) {
		throw new Error(
			`wrangler d1 execute ${database} failed (${result.status ?? 'no exit status'}): ${(result.stderr || result.stdout || '').slice(0, 2000)}`,
		);
	}
	return parseWranglerRows(result.stdout);
}

async function main() {
	try {
		const { mode, ...options } = parseArgs(process.argv.slice(2));
		const deps = {
			query: async (database, sql) => wranglerQuery(database, sql),
			prepareOutDir,
			writeFiles: writeSqlFiles,
			now: () => Math.floor(Date.now() / 1000),
		};
		let summary;
		if (mode === 'verify') summary = await runVerify(options, deps);
		else if (mode === 'replay-erasures') summary = await runReplayErasures(options, deps);
		else summary = await runCopy({ mode, ...options }, deps);
		console.log(JSON.stringify(summary, null, 2));
		if (mode === 'verify' && !summary.ok) process.exitCode = 1;
	} catch (error) {
		console.error(`FATAL: ${error instanceof Error ? error.message : String(error)}`);
		process.exitCode = 2;
	}
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
