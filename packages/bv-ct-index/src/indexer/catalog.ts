// SPDX-License-Identifier: BUSL-1.1
/**
 * The D1 side of the indexer (migrations/0002_catalog.sql): the `runs` catalog, `meta` and the `ops_ledger`
 * kill switch.
 *
 * Generations: every run row belongs to one generation, and readers and writers use `meta.current_generation`
 * (absent = 1). Writers resolve it inside their own SQL statement, so a write lands in whatever generation is
 * current when D1 runs it, never in one read a moment earlier. Run ids are `<generation>:<r2_key>`, so the
 * weekly snapshot (generations.ts) can copy every row under a new generation while the copies share R2 objects.
 *
 * D1 binds a JS number as REAL, and REAL 2 concatenates as '2.0', so every statement that turns a bound
 * generation into text casts it to INTEGER first.
 */

import type { RunDescriptor } from '../types';

export const DEFAULT_GENERATION = 1;
/** Every run object lives under this R2 prefix; the garbage sweep lists only it. */
export const RUNS_PREFIX = 'runs/';
export const HOUR_MS = 3_600_000;
export const DAY_MS = 24 * HOUR_MS;

/** The current generation as a SQL expression, for statements that must resolve it atomically. */
export const CURRENT_GENERATION_SQL = `COALESCE((SELECT CAST(v AS INTEGER) FROM meta WHERE k = 'current_generation'), ${DEFAULT_GENERATION})`;

/** Column list of `runs`, in the order of RunDescriptor. */
export const RUN_COLUMNS = 'id, generation, tier, key_lo, key_hi, r2_key, rows, bytes, block_index, created_at';

export function runId(generation: number, r2Key: string): string {
	return `${generation}:${r2Key}`;
}

/** The R2 key inside a run id. A job message carries ids only, and must still find the objects once the rows are gone. */
export function r2KeyOfRunId(id: string): string {
	return id.slice(id.indexOf(':') + 1);
}

export function utcDay(ms: number): string {
	return new Date(ms).toISOString().slice(0, 10);
}

export async function currentGeneration(db: D1Database): Promise<number> {
	const row = await db.prepare(`SELECT ${CURRENT_GENERATION_SQL} AS g`).first<{ g: number }>();
	return Number(row?.g ?? DEFAULT_GENERATION);
}

/** Run rows with their block index, by id. Ids travel as one JSON parameter, so there is no 100-parameter cap. */
export async function runsByIds(db: D1Database, ids: readonly string[]): Promise<RunDescriptor[]> {
	const { results } = await db
		.prepare(`SELECT ${RUN_COLUMNS} FROM runs WHERE id IN (SELECT value FROM json_each(?1))`)
		.bind(JSON.stringify(ids))
		.all<RunDescriptor>();
	return results;
}

/** Ops one writer adds to the day's ledger row. R2 deletes are free, so they are not counted. */
export interface Ops {
	r2ClassA: number;
	r2ClassB: number;
	d1Rows: number;
}

/**
 * Adds `ops` to the ledger row of the UTC day of `nowMs`. A new day's row inherits the latest earlier row's
 * `killed`, so the kill switch stays on across midnight until an operator clears it. Columns an operator
 * left NULL (e.g. a row inserted with only `killed = 1`) count as 0.
 */
export function ledgerStatement(db: D1Database, nowMs: number, ops: Ops): D1PreparedStatement {
	return db
		.prepare(
			`INSERT INTO ops_ledger (day, r2_class_a, r2_class_b, d1_rows, killed)
			 VALUES (?1, ?2, ?3, ?4, COALESCE((SELECT killed FROM ops_ledger WHERE day < ?1 ORDER BY day DESC LIMIT 1), 0))
			 ON CONFLICT (day) DO UPDATE SET
				r2_class_a = COALESCE(r2_class_a, 0) + excluded.r2_class_a,
				r2_class_b = COALESCE(r2_class_b, 0) + excluded.r2_class_b,
				d1_rows = COALESCE(d1_rows, 0) + excluded.d1_rows`,
		)
		.bind(utcDay(nowMs), ops.r2ClassA, ops.r2ClassB, ops.d1Rows);
}

/**
 * The kill switch: `killed = 1` on the latest ledger row up to today stops every writer (the T0 indexer,
 * the compaction planner and jobs, the weekly snapshot). Reads continue.
 */
export async function isKilled(db: D1Database, nowMs: number): Promise<boolean> {
	const row = await db
		.prepare('SELECT killed FROM ops_ledger WHERE day <= ?1 ORDER BY day DESC LIMIT 1')
		.bind(utcDay(nowMs))
		.first<{ killed: number | null }>();
	return Number(row?.killed ?? 0) === 1;
}

/**
 * Deletes the R2 objects among `r2Keys` that no catalog row of any generation references. Always safe for a
 * run that has left the catalog: whatever removed its row (a compaction swap, a retired generation) made the
 * object garbage, and a retained snapshot still referencing it keeps it.
 */
export async function deleteUnreferenced(db: D1Database, bucket: R2Bucket, r2Keys: readonly string[]): Promise<number> {
	if (r2Keys.length === 0) return 0;
	const { results } = await db
		.prepare('SELECT DISTINCT r2_key FROM runs WHERE r2_key IN (SELECT value FROM json_each(?1))')
		.bind(JSON.stringify(r2Keys))
		.all<{ r2_key: string }>();
	const referenced = new Set(results.map((row) => row.r2_key));
	const garbage = [...new Set(r2Keys)].filter((key) => !referenced.has(key));
	for (let i = 0; i < garbage.length; i += 1000) await bucket.delete(garbage.slice(i, i + 1000));
	return garbage.length;
}
