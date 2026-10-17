// SPDX-License-Identifier: BUSL-1.1
/**
 * Generations: readers and writers use `meta.current_generation`. Once a week the hourly cron snapshots it: the
 * rows of every generation other than the current one are retired, the current rows are copied under a new
 * generation (the copies share the R2 objects), and the new generation becomes current. The previous
 * generation's rows, and so its objects, stay untouched for the week until the next snapshot retires them.
 * Rollback = point `current_generation` back at a retained generation (`rollbackGeneration`).
 *
 * Objects leave R2 only when no row of any generation references them: compaction deletes its unreferenced
 * inputs right after its swap, and the sweep here deletes every other unreferenced object older than
 * GC_GRACE_MS (outputs of jobs that lost a race, T0 objects of failed attempts, a retired generation's runs).
 * No R2 lifecycle rule is involved.
 *
 * `meta.generation_started_at` (ISO 8601) records the last snapshot; before the first one, `index_started_at`
 * stands in.
 */

import type { Env } from '../index';
import { CURRENT_GENERATION_SQL, DAY_MS, RUNS_PREFIX, ledgerStatement } from './catalog';

export const SNAPSHOT_INTERVAL_MS = 7 * DAY_MS;
/** An unreferenced object younger than this may belong to a write that has not committed its catalog row yet. */
export const GC_GRACE_MS = DAY_MS;

/** Takes the weekly snapshot when one is due. Returns the new generation, or null. */
export async function maybeSnapshot(env: Env, nowMs: number): Promise<number | null> {
	const db = env.CURSORS;
	const { results } = await db
		.prepare("SELECT k, v FROM meta WHERE k IN ('current_generation', 'index_started_at', 'generation_started_at')")
		.all<{ k: string; v: string }>();
	const meta = new Map(results.map((row) => [row.k, row.v]));
	const since = meta.get('generation_started_at') ?? meta.get('index_started_at');
	if (since === undefined || nowMs - Date.parse(since) < SNAPSHOT_INTERVAL_MS) return null;

	const current = await db
		.prepare(`SELECT ${CURRENT_GENERATION_SQL} AS g, (SELECT MAX(generation) FROM runs) AS top`)
		.first<{ g: number; top: number | null }>();
	const from = Number(current!.g);
	// Never reuse a number: after a rollback, a job planned for a later generation must not match the new one.
	const next = Math.max(from, Number(current!.top ?? from)) + 1;
	// Every statement re-checks that `from` is still current, so a rollback racing this batch voids all of it.
	const stillCurrent = `CAST(?1 AS INTEGER) = ${CURRENT_GENERATION_SQL}`;
	const swap = await db.batch([
		db.prepare(`DELETE FROM runs WHERE generation <> CAST(?1 AS INTEGER) AND ${stillCurrent}`).bind(String(from)),
		db
			.prepare(
				`INSERT INTO runs (id, generation, tier, key_lo, key_hi, r2_key, rows, bytes, block_index, created_at)
				 SELECT CAST(?2 AS INTEGER) || ':' || r2_key, CAST(?2 AS INTEGER), tier, key_lo, key_hi, r2_key, rows, bytes, block_index, created_at
				 FROM runs WHERE generation = CAST(?1 AS INTEGER) AND ${stillCurrent}`,
			)
			.bind(String(from), String(next)),
		db
			.prepare(
				`INSERT INTO meta (k, v) SELECT 'generation_started_at', ?2 WHERE ${stillCurrent}
				 ON CONFLICT (k) DO UPDATE SET v = excluded.v`,
			)
			.bind(String(from), new Date(nowMs).toISOString()),
		db
			.prepare(
				`INSERT INTO meta (k, v) SELECT 'current_generation', CAST(CAST(?2 AS INTEGER) AS TEXT) WHERE ${stillCurrent}
				 ON CONFLICT (k) DO UPDATE SET v = excluded.v`,
			)
			.bind(String(from), String(next)),
	]);
	const copied = swap[1]!.meta.changes;
	await db.batch([ledgerStatement(db, nowMs, { r2ClassA: 0, r2ClassB: 0, d1Rows: swap[0]!.meta.changes + copied + 2 })]);
	if (swap[3]!.meta.changes !== 1) return null;
	await collectGarbage(env, nowMs);
	return next;
}

/** Deletes every run object that no catalog row references and that is older than GC_GRACE_MS. */
export async function collectGarbage(env: Env, nowMs: number): Promise<number> {
	const db = env.CURSORS;
	const { results } = await db.prepare('SELECT DISTINCT r2_key FROM runs').all<{ r2_key: string }>();
	const referenced = new Set(results.map((row) => row.r2_key));
	let deleted = 0;
	let lists = 0;
	let cursor: string | undefined;
	do {
		const page = await env.INDEX.list({ prefix: RUNS_PREFIX, cursor, limit: 1000 });
		lists++;
		const garbage = page.objects
			.filter((object) => !referenced.has(object.key) && object.uploaded.getTime() < nowMs - GC_GRACE_MS)
			.map((object) => object.key);
		if (garbage.length > 0) await env.INDEX.delete(garbage);
		deleted += garbage.length;
		cursor = page.truncated ? page.cursor : undefined;
	} while (cursor !== undefined);
	await db.batch([ledgerStatement(db, nowMs, { r2ClassA: lists, r2ClassB: 0, d1Rows: 1 })]);
	return deleted;
}

/** Points readers and writers at a retained generation. Refuses a generation with no runs. */
export async function rollbackGeneration(db: D1Database, generation: number): Promise<void> {
	const result = await db
		.prepare(
			`INSERT INTO meta (k, v) SELECT 'current_generation', CAST(CAST(?1 AS INTEGER) AS TEXT)
			 WHERE EXISTS (SELECT 1 FROM runs WHERE generation = CAST(?1 AS INTEGER))
			 ON CONFLICT (k) DO UPDATE SET v = excluded.v`,
		)
		.bind(String(generation))
		.run();
	if (result.meta.changes !== 1) throw new RangeError(`generation ${generation} has no runs to roll back to`);
}
