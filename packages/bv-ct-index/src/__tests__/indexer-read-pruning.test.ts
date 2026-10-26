// SPDX-License-Identifier: BUSL-1.1
/**
 * Read pruning end to end (SQ-401): the key filter keeps a lookup from opening runs that hold none of its keys, and
 * the interval index keeps the catalog query from reading the whole runs table.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { rangeFor, runSplitKey } from '../codec';
import { maybeSnapshot } from '../indexer/generations';
import { catalogQuery, createReader } from '../indexer/read';
import type { NameObservation } from '../types';
import { DAY_MS, HOUR_MS, T, applyCatalog, catalog, cronAndDrain, ingest, obs, sib, testEnv, withFault } from './indexer-harness';

beforeEach(applyCatalog);

/** 01:00 UTC today plus `second` seconds: every T0 run of these tests is written within one hour. */
const at = (second: number) => Math.floor(T / DAY_MS) * DAY_MS + HOUR_MS + second * 1_000;
const clock = () => at(10_000);

/** An INDEX binding that counts GETs. */
function countingBucket(bucket: R2Bucket) {
	const stats = { gets: 0 };
	const wrapped = withFault(bucket, 'get', async (...args: unknown[]) => {
		stats.gets++;
		return bucket.get(...(args as [string, R2GetOptions]));
	});
	return { bucket: wrapped, stats };
}

describe('key filter on the read path', () => {
	it('opens at most 3 of 300 T0 runs for an apex in one of them, and all 300 for an apex in every one', async () => {
		const env = testEnv();
		for (let i = 0; i < 300; i++) {
			const names: NameObservation[] = Array.from({ length: 150 }, (_, j) => obs(`h${j % 7}.apex-${i}-${j}.com`));
			names.push(obs(`run${i}.everywhere.com`), obs(`www.shop-${i}.co.nz`));
			if (i === 137) names.push(obs('www.needle.com'));
			await ingest(env, at(i), names);
		}
		expect((await catalog()).filter((run) => run.tier === 0)).toHaveLength(300);

		const needle = countingBucket(env.INDEX);
		const page = await createReader(testEnv({ INDEX: needle.bucket }), clock).scan('needle.com', { limit: 100 });
		expect(page.names.map((row) => row.name)).toEqual(['www.needle.com']);
		expect(needle.stats.gets).toBeGreaterThanOrEqual(1);
		expect(needle.stats.gets).toBeLessThanOrEqual(3);

		// Under a suffix-like second level the probe is three labels deep, so co.nz in every run does not defeat it.
		const shop = countingBucket(env.INDEX);
		const shopPage = await createReader(testEnv({ INDEX: shop.bucket }), clock).scan('shop-42.co.nz', { limit: 100 });
		expect(shopPage.names.map((row) => row.name)).toEqual(['www.shop-42.co.nz']);
		expect(shop.stats.gets).toBeLessThanOrEqual(3);

		const everywhere = countingBucket(env.INDEX);
		const all = await createReader(testEnv({ INDEX: everywhere.bucket }), clock).scan('everywhere.com', { limit: 1_000 });
		expect(all.names).toHaveLength(300);
		expect(new Set(all.names.map((row) => row.name)).size).toBe(300);
		expect(everywhere.stats.gets).toBe(300);
	}, 120_000);
});

describe('writers', () => {
	interface Columns {
		tier: number;
		key_lo: string;
		key_hi: string;
		key_split: string | null;
		filter: string | null;
	}
	const columns = async (generation: number) =>
		(
			await testEnv()
				.CURSORS.prepare(
					'SELECT tier, key_lo, key_hi, key_split, hex(key_filter) AS filter FROM runs WHERE generation = ?1 ORDER BY r2_key',
				)
				.bind(generation)
				.all<Columns>()
		).results;
	const expectIndexed = (runs: Columns[]) => {
		for (const run of runs) {
			expect(run.key_split).toBe(runSplitKey(run.key_lo, run.key_hi));
			expect(run.filter).toMatch(/^01/);
		}
	};

	it('gives T0 and compacted runs a filter and a split, and the weekly snapshot copies both', async () => {
		const env = testEnv();
		const day = Math.floor(T / DAY_MS) * DAY_MS;
		await ingest(env, at(0), [obs('a.example.com'), obs('b.shop.co.nz')], [sib('example.com', 'other.org')]);
		await ingest(env, at(60), [obs('c.example.com')]);
		const t0 = await columns(1);
		expect(t0.map((run) => run.tier)).toEqual([0, 0, 0]);
		expectIndexed(t0);

		expect((await cronAndDrain(env, day + 2 * HOUR_MS + 17 * 60_000)).outcomes).toEqual(['applied']);
		const t1 = await columns(1);
		expect(t1.map((run) => run.tier)).toEqual([1, 1]);
		expectIndexed(t1);
		const reader = createReader(env, clock);
		expect((await reader.scan('example.com', { limit: 10 })).names.map((row) => row.name)).toEqual(['a.example.com', 'c.example.com']);
		expect((await reader.siblings('example.com', { limit: 10 })).siblings.map((row) => row.sibling)).toEqual(['other.org']);

		expect(await maybeSnapshot(env, day + 8 * DAY_MS)).toBe(2);
		expect(await columns(2)).toEqual(t1);
	});

	it('still reads a run written before migration 0005, which has neither a filter nor a split', async () => {
		const env = testEnv();
		await ingest(env, at(0), [obs('www.legacy.com'), obs('x.other.com')]);
		await env.CURSORS.prepare('UPDATE runs SET key_filter = NULL, key_split = NULL').run();
		const page = await createReader(env, clock).scan('legacy.com', { limit: 10 });
		expect(page.names.map((row) => row.name)).toEqual(['www.legacy.com']);
	});
});

describe('catalog query', () => {
	/** 50 runs over the whole keyspace (like T0) and 5,000 narrow runs (like T1 in their cut ranges). */
	async function seedCatalog(): Promise<void> {
		const db = testEnv().CURSORS;
		const insert = db.prepare(
			"INSERT INTO runs (id, generation, tier, key_lo, key_hi, r2_key, rows, bytes, block_index, created_at, key_split) VALUES (?1, 1, ?2, ?3, ?4, ?1, 1, 1, x'0100', 'x', ?5)",
		);
		const statements = [];
		for (let i = 0; i < 50; i++) statements.push(insert.bind(`t0/${i}`, 0, `ac${i}`, `zw${i}`, runSplitKey(`ac${i}`, `zw${i}`)));
		for (let i = 0; i < 5_000; i++) {
			const lo = `com\x01k${String(i).padStart(5, '0')}`;
			statements.push(insert.bind(`t1/${i}`, 1, lo, `${lo}\x01zz`, runSplitKey(lo, `${lo}\x01zz`)));
		}
		for (let i = 0; i < statements.length; i += 500) await db.batch(statements.slice(i, i + 500));
	}

	it('reads the catalog rows of the overlapping runs through the interval index, not the whole table', async () => {
		await seedCatalog();
		const db = testEnv().CURSORS;
		const { lo, hi } = rangeFor('k02500.com');
		const { sql, params } = catalogQuery({ lo, hi, after: null, limit: 10, siblings: false, now: 0 });
		const result = await db
			.prepare(sql)
			.bind(...params)
			.all<{ r2_key: string }>();
		expect(result.results.map((row) => row.r2_key).sort()).toEqual([...Array.from({ length: 50 }, (_, i) => `t0/${i}`), 't1/2500'].sort());
		// The whole table is 5,050 rows; the query without the interval index read all of them (SQ-400: 54.8k of 54.8k).
		expect(result.meta.rows_read).toBeLessThan(500);

		const plan = (
			await db
				.prepare(`EXPLAIN QUERY PLAN ${sql}`)
				.bind(...params)
				.all<{ detail: string }>()
		).results.map((row) => row.detail);
		expect(plan.filter((detail) => detail.startsWith('SCAN runs'))).toEqual([]);
		expect(plan).toContain('SEARCH runs USING INTEGER PRIMARY KEY (rowid=?)');
		expect(plan).toContain('SEARCH runs USING COVERING INDEX runs_split_hi (generation=? AND key_split=? AND key_hi>?)');
		expect(plan).toContain('SEARCH runs USING COVERING INDEX runs_split_lo (generation=? AND key_split=? AND key_lo<?)');
		expect(plan).toContain('SEARCH runs USING COVERING INDEX runs_split_lo (generation=? AND key_split>? AND key_split<?)');
	});
});
