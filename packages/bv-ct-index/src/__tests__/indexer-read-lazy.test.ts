// SPDX-License-Identifier: BUSL-1.1
/**
 * Lazy run opening on the read path (SQ-402): a page reads the runs that hold its rows, not every run its range
 * overlaps, and returns exactly the rows and cursors of the eager reader, which read every overlapping run from
 * its first block in range.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { SIBLING_PREFIX, decodeBlock, encodeRun, mergeSortedRuns, parseBlockIndex, rangeFor, serializeBlockIndex } from '../codec';
import { readRange } from '../indexer/blocks';
import { INDEX_BATCH_SIZE, READ_CONCURRENCY, blocksFor, catalogQuery, createReader } from '../indexer/read';
import type { NameObservation, RunRow } from '../types';
import { DAY_MS, DAY_S, HOUR_MS, T, T_S, applyCatalog, catalog, expectedRows, ingest, obs, testEnv, withFault } from './indexer-harness';
import type { TestEnv } from './indexer-harness';

beforeEach(applyCatalog);

/** 01:00 UTC today plus `second` seconds. */
const at = (second: number) => Math.floor(T / DAY_MS) * DAY_MS + HOUR_MS + second * 1_000;
const NOW_MS = at(10_000);
const NOW = Math.floor(NOW_MS / 1000);

/** An INDEX binding that records which run objects were read. */
function recordingBucket(bucket: R2Bucket) {
	const opened = new Set<string>();
	const wrapped = withFault(bucket, 'get', async (...args: unknown[]) => {
		opened.add(args[0] as string);
		return bucket.get(...(args as [string, R2GetOptions]));
	});
	return { bucket: wrapped, opened };
}

const cursorOf = (key: string) => btoa(key).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const keyOf = (cursor: string) => atob(cursor.replace(/-/g, '+').replace(/_/g, '/'));

interface Page {
	names: RunRow[];
	cursor: string | null;
}

/** The rows of one run inside the scan range, every block in range read in order. */
async function* eagerRun(env: TestEnv, run: { r2_key: string; block_index: ArrayBuffer }, lo: string, hi: string, after: string | null) {
	for (const entry of blocksFor(parseBlockIndex(run.block_index), after ?? lo, hi)) {
		for (const row of await decodeBlock(await readRange(env.INDEX, run.r2_key, entry.offset, entry.length))) {
			if (after === null ? row.key < lo : row.key <= after) continue;
			if (row.key > hi) return;
			yield row;
		}
	}
}

/** The reader before SQ-402: every overlapping run is opened and merged with `mergeSortedRuns`. */
async function eagerScan(env: TestEnv, domain: string, limit: number, cursor: string | null): Promise<Page> {
	const { lo, hi } = rangeFor(domain);
	const after = cursor === null ? null : keyOf(cursor);
	const { sql, params } = catalogQuery({ lo, hi, after, limit, siblings: false, now: NOW });
	const { results } = await env.CURSORS.prepare(sql)
		.bind(...params)
		.all<{ r2_key: string; key_lo: string; block_index: ArrayBuffer }>();
	const inputs = results.filter((run) => !run.key_lo.startsWith(SIBLING_PREFIX)).map((run) => eagerRun(env, run, lo, hi, after));
	const names: RunRow[] = [];
	for await (const row of mergeSortedRuns(inputs, NOW)) {
		if (names.length === limit) return { names, cursor: cursorOf(names.at(-1)!.key) };
		names.push(row);
	}
	return { names, cursor: null };
}

/** Pages the lazy and the eager reader in lockstep, asserting every page is the same; returns the lazy rows. */
async function expectSamePages(env: TestEnv, domain: string, limit: number): Promise<RunRow[]> {
	const reader = createReader(env, () => NOW_MS);
	const rows: RunRow[] = [];
	let cursor: string | null = null;
	do {
		const lazy = await reader.scan(domain, { limit, cursor });
		const eager = await eagerScan(env, domain, limit, cursor);
		expect({ names: lazy.names, cursor: lazy.cursor }).toEqual(eager);
		expect(lazy.truncated).toBe(eager.cursor !== null);
		rows.push(...lazy.names);
		cursor = lazy.cursor;
	} while (cursor !== null);
	return rows;
}

const inRange = (domain: string, rows: NameObservation[]) => {
	const { lo, hi } = rangeFor(domain);
	return rows.filter((row) => row.key >= lo && row.key <= hi);
};

describe('lazy run opening', () => {
	it('refills six bounded slots behind a slow shared-bound first run without emitting early', async () => {
		const env = testEnv();
		for (let i = 0; i < 12; i++) await ingest(env, at(i), [obs('a.hot.com', { issuer: `issuer-${i}` }), obs(`x${i}.hot.com`)]);
		let release!: () => void;
		const blocked = new Promise<void>((resolve) => { release = resolve; });
		let refilled!: () => void;
		const refill = new Promise<void>((resolve) => { refilled = resolve; });
		let gets = 0;
		let active = 0;
		let maxActive = 0;
		let settled = false;
		const bucket = withFault(env.INDEX, 'get', async (...args: unknown[]) => {
			const call = ++gets;
			maxActive = Math.max(maxActive, ++active);
			try {
				if (call === 1) await blocked;
				if (call === READ_CONCURRENCY + 1) refilled();
				return await env.INDEX.get(...args as [string, R2GetOptions]);
			} finally { active--; }
		});
		const scanning = createReader(testEnv({ INDEX: bucket }), () => NOW_MS).scan('hot.com', { limit: 3 });
		scanning.then(() => { settled = true; }, () => { settled = true; });
		try {
			expect(await Promise.race([refill.then(() => true), new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 1000))])).toBe(true);
			expect(settled).toBe(false);
			expect(maxActive).toBeLessThanOrEqual(READ_CONCURRENCY);
		} finally { release(); }
		const page = await scanning;
		expect({ names: page.names, cursor: page.cursor }).toEqual(await eagerScan(env, 'hot.com', 3, null));
		expect(gets).toBe(12);
	});

	it('defers a failed later run when an earlier slow run shrinks the ready barrier', async () => {
		const env = testEnv();
		await ingest(env, at(0), [obs('a.foreign.com'), obs('z.hot.com')]);
		await ingest(env, at(1), [obs('a.foreign.com'), obs('b.hot.com'), obs('c.hot.com')]);
		await ingest(env, at(2), [obs('y.hot.com')]);
		const runs = await env.CURSORS.prepare('SELECT id, r2_key FROM runs ORDER BY created_at').all<{ id: string; r2_key: string }>();
		const slowKey = runs.results[1]!.r2_key;
		const failureKey = runs.results[2]!.r2_key;
		// A valid two-block run first reads an out-of-range predecessor, then advances to the known y block.
		const predecessor = await encodeRun([obs('a.foreign.com')]);
		const later = await encodeRun([obs('y.hot.com')]);
		const bytes = new Uint8Array(predecessor.bytes.byteLength + later.bytes.byteLength);
		bytes.set(predecessor.bytes);
		bytes.set(later.bytes, predecessor.bytes.byteLength);
		await env.INDEX.put(failureKey, bytes);
		const blockIndex = [...predecessor.blockIndex, ...later.blockIndex.map((block) => ({ ...block, offset: block.offset + predecessor.bytes.byteLength }))];
		await env.CURSORS.prepare('UPDATE runs SET key_lo = ?1, key_split = NULL, block_index = ?2 WHERE id = ?3')
			.bind(obs('a.foreign.com').key, serializeBlockIndex(blockIndex), runs.results[2]!.id).run();
		const scanning = async (limit: number) => {
			let release!: () => void;
			const blocked = new Promise<void>((resolve) => { release = resolve; });
			let laterGets = 0;
			const bucket = withFault(env.INDEX, 'get', async (...args: unknown[]) => {
				if (args[0] === slowKey) await blocked;
				if (args[0] === failureKey && ++laterGets === 2) {
					// The fast predecessor can become ready at z before y fails; b/c remain blocked until afterwards.
					await new Promise<void>((resolve) => setTimeout(resolve, 30));
					setTimeout(release, 30);
					throw new Error('later y preparation failed');
				}
				return env.INDEX.get(...args as [string, R2GetOptions]);
			});
			try { return await createReader(testEnv({ INDEX: bucket }), () => NOW_MS).scan('hot.com', { limit }); }
			finally { release(); }
		};
		const page = await scanning(1);
		expect(page.names.map((row) => row.name)).toEqual(['b.hot.com']);
		expect(page.truncated).toBe(true);
		expect({ names: page.names, cursor: page.cursor }).toEqual(await eagerScan(env, 'hot.com', 1, null));
		await expect(scanning(3)).rejects.toThrow('later y preparation failed');
	});

	it('ignores a failed speculative preparation beyond the page boundary', async () => {
		const env = testEnv();
		for (let i = 0; i < 8; i++) await ingest(env, at(i), [obs(`x${i}.hot.com`)]);
		let gets = 0;
		const bucket = withFault(env.INDEX, 'get', async (...args: unknown[]) => {
			if (++gets === 3) throw new Error('unused speculative read failed');
			return env.INDEX.get(...args as [string, R2GetOptions]);
		});
		const page = await createReader(testEnv({ INDEX: bucket }), () => NOW_MS).scan('hot.com', { limit: 1 });
		expect(page.names.map((row) => row.name)).toEqual(['x0.hot.com']);
		expect(page.truncated).toBe(true);
		expect(gets).toBeGreaterThanOrEqual(3);
	});

	it('never loads indexes beyond its bounded prefix for a short page', async () => {
		const env = testEnv();
		for (let i = 0; i < INDEX_BATCH_SIZE + 8; i++) {
			await ingest(env, at(i), [obs(`x${String(i).padStart(3, '0')}.hot.com`)]);
		}
		const batches: number[] = [];
		const db = withFault(env.CURSORS, 'prepare', (statement: unknown) => {
			const prepared = env.CURSORS.prepare(statement as string);
			if (!(statement as string).startsWith('SELECT id, r2_key, block_index FROM runs WHERE id IN')) return prepared;
			return withFault(prepared, 'bind', (...args: unknown[]) => {
				batches.push((JSON.parse(args[0] as string) as string[]).length);
				return prepared.bind(...args);
			});
		});
		const page = await createReader(testEnv({ CURSORS: db }), () => NOW_MS).scan('hot.com', { limit: 1 });
		expect(page.names.map((row) => row.name)).toEqual(['x000.hot.com']);
		expect(page.truncated).toBe(true);
		expect(batches).toEqual([INDEX_BATCH_SIZE]);
	});

	it('defers later indexes, loads bounded batches, and retries a catalog swap without losing rows', async () => {
		const env = testEnv();
		await ingest(env, at(0), [obs('a.hot.com'), obs('b.hot.com')]);
		const original = (await catalog())[0]!;
		const query = { ...rangeFor('hot.com'), after: null, limit: 1, siblings: false, now: NOW };
		const { sql, params } = catalogQuery(query, true);
		const initial = await env.CURSORS.prepare(sql).bind(...params).all<{ id: string; block_index: unknown }>();
		expect(initial.results).toHaveLength(1);
		expect(initial.results[0]!.block_index).toBeNull();
		let swaps = 0;
		let loads = 0;
		const db = withFault(env.CURSORS, 'prepare', (statement: unknown) => {
			const prepared = env.CURSORS.prepare(statement as string);
			if (!(statement as string).startsWith('SELECT id, r2_key, block_index FROM runs WHERE id IN')) return prepared;
			return withFault(prepared, 'bind', (...args: unknown[]) => {
				const ids = JSON.parse(args[0] as string) as string[];
				expect(ids.length).toBeLessThanOrEqual(INDEX_BATCH_SIZE);
				const bound = prepared.bind(...args);
				return withFault(bound, 'all', async () => {
					loads++;
					if (swaps++ === 0) {
						await ingest(env, at(1), [obs('a.hot.com'), obs('b.hot.com')]);
						await env.CURSORS.prepare('DELETE FROM runs WHERE id = ?1').bind(original.id).run();
					}
					return bound.all();
				});
			});
		});
		const page = await createReader(testEnv({ CURSORS: db }), () => NOW_MS).scan('hot.com', { limit: 1 });
		expect(page.names.map((row) => row.name)).toEqual(['a.hot.com']);
		expect(page.truncated).toBe(true);
		expect(loads).toBe(2);
	});

	it('opens only the runs a 50-row page needs when all 300 runs hold the apex, and pages like the eager reader', async () => {
		const env = testEnv();
		const names: NameObservation[] = [];
		for (let i = 0; i < 300; i++) {
			// Run i holds the apex's names number i, 300 + i and 600 + i, so the first 51 names are spread over runs
			// 0-50. Its other name sorts after the apex's range.
			const batch = [0, 1, 2].map((j) => obs(`x${String(i + 300 * j).padStart(3, '0')}.hot.com`));
			batch.push(obs(`www.filler-${i}.org`));
			names.push(...batch);
			await ingest(env, at(i), batch);
		}
		expect((await catalog()).filter((run) => run.tier === 0)).toHaveLength(300);

		const lazy = recordingBucket(env.INDEX);
		const page = await createReader(testEnv({ INDEX: lazy.bucket }), () => NOW_MS).scan('hot.com', { limit: 50 });
		expect(page.names.map((row) => row.name)).toEqual(Array.from({ length: 50 }, (_, i) => `x${String(i).padStart(3, '0')}.hot.com`));
		expect(page.truncated).toBe(true);
		// Runs 0-49 hold the page and run 50 the row that truncates it. While a run must be read, the next ones in
		// key order are read alongside it, so at most READ_CONCURRENCY - 1 runs past run 50 were read ahead.
		expect(lazy.opened.size).toBeGreaterThanOrEqual(51);
		expect(lazy.opened.size).toBeLessThanOrEqual(51 + READ_CONCURRENCY - 1);

		const eager = recordingBucket(env.INDEX);
		const eagerPage = await eagerScan(testEnv({ INDEX: eager.bucket }), 'hot.com', 50, null);
		expect(eager.opened.size).toBe(300);
		expect({ names: page.names, cursor: page.cursor }).toEqual(eagerPage);

		expect(await expectSamePages(env, 'hot.com', 50)).toEqual(expectedRows(inRange('hot.com', names), NOW));
	}, 120_000);

	it('pages like the eager reader over multi-block runs that share keys, hold expired rows and straddle the range', async () => {
		const env = testEnv();
		const names: NameObservation[] = [];
		const stem = 'p'.repeat(48);
		for (let i = 0; i < 12; i++) {
			const batch: NameObservation[] = [];
			for (let j = 0; j < 1_000; j++) {
				const n = String((j * 12 + i * 5) % 2_000).padStart(4, '0');
				const expired = (i + j) % 9 === 0;
				batch.push(
					obs(`${j % 7 === 0 ? '*.' : ''}${stem}${n}.hot.com`, {
						firstSeen: T_S - i * 100 - j,
						notAfter: expired ? T_S - DAY_S : T_S + ((i % 5) + 1) * DAY_S,
						issuer: `I${(i + j) % 4}`,
					}),
				);
			}
			// Keys just below and just above the range: every run's first block straddles its start.
			batch.push(obs(`${stem}${i}.hos.com`), obs(`www.${stem}${i}.hou.com`));
			names.push(...batch);
			await ingest(env, at(i), batch);
		}
		const { results } = await env.CURSORS.prepare('SELECT block_index FROM runs').all<{ block_index: ArrayBuffer }>();
		expect(results).toHaveLength(12);
		for (const run of results) expect(parseBlockIndex(run.block_index).length).toBeGreaterThan(1);

		const expected = expectedRows(inRange('hot.com', names), NOW);
		expect(expected.length).toBeGreaterThan(1_000);
		for (const limit of [1, 37, 500]) expect(await expectSamePages(env, 'hot.com', limit)).toEqual(expected);
	}, 120_000);

	it('throws, rather than emit rows out of order, on a run whose block index puts a block after its own first key', async () => {
		const env = testEnv();
		await ingest(env, at(0), [obs('a.hot.com'), obs('b.hot.com')]);
		await ingest(env, at(1), [obs('c.hot.com')]);
		const run = await env.CURSORS.prepare('SELECT id, block_index FROM runs ORDER BY created_at LIMIT 1').first<{
			id: string;
			block_index: ArrayBuffer;
		}>();
		const [block] = parseBlockIndex(run!.block_index);
		const lying = serializeBlockIndex([{ ...block!, firstKey: rangeFor('c.hot.com').lo + '\x01' }]);
		await env.CURSORS.prepare('UPDATE runs SET block_index = ?1 WHERE id = ?2').bind(lying, run!.id).run();
		await expect(createReader(env, () => NOW_MS).scan('hot.com', { limit: 10 })).rejects.toThrow(/is not key-sorted/);
	});
});
