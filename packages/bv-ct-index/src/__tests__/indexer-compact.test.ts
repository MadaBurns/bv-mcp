// SPDX-License-Identifier: BUSL-1.1
/**
 * Tiered compaction (planner + jobs) and generations: T0 -> T1 -> T2 -> T3 against the merge-rule oracle,
 * crash and retry safety, the weekly snapshot, rollback and the garbage sweep.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { SIBLING_PREFIX } from '../codec';
import { runCompactionJob } from '../indexer/compact';
import { rollbackGeneration } from '../indexer/generations';
import { GROUP_MAX_SHARDS, components, cutsFor, runCompactionCron } from '../indexer/plan';
import { createReader } from '../indexer/read';
import type { NameObservation, SiblingObservation } from '../types';
import {
	DAY_MS,
	DAY_S,
	HOUR_MS,
	T,
	T_S,
	applyCatalog,
	catalog,
	cronAndDrain,
	expectedRows,
	ingest,
	objectKeys,
	obs,
	sib,
	testEnv,
	withFault,
} from './indexer-harness';

beforeEach(applyCatalog);

/** Day `day` (0 = the day of T) at hh:mm UTC. */
const at = (day: number, hh: number, mm: number) => Math.floor(T / DAY_MS) * DAY_MS + day * DAY_MS + hh * HOUR_MS + mm * 60_000;
/** Small output runs, so a few hundred rows split into several parts per job. */
const SMALL = { targetRawBytes: 8 * 1024 };

function many(count: number, tag: string, overrides: (i: number) => Partial<NameObservation> = () => ({})): NameObservation[] {
	const tlds = ['com', 'org', 'uk', 'se'];
	return Array.from({ length: count }, (_, i) => obs(`${tag}-${i}.zone${i % 7}.example${i % 3}.${tlds[i % tlds.length]}`, overrides(i)));
}

const kindOf = (key: string) => (key.startsWith(SIBLING_PREFIX) ? 'sibling' : 'name');

async function assertCatalogInvariants(): Promise<void> {
	const runs = await catalog();
	for (const run of runs) expect(kindOf(run.key_lo), run.r2_key).toBe(kindOf(run.key_hi));
	// The bucket holds exactly the objects the catalog lists: compaction deleted every consumed input.
	expect(await objectKeys()).toEqual([...new Set(runs.map((run) => run.r2_key))].sort());
	const t3 = runs.filter((run) => run.tier === 3);
	for (let i = 1; i < t3.length; i++) expect(t3[i - 1]!.key_hi < t3[i]!.key_lo).toBe(true);
}

async function readAll(nowMs: number): Promise<{ names: NameObservation[]; siblings: SiblingObservation[] }> {
	const reader = createReader(testEnv(), () => nowMs);
	const names = (await Promise.all(['com', 'org', 'se', 'uk'].map((tld) => reader.scan(tld, { limit: 100_000 })))).flatMap(
		(page) => page.names,
	);
	const siblings = (await reader.siblings('example.com', { limit: 1000 })).siblings;
	return { names, siblings };
}

describe('tiered compaction', () => {
	it('T0 -> T1 -> T2 -> T3 keeps the merge rule, drops expired rows and keeps runs single-kind and T3 disjoint', async () => {
		const env = testEnv();
		const names: NameObservation[] = [];
		const siblings: SiblingObservation[] = [];
		const add = async (nowMs: number, n: NameObservation[], s: SiblingObservation[] = []) => {
			names.push(...n);
			siblings.push(...s);
			expect((await ingest(env, nowMs, n, s)).ackedAll).toBe(true);
		};

		// Day 0, hour 01: two T0 runs that overlap on every key.
		await add(
			at(0, 1, 5),
			[
				obs('example.com', { firstSeen: T_S - 100, notAfter: T_S + 90 * DAY_S, issuer: 'R10' }),
				obs('www.example.com', { notAfter: T_S + 12 * 3600 }),
				...many(240, 'a'),
			],
			[sib('example.com', 'other.org'), sib('example.com', 'gone.net', { notAfter: T_S + 6 * 3600 })],
		);
		await add(
			at(0, 1, 30),
			[
				obs('*.example.com', { firstSeen: T_S - 500, notAfter: T_S + 60 * DAY_S, issuer: 'R11' }),
				...many(240, 'a', (i) => ({ firstSeen: T_S - i, notAfter: T_S + (i % 50) * DAY_S, issuer: `I${i % 4}` })),
			],
			[sib('example.com', 'other.org', { firstSeen: T_S - 9 * DAY_S, notAfter: T_S + 30 * DAY_S })],
		);
		const t1 = await cronAndDrain(env, at(0, 3, 17), SMALL);
		expect(t1.jobs.map((job) => job.tier)).toEqual([1]);
		expect(t1.outcomes).toEqual(['applied']);
		// Hour 04: a third T0 run, its own T1 job.
		await add(at(0, 4, 5), many(60, 'b'), [sib('example.com', 'third.io')]);
		expect((await cronAndDrain(env, at(0, 5, 17), SMALL)).outcomes).toEqual(['applied']);
		expect(new Set((await catalog()).map((run) => run.tier))).toEqual(new Set([1]));
		await assertCatalogInvariants();
		expect(await readAll(at(0, 5, 17))).toEqual({
			names: expectedRows(names, Math.floor(at(0, 5, 17) / 1000)),
			siblings: expectedRows(siblings, Math.floor(at(0, 5, 17) / 1000)),
		});

		// Day 1, 00:17: the day-0 T1 runs become T2, one job per key range (names below 's\0', siblings, names above 's\1').
		const t2 = await cronAndDrain(env, at(1, 0, 17), SMALL);
		expect(t2.jobs.map((job) => job.tier)).toEqual([2, 2, 2]);
		expect(t2.outcomes).toEqual(['applied', 'applied', 'applied']);
		const t2Now = Math.floor(at(1, 0, 17) / 1000);
		const t2Runs = await catalog();
		expect(new Set(t2Runs.map((run) => run.tier))).toEqual(new Set([2]));
		// Expired rows are gone from storage, not just filtered on read: a reader whose clock is still at day 0
		// sees exactly the rows that were alive at the T2 job's plan time.
		expect(t2Runs.reduce((sum, run) => sum + run.rows, 0)).toBe(expectedRows(names, t2Now).length + expectedRows(siblings, t2Now).length);
		expect(await readAll(T)).toEqual({ names: expectedRows(names, t2Now), siblings: expectedRows(siblings, t2Now) });
		expect((await readAll(T)).names.find((row) => row.name === 'example.com')).toMatchObject({
			firstSeen: T_S - 500,
			notAfter: T_S + 90 * DAY_S,
			issuer: 'R10',
			wildcard: true,
		});
		await assertCatalogInvariants();

		// Day 1, 01:17: T2 -> T3.
		expect((await cronAndDrain(env, at(1, 1, 17), SMALL)).jobs.map((job) => job.tier)).toEqual([3, 3, 3]);
		expect(new Set((await catalog()).map((run) => run.tier))).toEqual(new Set([3]));
		await assertCatalogInvariants();

		// Day 1: new and updated rows go through T1 and T2 again and merge into the existing T3 shards.
		await add(
			at(1, 2, 5),
			[...many(100, 'a', (i) => ({ firstSeen: T_S - 1000 - i, notAfter: T_S + 70 * DAY_S, issuer: 'Z9' })), ...many(30, 'c')],
			[sib('example.com', 'fourth.dev')],
		);
		await cronAndDrain(env, at(1, 3, 17), SMALL);
		await cronAndDrain(env, at(2, 0, 17), SMALL);
		const final = await cronAndDrain(env, at(2, 1, 17), SMALL);
		expect(final.jobs.every((job) => job.tier === 3 && job.inputs.some((id) => id.includes('/t3/')))).toBe(true);
		expect(new Set((await catalog()).map((run) => run.tier))).toEqual(new Set([3]));
		expect((await catalog()).length).toBeGreaterThan(3);
		await assertCatalogInvariants();
		const finalNow = Math.floor(at(2, 1, 17) / 1000);
		expect(await readAll(at(2, 1, 17))).toEqual({ names: expectedRows(names, finalNow), siblings: expectedRows(siblings, finalNow) });
	});

	it('loses nothing when a job dies between the catalog swap and the R2 deletes, and its retry finishes the deletes', async () => {
		const env = testEnv();
		const names = [...many(50, 'a'), obs('www.example.com')];
		await ingest(env, at(0, 1, 5), names.slice(0, 30));
		await ingest(env, at(0, 1, 20), names.slice(30));
		const [job] = (await runCompactionCron(env, at(0, 2, 17))).jobs;
		const t0Keys = (await catalog()).map((run) => run.r2_key);

		const crashing = testEnv({
			INDEX: withFault(env.INDEX, 'delete', async () => Promise.reject(new Error('injected crash before R2 delete'))),
		});
		await expect(runCompactionJob(crashing, job!, SMALL, at(0, 2, 17))).rejects.toThrow('injected crash before R2 delete');
		const swapped = await catalog();
		expect(new Set(swapped.map((run) => run.tier))).toEqual(new Set([1]));
		expect(await objectKeys()).toEqual([...t0Keys, ...swapped.map((run) => run.r2_key)].sort());
		const now = Math.floor(at(0, 2, 17) / 1000);
		expect((await readAll(at(0, 2, 17))).names).toEqual(expectedRows(names, now));

		expect(await runCompactionJob(env, job!, SMALL, at(0, 2, 18))).toBe('already-applied');
		expect(await catalog()).toEqual(swapped);
		await assertCatalogInvariants();
		expect((await readAll(at(0, 2, 18))).names).toEqual(expectedRows(names, now));
	});

	it('is idempotent on retry: the same job id writes the same output keys, and one swap goes through', async () => {
		const env = testEnv();
		const names = many(120, 'a');
		await ingest(env, at(0, 1, 5), names);
		const [job] = (await runCompactionCron(env, at(0, 2, 17))).jobs;
		const t0 = await catalog();

		// Attempt 1 writes its outputs, then D1 fails before the swap.
		const failingD1 = testEnv({ CURSORS: withFault(env.CURSORS, 'batch', async () => Promise.reject(new Error('injected D1 failure'))) });
		await expect(runCompactionJob(failingD1, job!, SMALL, at(0, 2, 17))).rejects.toThrow('injected D1 failure');
		expect(await catalog()).toEqual(t0);
		const afterFailure = await objectKeys();
		expect(afterFailure.length).toBeGreaterThan(2);

		// Attempt 2 rewrites the very same keys (no orphan from attempt 1 remains) and swaps.
		expect(await runCompactionJob(env, job!, SMALL, at(0, 2, 18))).toBe('applied');
		const swapped = await catalog();
		expect(swapped.map((run) => run.r2_key).sort()).toEqual(afterFailure.filter((key) => !t0.some((run) => run.r2_key === key)));
		await assertCatalogInvariants();

		// Attempt 3 (a duplicate delivery) changes nothing.
		expect(await runCompactionJob(env, job!, SMALL, at(0, 2, 19))).toBe('already-applied');
		expect(await catalog()).toEqual(swapped);
		await assertCatalogInvariants();

		// A job re-planned later over the same inputs (a different id) finds them consumed and changes nothing.
		const replanned = { ...job!, id: 'f'.repeat(32), now: job!.now + 3600 };
		expect(await runCompactionJob(env, replanned, SMALL, at(0, 3, 17))).toBe('stale');
		expect((await catalog()).filter((run) => run.tier === 1)).toEqual(swapped);
		expect((await readAll(at(0, 3, 17))).names).toEqual(expectedRows(names, Math.floor(at(0, 3, 17) / 1000)));
	});
});

describe('planner', () => {
	it('groups runs by cut range, joining ranges a run straddles, and passes each job the cuts inside it', () => {
		const run = (key_lo: string, key_hi: string) => ({ key_lo, key_hi });
		const groups = components([run('a', 'a2'), run('b', 'c'), run('c5', 'e'), run('f', 'g')], ['b', 'd', 'f']);
		expect(groups).toEqual([
			{ runs: [run('a', 'a2')], cuts: [] },
			{ runs: [run('b', 'c'), run('c5', 'e')], cuts: ['d'] },
			{ runs: [run('f', 'g')], cuts: [] },
		]);
	});

	it('cuts at the sibling keyspace edges and at shard boundaries, never more than GROUP_MAX_SHARDS shards apart', () => {
		const shards = Array.from({ length: 200 }, (_, i) => ({ key_lo: `com\x01shard${String(i).padStart(4, '0')}` }));
		const cuts = cutsFor(shards);
		expect(cuts).toContain(SIBLING_PREFIX);
		expect(cuts).toContain('s\x01');
		const positions = cuts.filter((cut) => cut.startsWith('com')).map((cut) => shards.findIndex((shard) => shard.key_lo === cut));
		expect(positions.every((position) => position > 0)).toBe(true);
		for (const [i, position] of [0, ...positions, shards.length - 1].entries()) {
			if (i > 0) expect(position - [0, ...positions][i - 1]!).toBeLessThanOrEqual(GROUP_MAX_SHARDS);
		}
		expect(cutsFor([...shards].reverse())).toEqual(cuts);
	});
});

describe('generations', () => {
	it('snapshots weekly, keeps the previous generation intact, rolls back with one write, and sweeps garbage', async () => {
		const env = testEnv();
		const old = [obs('old.example.com'), obs('kept.example.com')];
		await ingest(env, at(0, 1, 5), old);
		const [beforeSnapshot] = (await runCompactionCron(env, at(0, 2, 17))).jobs;

		// Day 7: snapshot to generation 2, then compaction in generation 2. The generation-1 rows and objects stay.
		const week1 = await cronAndDrain(env, at(7, 2, 17));
		expect(week1.snapshot).toBe(2);
		expect(week1.outcomes).toEqual(['applied']);
		expect((await catalog(1)).map((run) => run.tier)).toEqual([0]);
		expect((await catalog(2)).map((run) => run.tier)).toEqual([1]);
		// The job planned before the snapshot is refused: its generation is no longer current.
		expect(await runCompactionJob(env, beforeSnapshot!, undefined, at(7, 2, 30))).toBe('stale');
		expect((await catalog(1)).map((run) => run.tier)).toEqual([0]);

		await ingest(env, at(7, 3, 5), [obs('new.example.com')]);
		const reader = createReader(env, () => at(7, 4, 0));
		const scanNames = async () => (await reader.scan('example.com', { limit: 100 })).names.map((row) => row.name);
		expect(await scanNames()).toEqual(['kept.example.com', 'new.example.com', 'old.example.com']);
		expect((await reader.meta()).generation).toBe(2);

		await rollbackGeneration(env.CURSORS, 1);
		expect(await scanNames()).toEqual(['kept.example.com', 'old.example.com']);
		expect((await reader.meta()).generation).toBe(1);
		await expect(rollbackGeneration(env.CURSORS, 7)).rejects.toThrow(RangeError);

		// Day 14: the next snapshot retires generation 2 (never reusing its number) and sweeps its objects.
		const week2 = await cronAndDrain(env, at(14, 2, 17));
		expect(week2.snapshot).toBe(3);
		expect(new Set((await catalog()).map((run) => run.generation))).toEqual(new Set([1, 3]));
		await assertCatalogInvariants();
		expect(await scanNames()).toEqual(['kept.example.com', 'old.example.com']);
	});
});
