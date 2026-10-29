// SPDX-License-Identifier: BUSL-1.1
/**
 * The T0 indexer (queue consumer of bv-ct-index-entries), the kill switch, and the Worker's queue and
 * compaction cron wiring.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import worker from '../index';
import { runCompactionJob } from '../indexer/compact';
import { COMPACTION_CRON, runCompactionCron } from '../indexer/plan';
import { createReader } from '../indexer/read';
import { KILLED_RETRY_DELAY_SECONDS, indexEntries } from '../indexer/write';
import type { NameObservation } from '../types';
import {
	DAY_S,
	HOUR_MS,
	T,
	T_S,
	applyCatalog,
	batchBody,
	catalog,
	fakeBatch,
	ingest,
	objectKeys,
	obs,
	sib,
	testEnv,
	withFault,
} from './indexer-harness';

const DAY_MS = 24 * HOUR_MS;

beforeEach(applyCatalog);

async function ledger() {
	const env = testEnv();
	const { results } = await env.CURSORS.prepare('SELECT day, r2_class_a, r2_class_b, d1_rows, killed FROM ops_ledger ORDER BY day').all();
	return results;
}

async function meta() {
	return createReader(testEnv(), () => T).meta();
}

describe('T0 indexer', () => {
	it('writes one names run and one siblings run per batch, and a scan finds them', async () => {
		const env = testEnv();
		const batch = fakeBatch('bv-ct-index-entries', [
			batchBody([obs('www.example.com'), obs('*.example.com', { issuer: 'E5' })], [sib('example.com', 'other.org')]),
			batchBody([obs('api.example.com'), obs('foo.other.org'), obs('example.com', { firstSeen: 1 })]),
		]);
		const outcome = await indexEntries(batch, env, T);

		expect(outcome).toEqual({ killed: false, names: 5, siblings: 1, rejected: 0 });
		expect(batch.ackedAll).toBe(true);
		const runs = await catalog();
		expect(runs.map((run) => [run.generation, run.tier, run.rows])).toEqual([
			[1, 0, 4],
			[1, 0, 1],
		]);
		expect(await objectKeys()).toEqual(runs.map((run) => run.r2_key).sort());

		const reader = createReader(env, () => T);
		const page = await reader.scan('example.com', { limit: 10 });
		expect(page.truncated).toBe(false);
		expect(page.cursor).toBeNull();
		// *.example.com folded into example.com: wildcard ORed, firstSeen min, issuer from the later notAfter (a tie,
		// broken by field order: 'R11' > 'E5').
		expect(page.names.map((row) => [row.name, row.wildcard, row.firstSeen, row.issuer])).toEqual([
			['example.com', true, 1, 'R11'],
			['api.example.com', false, obs('x.example.com').firstSeen, 'R11'],
			['www.example.com', false, obs('x.example.com').firstSeen, 'R11'],
		]);
		expect((await reader.siblings('example.com', { limit: 10 })).siblings.map((row) => row.sibling)).toEqual(['other.org']);
	});

	it('sets index_started_at once, only advances fresh_through, and counts its ops in the ledger', async () => {
		const env = testEnv();
		await ingest(env, T, [obs('a.example.com')]);
		await ingest(env, T + HOUR_MS, [obs('b.example.com')], [sib('example.com', 'x.net')]);
		await ingest(env, T - HOUR_MS, [obs('c.example.com')]);

		expect(await meta()).toEqual({
			indexStartedAt: new Date(T).toISOString(),
			freshThrough: new Date(T + HOUR_MS).toISOString(),
			// The indexer writes no cursors; with none, the backlog is unknown, not zero.
			entriesBehind: null,
			generation: 1,
		});
		// One row per day: 4 puts (3 names runs, 1 siblings run), no GETs, and the D1 rows the batches wrote.
		expect(await ledger()).toEqual([{ day: new Date(T).toISOString().slice(0, 10), r2_class_a: 4, r2_class_b: 0, d1_rows: 13, killed: 0 }]);
	});

	it('acks nothing when the R2 put or the D1 batch fails', async () => {
		const failingPut = testEnv({
			INDEX: withFault(testEnv().INDEX, 'put', async () => Promise.reject(new Error('injected R2 put failure'))),
		});
		const first = fakeBatch('bv-ct-index-entries', [batchBody([obs('www.example.com')])]);
		await expect(indexEntries(first, failingPut, T)).rejects.toThrow('injected R2 put failure');
		expect(first.ackedAll).toBe(false);

		const failingD1 = testEnv({
			CURSORS: withFault(testEnv().CURSORS, 'batch', async () => Promise.reject(new Error('injected D1 failure'))),
		});
		const second = fakeBatch('bv-ct-index-entries', [batchBody([obs('www.example.com')])]);
		await expect(indexEntries(second, failingD1, T)).rejects.toThrow('injected D1 failure');
		expect(second.ackedAll).toBe(false);

		expect(await catalog()).toEqual([]);
		expect(await meta()).toMatchObject({ indexStartedAt: null, freshThrough: null });
	});

	it('drops observations whose key disagrees with the codec, and acks malformed messages alone', async () => {
		const env = testEnv();
		const forged = { ...obs('evil.example.org'), key: obs('www.example.com').key };
		const intoSiblings = { ...obs('www.example.net'), key: sib('example.net', 'a.org').key };
		const badSibling = { ...sib('example.com', 'b.org'), key: sib('example.com', 'c.org').key };
		const batch = fakeBatch('bv-ct-index-entries', [
			batchBody([obs('ok.example.com'), forged, intoSiblings, { ...obs('n.example.com'), notAfter: 1.5 }], [badSibling]),
			{ names: 'not an array' },
			null,
		]);
		const outcome = await indexEntries(batch, env, T);

		expect(outcome).toEqual({ killed: false, names: 1, siblings: 0, rejected: 6 });
		expect(batch.acked).toEqual(['m1', 'm2']);
		expect(batch.ackedAll).toBe(true);
		expect((await createReader(env, () => T).scan('example.com', { limit: 10 })).names.map((row) => row.name)).toEqual(['ok.example.com']);
	});

	it('stores certificate details from the queue, and drops malformed details but keeps the row and its names', async () => {
		const env = testEnv();
		const details = {
			notBefore: T_S - DAY_S,
			serial: '0a1b',
			keyType: 'ec' as const,
			keyBits: 256,
			sigAlg: 'ecdsa-with-SHA256',
			sanCount: 3,
		};
		const malformed = [
			{ ...details, serial: 'XYZ' },
			{ ...details, keyType: 'dsa' },
			{ ...details, keyBits: -1 },
			{ ...details, sigAlg: 'x'.repeat(65) },
			{ ...details, sanCount: 1.5 },
			'not an object',
		];
		const rows = [obs('good.example.com', { details }), ...malformed.map((bad, i) => ({ ...obs(`bad${i}.example.com`), details: bad }))];
		const outcome = await indexEntries(fakeBatch('bv-ct-index-entries', [batchBody(rows as NameObservation[], [])]), env, T);

		expect(outcome).toMatchObject({ names: rows.length, rejected: 0 });
		const stored = (await createReader(env, () => T).scan('example.com', { limit: 10 })).names;
		expect(stored.find((row) => row.name === 'good.example.com')?.details).toEqual(details);
		expect(stored.filter((row) => row.name.startsWith('bad')).map((row) => row.details)).toEqual(malformed.map(() => undefined));
	});
});

describe('kill switch', () => {
	it('stops the indexer, the planner and jobs, stays on across midnight, and leaves reads alone', async () => {
		const env = testEnv();
		await ingest(env, T, [obs('www.example.com')]);
		// T is 01:05, so this is the 03:17 tick, which plans every tier.
		const plannedBeforeKill = (await runCompactionCron(env, T + 2 * HOUR_MS + 12 * 60_000)).jobs;
		expect(plannedBeforeKill).toHaveLength(1);
		await env.CURSORS.prepare('UPDATE ops_ledger SET killed = 1').run();

		// Next UTC day: the kill set on an earlier day's row still applies.
		const nextDay = T + DAY_MS;
		const batch = await ingest(env, nextDay, [obs('new.example.com')]);
		expect(batch.retriedAll).toEqual({ delaySeconds: KILLED_RETRY_DELAY_SECONDS });
		expect(batch.ackedAll).toBe(false);
		expect(await runCompactionCron(env, nextDay)).toEqual({ killed: true, snapshot: null, jobs: [] });
		expect(await runCompactionJob(env, plannedBeforeKill[0]!, undefined, nextDay)).toBe('killed');
		expect((await catalog()).map((run) => run.tier)).toEqual([0]);
		expect(await objectKeys()).toHaveLength(1);
		expect((await createReader(env, () => nextDay).scan('example.com', { limit: 10 })).names.map((row) => row.name)).toEqual([
			'www.example.com',
		]);

		// A fresh row for today does not clear an earlier kill; clearing every row resumes the writers.
		await env.CURSORS.prepare('INSERT INTO ops_ledger (day, killed) VALUES (?1, 0)')
			.bind(new Date(nextDay).toISOString().slice(0, 10))
			.run();
		expect((await ingest(env, nextDay, [obs('new.example.com')])).ackedAll).toBe(false);
		await env.CURSORS.prepare('UPDATE ops_ledger SET killed = 0').run();
		expect((await ingest(env, nextDay, [obs('new.example.com')])).ackedAll).toBe(true);
	});
});

describe('Worker wiring', () => {
	const controller = (cron: string, scheduledTime: number) => ({ cron, scheduledTime, noRetry: () => undefined }) as ScheduledController;

	it('routes each queue to its consumer and plans compaction on the COMPACTION_CRON cron', async () => {
		const env = testEnv();
		await worker.queue(fakeBatch('bv-ct-index-entries', [batchBody([obs('www.example.com')])]), env);
		expect((await catalog()).map((run) => run.tier)).toEqual([0]);

		// The :17 tick two hours on, which plans every T0 run that is due.
		await worker.scheduled(controller(COMPACTION_CRON, Math.floor(Date.now() / HOUR_MS) * HOUR_MS + 2 * HOUR_MS + 17 * 60_000), env);
		expect(env.queue.sent.map((job) => job.tier)).toEqual([1]);

		const jobs = fakeBatch('bv-ct-index-compact', [env.queue.sent[0], { not: 'a job' }]);
		await worker.queue(jobs, env);
		expect(jobs.acked).toEqual(['m0', 'm1']);
		expect((await catalog()).map((run) => run.tier)).toEqual([1]);

		await expect(worker.queue(fakeBatch('some-other-queue', []), env)).rejects.toThrow('no consumer for queue some-other-queue');
	});
});
