// SPDX-License-Identifier: BUSL-1.1
/**
 * Worker wiring of the bounded catch-up reader: its own queue `bv-ct-index-catchup` (routed by batch.queue, apart from the
 * tailer's `bv-ct-index-tail`), the 2-minute cron dispatching to the CATCHUP binding, the binding-absent fallback, and a thrown
 * run being logged, not rethrown (the consumer has max_retries 0).
 */

import { env } from 'cloudflare:workers';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import cursorsSql from '../../migrations/0001_log_cursors.sql?raw';
import catalogSql from '../../migrations/0002_catalog.sql?raw';
import cursorErrorsSql from '../../migrations/0003_cursor_errors.sql?raw';
import backfillSql from '../../migrations/0006_log_backfill.sql?raw';
import worker, { CATCHUP_QUEUE, TAIL_QUEUE, type Env } from '../index';
import { CATCHUP_CRON, CATCHUP_KILL_KEY, type CatchupRequest } from '../tailer/catchup';
import { fakeBatch, testEnv } from './indexer-harness';

const db = (env as unknown as Env).CURSORS;
const ROW = { log_id: 'readonly-log-id=', url: 'https://readonly.ct.test/2027h1/' };

async function lines(run: () => Promise<void>): Promise<Array<Record<string, unknown>>> {
	const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
	try {
		await run();
		return log.mock.calls.map(([line]) => JSON.parse(String(line)) as Record<string, unknown>);
	} finally {
		log.mockRestore();
	}
}

const request = (): CatchupRequest => ({ kind: 'catchup', scheduledTime: Date.now(), logId: ROW.log_id, upperIndex: 1_000 });

beforeEach(async () => {
	await db.batch(['log_cursors', 'runs', 'meta', 'ops_ledger', 'log_backfill'].map((table) => db.prepare(`DROP TABLE IF EXISTS ${table}`)));
	for (const sql of [cursorsSql, catalogSql, cursorErrorsSql, backfillSql]) {
		const statements = sql
			.replace(/--.*$/gm, '')
			.split(';')
			.map((statement) => statement.trim())
			.filter((statement) => statement !== '');
		await db.batch(statements.map((statement) => db.prepare(statement)));
	}
	await db
		.prepare('INSERT INTO log_backfill (log_id, kind, url, lower_index, next_index, upper_index) VALUES (?, ?, ?, 0, 0, 1000)')
		.bind(ROW.log_id, 'rfc6962', ROW.url)
		.run();
});

afterEach(() => vi.unstubAllGlobals());

describe('the catch-up queue', () => {
	it('routes bv-ct-index-catchup to the catch-up reader and acks the message', async () => {
		await db.prepare('INSERT INTO meta (k, v) VALUES (?, ?)').bind(CATCHUP_KILL_KEY, '1').run();
		const batch = fakeBatch(CATCHUP_QUEUE, [request()]);
		const out = await lines(() => worker.queue(batch, testEnv()));

		expect(out).toEqual([expect.objectContaining({ event: 'ct_catchup_run', killed: true })]);
		expect(batch.acked).toEqual(['m0']);
	});

	it('logs a malformed catch-up message and acks it', async () => {
		const batch = fakeBatch(CATCHUP_QUEUE, [{ kind: 'something-else' }]);
		const out = await lines(() => worker.queue(batch, testEnv()));
		expect(out).toEqual([{ event: 'ct_catchup_run', skipped: 'malformed' }]);
		expect(batch.acked).toEqual(['m0']);
	});

	it('a run that throws is logged as ct_catchup_error with a bounded message, acked, and not rethrown', async () => {
		await db.prepare('DROP TABLE meta').run(); // the kill-switch read fails closed: the run throws
		const batch = fakeBatch(CATCHUP_QUEUE, [request()]);
		let thrown: unknown = null;
		const out = await lines(async () => {
			try {
				await worker.queue(batch, testEnv());
			} catch (error) {
				thrown = error;
			}
		});

		expect(thrown).toBeNull();
		expect(out).toHaveLength(1);
		expect(out[0]).toMatchObject({ event: 'ct_catchup_error' });
		expect(String(out[0]!.error).length).toBeLessThanOrEqual(300);
		expect(batch.acked).toEqual(['m0']);
	});

	it('leaves the tail queue exactly as it was: a catch-up-shaped body there is a malformed shard, not a catch-up run', async () => {
		const fetchSpy = vi.fn(async () => new Response('no', { status: 500 }));
		vi.stubGlobal('fetch', fetchSpy);
		const batch = fakeBatch(TAIL_QUEUE, [request()]);
		const out = await lines(() => worker.queue(batch, testEnv()));

		expect(out).toEqual([{ event: 'ct_tailer_shard_skipped', shard: -1, skipped: 'malformed' }]);
		expect(batch.acked).toEqual(['m0']);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('still refuses a queue it has no consumer for', async () => {
		await expect(worker.queue(fakeBatch('bv-ct-index-other', []), testEnv())).rejects.toThrow('no consumer for queue');
	});
});

describe(`the ${CATCHUP_CRON} cron`, () => {
	const scheduled = (e: Env) => worker.scheduled({ cron: CATCHUP_CRON, scheduledTime: Date.now(), noRetry: () => undefined }, e);

	it('dispatches one message per claimable row to the CATCHUP queue, and reads nothing itself', async () => {
		const sent: Array<{ body: CatchupRequest }> = [];
		const CATCHUP = {
			async sendBatch(messages: Array<{ body: CatchupRequest }>) {
				sent.push(...messages);
			},
		} as unknown as Queue<CatchupRequest>;
		const fetchSpy = vi.fn(async () => new Response('no', { status: 500 }));
		vi.stubGlobal('fetch', fetchSpy);
		const out = await lines(() => scheduled({ ...testEnv(), CATCHUP } as Env));

		expect(sent.map((m) => m.body)).toEqual([expect.objectContaining({ kind: 'catchup', logId: ROW.log_id, upperIndex: 1_000 })]);
		expect(out).toEqual([expect.objectContaining({ event: 'ct_catchup_dispatch', rows: 1, sent: 1, failed: null })]);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('without the CATCHUP binding reads the first claimable row itself (the bounded fallback)', async () => {
		await db.prepare('INSERT INTO meta (k, v) VALUES (?, ?)').bind(CATCHUP_KILL_KEY, '1').run();
		const out = await lines(() => scheduled(testEnv() as Env));
		expect(out).toEqual([expect.objectContaining({ event: 'ct_catchup_run', killed: true })]);
	});

	it('without the CATCHUP binding the fallback runs one row through the reader (a 429 is a deferral on the row)', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => new Response('slow', { status: 429 })),
		);
		const out = await lines(() => scheduled(testEnv() as Env));
		expect(out).toEqual([expect.objectContaining({ event: 'ct_catchup_run', rows: 1 })]);
		const row = await db
			.prepare('SELECT hold_until FROM log_backfill WHERE log_id = ?')
			.bind(ROW.log_id)
			.first<{ hold_until: string | null }>();
		expect(row?.hold_until).not.toBeNull(); // backed off
	});
});
