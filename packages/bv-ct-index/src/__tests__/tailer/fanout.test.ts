// SPDX-License-Identifier: BUSL-1.1
/**
 * The tailer fan-out (src/tailer/fanout.ts) and the tailer across several logs, against miniflare D1 with a fake CT
 * network: shards are dealt by how far each log is behind and sent as one queue message each, a shard message runs
 * only its own logs and is dropped when stale or malformed, the kill switch sends none, a log never drops rows on the
 * strength of another log's send that is still in flight, and no request starts after the fetch phase.
 */

import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import cursorsSql from '../../../migrations/0001_log_cursors.sql?raw';
import catalogSql from '../../../migrations/0002_catalog.sql?raw';
import cursorErrorsSql from '../../../migrations/0003_cursor_errors.sql?raw';
import type { Env } from '../../index';
import { LOG_LIST_URL, TILE_WIDTH, tilePath } from '../../tailer/ct';
import { STALE_SHARD_MS, partitionLogs, runFanout, runShard, type ShardRequest } from '../../tailer/fanout';
import { resetLogListMemo, runTailer } from '../../tailer';
import type { ObservationBatch } from '../../types';
import { STATIC_PRECERT_TILE_LEAF } from './fixtures';

const db = (env as unknown as Env).CURSORS;
const NOW = Date.parse('2026-10-17T06:00:00Z');
const interval = { start_inclusive: '2027-01-01T00:00:00Z', end_exclusive: '2027-07-01T00:00:00Z' };
const LOGS = ['a', 'b', 'c'].map((name) => ({ log_id: `${name}-log-id=`, monitoring_url: `https://${name}.ct.test/2027h1/` }));
const LIST = {
	operators: [
		{ name: "Let's Encrypt", logs: [], tiled_logs: LOGS.map((log) => ({ ...log, state: { usable: {} }, temporal_interval: interval })) },
	],
};
const SIZE = 6 * TILE_WIDTH;

const leaf = Uint8Array.from(atob(STATIC_PRECERT_TILE_LEAF), (c) => c.charCodeAt(0));
/** Every log serves the same tiles, so every log observes the same rows. */
const TILE = new Uint8Array(Array.from({ length: TILE_WIDTH }, () => [...leaf]).flat());

const TILE_URLS = new Set(
	LOGS.flatMap((log) => Array.from({ length: SIZE / TILE_WIDTH }, (_, t) => `${log.monitoring_url}tile/data/${tilePath(t)}`)),
);
const CHECKPOINTS = new Map(LOGS.map((log) => [`${log.monitoring_url}checkpoint`, `${log.log_id}\n${SIZE}\nAAAA\n\n— sig\n`]));

function respond(url: string): Response {
	if (url === LOG_LIST_URL) return Response.json(LIST);
	const checkpoint = CHECKPOINTS.get(url);
	if (checkpoint !== undefined) return new Response(checkpoint);
	if (TILE_URLS.has(url)) return new Response(TILE);
	return new Response('unexpected request', { status: 599 });
}

/** Serves LIST, every log's checkpoint and its tiles; tiles take `tileDelayMs` each. */
function fakeNetwork(tileDelayMs = 0) {
	const calls: Array<{ url: string; at: number }> = [];
	const fetcher = async (input: RequestInfo | URL) => {
		const url = String(input);
		calls.push({ url, at: Date.now() });
		if (TILE_URLS.has(url)) await new Promise((resolve) => setTimeout(resolve, tileDelayMs));
		return respond(url);
	};
	return { calls, fetch: fetcher as typeof fetch };
}

const quietQueue = { async send() {}, async sendBatch() {} } as unknown as Queue<ObservationBatch>;
const tailers = { CURSORS: db, ENTRIES: quietQueue };

async function seed(logIndex: number, nextIndex: number) {
	const log = LOGS[logIndex]!;
	await db
		.prepare('INSERT INTO log_cursors (log_id, kind, url, next_index, tree_size, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
		.bind(log.log_id, 'static', log.monitoring_url, nextIndex, SIZE, '2026-10-17T05:59:00Z')
		.run();
}

const nextIndex = async (logIndex: number) =>
	(await db.prepare('SELECT next_index FROM log_cursors WHERE log_id = ?').bind(LOGS[logIndex]!.log_id).first<{ next_index: number }>())
		?.next_index;

function fakeTailQueue() {
	const sent: ShardRequest[] = [];
	const queue = {
		async sendBatch(messages: Iterable<MessageSendRequest<ShardRequest>>) {
			for (const message of messages) sent.push(message.body);
		},
	} as unknown as Pick<Queue<ShardRequest>, 'sendBatch'>;
	return { sent, queue };
}

beforeEach(async () => {
	resetLogListMemo();
	await db.batch(['log_cursors', 'runs', 'meta', 'ops_ledger'].map((table) => db.prepare(`DROP TABLE IF EXISTS ${table}`)));
	for (const sql of [cursorsSql, catalogSql, cursorErrorsSql]) {
		const statements = sql
			.replace(/--.*$/gm, '')
			.split(';')
			.map((statement) => statement.trim())
			.filter((statement) => statement !== '');
		await db.batch(statements.map((statement) => db.prepare(statement)));
	}
});

describe('partitionLogs', () => {
	it('deals the most-behind logs out first, round-robin, so deep backlogs land on different shards', () => {
		const behind = new Map([
			['a', 10],
			['b', 50],
			['c', 30],
			['d', 40],
			['e', 20],
		]);
		expect(partitionLogs(['a', 'b', 'c', 'd', 'e'], behind, 2)).toEqual([
			['b', 'c', 'a'],
			['d', 'e'],
		]);
	});

	it('puts a log with no cursor last and leaves out shards it has no logs for', () => {
		expect(partitionLogs(['new', 'old'], new Map([['old', 5]]), 4)).toEqual([['old'], ['new']]);
	});
});

describe('runFanout', () => {
	it('sends one tail-queue message per shard, logs dealt by how far behind they are', async () => {
		await seed(0, 0);
		await seed(1, 4 * TILE_WIDTH);
		await seed(2, 2 * TILE_WIDTH);
		const tail = fakeTailQueue();
		const summary = await runFanout(tailers, NOW, tail.queue, { now: NOW, fetch: fakeNetwork().fetch, shards: 2 });

		// Behind: a by 6 tiles, c by 4, b by 2. Dealt a -> 0, c -> 1, b -> 0.
		expect(tail.sent).toEqual([
			{ scheduledTime: NOW, shard: 0, logIds: [LOGS[0]!.log_id, LOGS[1]!.log_id] },
			{ scheduledTime: NOW, shard: 1, logIds: [LOGS[2]!.log_id] },
		]);
		expect(summary).toEqual({ killed: false, logs: 3, backlog: (6 + 2 + 4) * TILE_WIDTH, shards: 2, failed: null });
	});

	it('sends no shard while the kill switch is set', async () => {
		await db
			.prepare('INSERT INTO ops_ledger (day, r2_class_a, r2_class_b, d1_rows, killed) VALUES (?, 0, 0, 0, 1)')
			.bind('2026-10-16')
			.run();
		const net = fakeNetwork();
		const tail = fakeTailQueue();
		const summary = await runFanout(tailers, NOW, tail.queue, { now: NOW, fetch: net.fetch });

		expect(tail.sent).toEqual([]);
		expect(net.calls).toEqual([]);
		expect(summary).toMatchObject({ killed: true, shards: 0 });
	});

	it('reports a failed send', async () => {
		await seed(0, 0);
		const failing = {
			async sendBatch() {
				throw new Error('queue unavailable');
			},
		};
		const summary = await runFanout(tailers, NOW, failing, { now: NOW, fetch: fakeNetwork().fetch });
		expect(summary.failed).toBe('queue unavailable');
	});
});

describe('runShard', () => {
	it('tails only the logs of its message, and its cursors advance', async () => {
		await seed(0, 0);
		await seed(1, 4 * TILE_WIDTH);
		const net = fakeNetwork();
		const outcome = await runShard(tailers, { scheduledTime: NOW, shard: 1, logIds: [LOGS[1]!.log_id] }, { now: NOW, fetch: net.fetch });

		expect(outcome).toMatchObject({ shard: 1, summary: { logs: 1, entries: 2 * TILE_WIDTH } });
		expect(net.calls.some((call) => call.url.startsWith(LOGS[0]!.monitoring_url))).toBe(false);
		expect([await nextIndex(0), await nextIndex(1)]).toEqual([0, SIZE]);
	});

	it('drops a stale message unread, as the next tick has sent a fresh one for the same logs', async () => {
		await seed(0, 0);
		const net = fakeNetwork();
		const outcome = await runShard(
			tailers,
			{ scheduledTime: NOW - STALE_SHARD_MS - 1, shard: 0, logIds: [LOGS[0]!.log_id] },
			{ now: NOW, fetch: net.fetch },
		);

		expect(outcome).toEqual({ shard: 0, summary: null, skipped: 'stale' });
		expect(net.calls).toEqual([]);
		expect(await nextIndex(0)).toBe(0);
	});

	it('drops a malformed message', async () => {
		expect(await runShard(tailers, { shard: 0, logIds: 'a-log-id=' }, { now: NOW })).toEqual({
			shard: -1,
			summary: null,
			skipped: 'malformed',
		});
	});
});

describe('runTailer across logs', () => {
	it("still sends a log's rows while another log's send of the same rows is in flight, so that send failing loses nothing", async () => {
		await seed(0, 0);
		await seed(1, 0);
		// The first send waits for the second and then fails. The second must carry the rows both logs share.
		const sends: ObservationBatch[] = [];
		let second!: () => void;
		const secondArrived = new Promise<void>((resolve) => (second = resolve));
		const queue = {
			async send(batch: ObservationBatch) {
				sends.push(batch);
				if (sends.length === 1) {
					await Promise.race([secondArrived, new Promise((resolve) => setTimeout(resolve, 200))]);
					throw new Error('queue unavailable');
				}
				second();
			},
		} as unknown as Queue<ObservationBatch>;
		await runTailer(
			{ CURSORS: db, ENTRIES: queue },
			{ scheduledTime: NOW, now: NOW, fetch: fakeNetwork().fetch, flushRows: 1, logIds: new Set([LOGS[0]!.log_id, LOGS[1]!.log_id]) },
		);

		expect(sends.length).toBeGreaterThanOrEqual(2);
		const [failed, delivered] = sends;
		expect(delivered!.logId).not.toBe(failed!.logId);
		expect(delivered!.names.length).toBeGreaterThan(0);
		const failedIndex = LOGS.findIndex((log) => log.log_id === failed!.logId);
		expect(await nextIndex(failedIndex)).toBe(0);
	});

	it('starts no request after the fetch phase ends, even one that was waiting for a slot', async () => {
		await seed(0, 0);
		await seed(1, 0);
		await seed(2, 0);
		// Three logs, WINDOW tiles each, want 12 slots; six are free, and every tile takes 30 ms, so six requests are still
		// waiting for a slot when the 20 ms fetch phase ends.
		const net = fakeNetwork(30);
		const start = Date.now();
		const summary = await runTailer(tailers, { scheduledTime: NOW, now: NOW, fetch: net.fetch, fetchPhaseMs: 20 });

		const late = net.calls.filter((call) => call.at > start + 20 + 5);
		expect(late).toEqual([]);
		expect(Object.values(summary.deferred)).toContain('fetch phase ended before this request had a slot');
		expect(summary.errors).toEqual({});
	});
});
