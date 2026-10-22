// SPDX-License-Identifier: BUSL-1.1
/**
 * The tailer fan-out (src/tailer/fanout.ts) against miniflare D1 with a fake CT network: shards are dealt by how far
 * each log is behind, every shard runs at once and advances only its own logs, the kill switch spawns none, and a
 * failed shard is reported without touching the others.
 */

import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import cursorsSql from '../../../migrations/0001_log_cursors.sql?raw';
import catalogSql from '../../../migrations/0002_catalog.sql?raw';
import cursorErrorsSql from '../../../migrations/0003_cursor_errors.sql?raw';
import type { Env } from '../../index';
import { LOG_LIST_URL, TILE_WIDTH, tilePath } from '../../tailer/ct';
import { partitionLogs, runFanout, type ShardRequest } from '../../tailer/fanout';
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
const TILE = new Uint8Array(Array.from({ length: TILE_WIDTH }, () => [...leaf]).flat());

function fakeNetwork() {
	const calls: string[] = [];
	const fetcher = async (input: RequestInfo | URL) => {
		const url = String(input);
		calls.push(url);
		if (url === LOG_LIST_URL) return Response.json(LIST);
		const log = LOGS.find((candidate) => url.startsWith(candidate.monitoring_url));
		if (log && url.endsWith('/checkpoint')) return new Response(`${log.log_id}\n${SIZE}\nAAAA\n\n— sig\n`);
		if (log && Array.from({ length: SIZE / TILE_WIDTH }, (_, t) => `${log.monitoring_url}tile/data/${tilePath(t)}`).includes(url)) {
			return new Response(TILE);
		}
		return new Response('unexpected request', { status: 599 });
	};
	return { calls, fetch: fetcher as typeof fetch };
}

const queue = { async send() {}, async sendBatch() {} } as unknown as Queue<ObservationBatch>;
const tailers = { CURSORS: db, ENTRIES: queue };

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
	it('runs every shard at once over its own logs, and each advances only those', async () => {
		await seed(0, 0);
		await seed(1, 4 * TILE_WIDTH);
		await seed(2, 2 * TILE_WIDTH);
		const net = fakeNetwork();
		const requests: ShardRequest[] = [];
		let running = 0;
		let maxRunning = 0;
		const tailShard = async (request: ShardRequest) => {
			requests.push(request);
			maxRunning = Math.max(maxRunning, ++running);
			try {
				return await runTailer(tailers, {
					scheduledTime: request.scheduledTime,
					now: NOW,
					fetch: net.fetch,
					logIds: new Set(request.logIds),
				});
			} finally {
				running--;
			}
		};
		const summary = await runFanout(tailers, NOW, tailShard, { now: NOW, fetch: net.fetch, shards: 2 });

		// Behind: a by 6 tiles, c by 4, b by 2. Dealt a -> 0, c -> 1, b -> 0.
		expect(requests.map((request) => request.logIds)).toEqual([[LOGS[0]!.log_id, LOGS[1]!.log_id], [LOGS[2]!.log_id]]);
		expect(maxRunning).toBe(2);
		expect([await nextIndex(0), await nextIndex(1), await nextIndex(2)]).toEqual([SIZE, SIZE, SIZE]);
		expect(summary).toMatchObject({
			killed: false,
			logs: 3,
			shards: 2,
			backlog: (6 + 2 + 4) * TILE_WIDTH,
			entries: (6 + 2 + 4) * TILE_WIDTH,
			failed: {},
		});
	});

	it('starts no shard while the kill switch is set', async () => {
		await db
			.prepare('INSERT INTO ops_ledger (day, r2_class_a, r2_class_b, d1_rows, killed) VALUES (?, 0, 0, 0, 1)')
			.bind('2026-10-16')
			.run();
		const net = fakeNetwork();
		let calls = 0;
		const summary = await runFanout(
			tailers,
			NOW,
			async () => {
				calls++;
				throw new Error('must not run');
			},
			{ now: NOW, fetch: net.fetch },
		);

		expect(calls).toBe(0);
		expect(net.calls).toEqual([]);
		expect(summary).toMatchObject({ killed: true, shards: 0 });
	});

	it('reports a failed shard and still totals the shards that ran', async () => {
		await seed(0, 0);
		await seed(1, 4 * TILE_WIDTH);
		const net = fakeNetwork();
		const summary = await runFanout(
			tailers,
			NOW,
			async (request) => {
				if (request.shard === 0) throw new Error('shard invocation failed');
				return runTailer(tailers, { scheduledTime: request.scheduledTime, now: NOW, fetch: net.fetch, logIds: new Set(request.logIds) });
			},
			{ now: NOW, fetch: net.fetch, shards: 3 },
		);

		expect(summary.failed).toEqual({ 0: 'shard invocation failed' });
		expect(await nextIndex(0)).toBe(0);
		expect(summary.entries).toBeGreaterThan(0);
	});
});
