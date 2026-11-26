// SPDX-License-Identifier: BUSL-1.1
/**
 * runCatchup (src/tailer/catchup.ts) against miniflare D1, with a fake CT network and a fake ENTRIES queue: it reads
 * [lower, upper) of a log from the row's own url, never at or past upper, advances its own cursor only after the rows
 * are sent, skips expired certificates, and stops on either kill switch.
 */

import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import cursorsSql from '../../../migrations/0001_log_cursors.sql?raw';
import catalogSql from '../../../migrations/0002_catalog.sql?raw';
import cursorErrorsSql from '../../../migrations/0003_cursor_errors.sql?raw';
import backfillSql from '../../../migrations/0006_log_backfill.sql?raw';
import type { Env } from '../../index';
import { LOG_LIST_URL, TILE_WIDTH, tilePath } from '../../tailer/ct';
import { CATCHUP_KILL_KEY, resetCatchupMemo, runCatchup, type CatchupOptions } from '../../tailer/catchup';
import type { ObservationBatch } from '../../types';
import {
	RFC6962_PRECERT_FACTS,
	RFC6962_PRECERT_LEAF_INPUT,
	RFC6962_X509_LEAF_INPUT,
	STATIC_PRECERT_TILE_LEAF,
	STATIC_X509_TILE_LEAF,
} from './fixtures';

const db = (env as unknown as Env).CURSORS;
const NOW = Date.parse('2026-11-27T06:00:00Z');
const RO = { log_id: 'readonly-log-id=', url: 'https://readonly.ct.test/2027h1/' };
const STATIC = { log_id: 'static-log-id=', url: 'https://static.ct.test/2027h1/' };

const bytes = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
/** A full data tile: entry 3 a precert, the rest x509. */
const TILE = new Uint8Array(
	Array.from({ length: TILE_WIDTH }, (_, i) => (i === 3 ? bytes(STATIC_PRECERT_TILE_LEAF) : bytes(STATIC_X509_TILE_LEAF))).flatMap(
		(leaf) => [...leaf],
	),
);

interface Network {
	/** Entries per get-entries page, like the real logs' caps. */
	pageCap: number;
	calls: string[];
	/** Largest `end` any get-entries request asked for. */
	maxEnd: number;
	failPrefix: string | null;
}

function fakeNetwork(pageCap = 8): Network & { fetch: typeof fetch } {
	const net: Network = { pageCap, calls: [], maxEnd: -1, failPrefix: null };
	const fetcher = async (input: RequestInfo | URL) => {
		const url = input instanceof Request ? input.url : String(input);
		net.calls.push(url);
		if (net.failPrefix && url.startsWith(net.failPrefix)) return new Response('unavailable', { status: 503 });
		if (url.startsWith(`${RO.url}ct/v1/get-entries?`)) {
			const query = new URL(url).searchParams;
			const start = Number(query.get('start'));
			const asked = Number(query.get('end'));
			net.maxEnd = Math.max(net.maxEnd, asked);
			const end = Math.min(asked, start + net.pageCap - 1);
			const entries = Array.from({ length: end - start + 1 }, (_, k) => ({
				leaf_input: (start + k) % 2 === 0 ? RFC6962_PRECERT_LEAF_INPUT : RFC6962_X509_LEAF_INPUT,
				extra_data: '',
			}));
			return Response.json({ entries });
		}
		if (url.startsWith(`${STATIC.url}tile/data/`)) return new Response(TILE);
		return new Response('unexpected request', { status: 599 });
	};
	return Object.assign(net, { fetch: fetcher as typeof fetch });
}

interface FakeQueue {
	queue: Queue<ObservationBatch>;
	sent: ObservationBatch[];
}

function fakeQueue(onSend: (batch: ObservationBatch) => Promise<void> = async () => {}): FakeQueue {
	const sent: ObservationBatch[] = [];
	const queue = {
		async send(batch: ObservationBatch) {
			await onSend(batch);
			sent.push(JSON.parse(JSON.stringify(batch)));
		},
		async sendBatch() {
			throw new Error('not used');
		},
	} as unknown as Queue<ObservationBatch>;
	return { queue, sent };
}

async function row(logId: string) {
	return db.prepare('SELECT * FROM log_backfill WHERE log_id = ?').bind(logId).first<Record<string, unknown>>();
}

async function seed(log: { log_id: string; url: string }, kind: 'rfc6962' | 'static', lower: number, upper: number, state = 'active') {
	await db
		.prepare('INSERT INTO log_backfill (log_id, kind, url, lower_index, next_index, upper_index, state) VALUES (?, ?, ?, ?, ?, ?, ?)')
		.bind(log.log_id, kind, log.url, lower, lower, upper, state)
		.run();
}

const run = (net: { fetch: typeof fetch }, queue: FakeQueue, options: Partial<CatchupOptions> = {}, now = NOW) =>
	runCatchup({ CURSORS: db, ENTRIES: queue.queue }, { now, fetch: net.fetch, ...options });

beforeEach(async () => {
	resetCatchupMemo();
	await db.batch(['log_cursors', 'runs', 'meta', 'ops_ledger', 'log_backfill'].map((table) => db.prepare(`DROP TABLE IF EXISTS ${table}`)));
	for (const sql of [cursorsSql, catalogSql, cursorErrorsSql, backfillSql]) {
		const statements = sql
			.replace(/--.*$/gm, '')
			.split(';')
			.map((statement) => statement.trim())
			.filter((statement) => statement !== '');
		await db.batch(statements.map((statement) => db.prepare(statement)));
	}
});

describe('runCatchup', () => {
	it('reads [lower, upper) of a log from the row url, never at or past upper, then marks the row done', async () => {
		await seed(RO, 'rfc6962', 100, 140);
		const net = fakeNetwork();
		const queue = fakeQueue();
		const summary = await run(net, queue);

		expect(net.maxEnd).toBe(139);
		expect(net.calls.every((url) => url.startsWith(RO.url))).toBe(true); // no log list, no get-sth: the row has everything
		expect(net.calls).not.toContain(LOG_LIST_URL);
		expect(await row(RO.log_id)).toMatchObject({ next_index: 140, state: 'done', entries_read: 40, expired_skipped: 0, last_error: null });
		expect(queue.sent.length).toBeGreaterThan(0);
		expect(queue.sent.every((batch) => batch.logId === RO.log_id && batch.startIndex >= 100 && batch.endIndex <= 140)).toBe(true);
		const names = queue.sent.flatMap((batch) => batch.names);
		expect(names[0]).toMatchObject({ name: '4f6k.com', notAfter: RFC6962_PRECERT_FACTS.notAfter });
		expect(summary).toMatchObject({ killed: false, rows: 1, entries: 40, precerts: 20, expired: 0, lost: 0 });
		// the forward tail's table is never touched
		expect((await db.prepare('SELECT COUNT(*) AS n FROM log_cursors').first<{ n: number }>())?.n).toBe(0);

		// a done row is not read again
		const again = fakeNetwork();
		await run(again, queue);
		expect(again.calls).toEqual([]);
	});

	it('stops at the per-run fetch budget and resumes from its own cursor', async () => {
		await seed(RO, 'rfc6962', 0, 1_000);
		const net = fakeNetwork();
		const queue = fakeQueue();
		await run(net, queue, { maxFetches: 3, pageSize: 8 });

		const first = await row(RO.log_id);
		expect(first).toMatchObject({ state: 'active' });
		expect(first?.next_index).toBe(24); // three 8-entry pages
		expect(net.calls).toHaveLength(3);
		await run(fakeNetwork(), queue, { maxFetches: 3, pageSize: 8 });
		expect((await row(RO.log_id))?.next_index).toBe(48);
		expect(queue.sent.every((batch) => batch.endIndex <= 48)).toBe(true);
	});

	it('moves its cursor with a compare-and-set: an overlapping run that got there first is not overwritten', async () => {
		await seed(RO, 'rfc6962', 100, 140);
		const net = fakeNetwork();
		// While this run's rows are in flight, another run advances the cursor.
		const queue = fakeQueue(async () => {
			await db.prepare('UPDATE log_backfill SET next_index = 133 WHERE log_id = ?').bind(RO.log_id).run();
		});
		const summary = await run(net, queue);

		expect(await row(RO.log_id)).toMatchObject({ next_index: 133, state: 'active', entries_read: 0 });
		expect(summary.lost).toBe(1);
	});

	it('skips certificates that have already expired and counts them; the cursor still advances', async () => {
		await seed(RO, 'rfc6962', 100, 140);
		const net = fakeNetwork();
		const queue = fakeQueue();
		const afterExpiry = (RFC6962_PRECERT_FACTS.notAfter + 1) * 1000;
		const summary = await run(net, queue, {}, afterExpiry);

		expect(queue.sent).toEqual([]);
		expect(await row(RO.log_id)).toMatchObject({ next_index: 140, state: 'done', expired_skipped: 20, entries_read: 40 });
		expect(summary).toMatchObject({ precerts: 20, expired: 20 });
	});

	it('a failed send leaves the cursor unchanged and records the error', async () => {
		await seed(RO, 'rfc6962', 100, 140);
		const queue = fakeQueue(async () => {
			throw new Error('queue unavailable');
		});
		const summary = await run(fakeNetwork(), queue);

		expect(await row(RO.log_id)).toMatchObject({ next_index: 100, state: 'active', entries_read: 0 });
		expect(String((await row(RO.log_id))?.last_error)).toContain('queue send: queue unavailable');
		expect(summary.errors[RO.log_id]).toContain('queue unavailable');
	});

	it('a failed fetch records the error on the row and keeps the progress made before it', async () => {
		await seed(RO, 'rfc6962', 0, 1_000);
		const net = fakeNetwork();
		const queue = fakeQueue();
		const base = net.fetch;
		let served = 0;
		const flaky = (async (input: RequestInfo | URL) =>
			++served > 2 ? new Response('down', { status: 503 }) : base(input)) as typeof fetch;
		await run({ fetch: flaky }, queue, { pageSize: 8 });

		expect(await row(RO.log_id)).toMatchObject({ next_index: 16, state: 'active' });
		expect(String((await row(RO.log_id))?.last_error)).toContain('HTTP 503');
	});

	it('the ops_ledger kill switch halts it', async () => {
		await seed(RO, 'rfc6962', 100, 140);
		await db.prepare("INSERT INTO ops_ledger (day, killed) VALUES ('2026-11-27', 1)").run();
		const net = fakeNetwork();
		const summary = await run(net, fakeQueue());

		expect(summary.killed).toBe(true);
		expect(net.calls).toEqual([]);
		expect((await row(RO.log_id))?.next_index).toBe(100);
	});

	it('its own kill switch halts it, and the other direction holds: the forward tail does not read it', async () => {
		await seed(RO, 'rfc6962', 100, 140);
		await db.prepare('INSERT INTO meta (k, v) VALUES (?, ?)').bind(CATCHUP_KILL_KEY, '1').run();
		const net = fakeNetwork();
		const summary = await run(net, fakeQueue());
		expect(summary.killed).toBe(true);
		expect(net.calls).toEqual([]);

		// Any other value is not a kill.
		await db.prepare('UPDATE meta SET v = ? WHERE k = ?').bind('0', CATCHUP_KILL_KEY).run();
		expect((await run(fakeNetwork(), fakeQueue())).killed).toBe(false);
		expect((await row(RO.log_id))?.next_index).toBe(140);
	});

	it('does not read a paused row', async () => {
		await seed(RO, 'rfc6962', 100, 140, 'paused');
		const net = fakeNetwork();
		const summary = await run(net, fakeQueue());
		expect(net.calls).toEqual([]);
		expect(summary.rows).toBe(0);
	});

	it('reads a static-ct log in full tiles, keeps to the ceiling, and counts tiles it skips', async () => {
		await seed(STATIC, 'static', 100, 3 * TILE_WIDTH);
		const net = fakeNetwork();
		const queue = fakeQueue();
		await run(net, queue);

		expect(net.calls).toEqual([0, 1, 2].map((tile) => `${STATIC.url}tile/data/${tilePath(tile)}`));
		expect(await row(STATIC.log_id)).toMatchObject({ next_index: 3 * TILE_WIDTH, state: 'done' });
		expect(queue.sent.every((batch) => batch.startIndex === 100 && batch.endIndex === 3 * TILE_WIDTH)).toBe(true);
	});
});
