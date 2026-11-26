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

	it('a row that keeps failing goes to the back of the work list, so the rows behind it still run', async () => {
		const others = [
			{ log_id: 'bad-a', url: 'https://bad-a.example/' },
			{ log_id: 'bad-b', url: 'https://bad-b.example/' },
		];
		for (const log of others) await seed(log, 'rfc6962', 0, 1_000);
		await seed(RO, 'rfc6962', 100, 140);
		// The two failing rows sort ahead of the healthy one, and a run takes two rows.
		await db.prepare("UPDATE log_backfill SET updated_at = '2026-01-01T00:00:00.000Z' WHERE log_id LIKE 'bad-%'").run();
		await db.prepare("UPDATE log_backfill SET updated_at = '2026-06-01T00:00:00.000Z' WHERE log_id = ?").bind(RO.log_id).run();
		const net = fakeNetwork();
		const base = net.fetch;
		const flaky = (async (input: RequestInfo | URL) =>
			String(input instanceof Request ? input.url : input).includes('bad-') ? new Response('down', { status: 503 }) : base(input)) as typeof fetch;

		await run({ fetch: flaky }, fakeQueue());
		expect((await row(RO.log_id))?.next_index).toBe(100);
		await run({ fetch: flaky }, fakeQueue());
		expect(await row(RO.log_id)).toMatchObject({ next_index: 140, state: 'done' });
	});

	it('a kill switch thrown mid-row stops the read; what was read before it is kept', async () => {
		await seed(RO, 'rfc6962', 0, 1_000);
		const net = fakeNetwork();
		const base = net.fetch;
		let served = 0;
		const killing = (async (input: RequestInfo | URL) => {
			if (++served === 2) await db.prepare('INSERT INTO meta (k, v) VALUES (?, ?)').bind(CATCHUP_KILL_KEY, '1').run();
			return base(input);
		}) as typeof fetch;
		const summary = await run({ fetch: killing }, fakeQueue(), { pageSize: 8, killRecheckMs: 0 });

		expect(summary.killed).toBe(true);
		const after = await row(RO.log_id);
		expect(after?.state).toBe('active');
		expect(Number(after?.next_index)).toBeGreaterThan(0);
		expect(Number(after?.next_index)).toBeLessThan(1_000);
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

	it('a short page advances the cursor by exactly what was returned, and the page size the log served is used next run', async () => {
		await seed(RO, 'rfc6962', 0, 1_000);
		const net = fakeNetwork(8); // the log serves 8 however many are asked for
		const queue = fakeQueue();
		await run(net, queue, { pageSize: 32, maxFetches: 4 }); // one window: the short first page ends it

		expect(await row(RO.log_id)).toMatchObject({ next_index: 8, entries_read: 8, state: 'active' });
		expect(net.calls).toHaveLength(4); // the pages after the short one were asked for and not used

		const next = fakeNetwork(8);
		await run(next, queue, { maxFetches: 2 }); // no pageSize: the learned size of 8 is asked for
		expect(next.calls.map((url) => new URL(url).search)).toEqual(['?start=8&end=15', '?start=16&end=23']);
		expect((await row(RO.log_id))?.next_index).toBe(24);
	});

	it('an empty page is a deferral: the cursor stays, no error is recorded, and the row goes to the back of the list', async () => {
		await seed(RO, 'rfc6962', 100, 140);
		await db.prepare("UPDATE log_backfill SET updated_at = '2026-01-01T00:00:00.000Z' WHERE log_id = ?").bind(RO.log_id).run();
		const empty = (async () => Response.json({ entries: [] })) as typeof fetch;
		const summary = await run({ fetch: empty }, fakeQueue());

		expect(await row(RO.log_id)).toMatchObject({
			next_index: 100,
			state: 'active',
			last_error: null,
			last_error_at: null,
			updated_at: new Date(NOW).toISOString(),
		});
		expect(summary.errors).toEqual({});
		expect(summary.deferred[RO.log_id]).toContain('no entries served yet');
	});

	it('HTTP 429 is a deferral, not an error', async () => {
		await seed(RO, 'rfc6962', 100, 140);
		await db.prepare("UPDATE log_backfill SET updated_at = '2026-01-01T00:00:00.000Z' WHERE log_id = ?").bind(RO.log_id).run();
		const limited = (async () => new Response('slow down', { status: 429 })) as typeof fetch;
		const summary = await run({ fetch: limited }, fakeQueue());

		expect(await row(RO.log_id)).toMatchObject({ next_index: 100, last_error: null, updated_at: new Date(NOW).toISOString() });
		expect(summary.errors).toEqual({});
		expect(summary.deferred[RO.log_id]).toContain('HTTP 429');
	});

	it('a reply with more entries than asked is rejected, and the cursor stops at the last verified entry', async () => {
		await seed(RO, 'rfc6962', 100, 1_000);
		const base = fakeNetwork(8);
		const greedy = (async (input: RequestInfo | URL) => {
			const url = String(input instanceof Request ? input.url : input);
			if (new URL(url).searchParams.get('start') !== '108') return base.fetch(input);
			const entries = Array.from({ length: 9 }, () => ({ leaf_input: RFC6962_PRECERT_LEAF_INPUT, extra_data: '' }));
			return Response.json({ entries });
		}) as typeof fetch;
		const queue = fakeQueue();
		const summary = await run({ fetch: greedy }, queue, { pageSize: 8 });

		expect(await row(RO.log_id)).toMatchObject({ next_index: 108, state: 'active', entries_read: 8 });
		expect(String((await row(RO.log_id))?.last_error)).toContain('bad entries array');
		expect(summary.errors[RO.log_id]).toContain('bad entries array');
		expect(queue.sent.every((batch) => batch.endIndex <= 108)).toBe(true);
	});

	it('a failed send on a later row leaves that row at its cursor, keeps the earlier row advanced, and stops the run', async () => {
		await seed(RO, 'rfc6962', 100, 140);
		await seed(STATIC, 'static', 0, TILE_WIDTH);
		const net = fakeNetwork();
		const queue = fakeQueue(async (batch) => {
			if (batch.logId === STATIC.log_id) throw new Error('queue unavailable');
		});
		const summary = await run(net, queue);

		// A row's cursor moves only after all of that row's batches were sent, so the failed row stays where it began.
		expect(await row(RO.log_id)).toMatchObject({ next_index: 140, state: 'done' });
		expect(queue.sent.some((batch) => batch.logId === RO.log_id)).toBe(true);
		expect(await row(STATIC.log_id)).toMatchObject({ next_index: 0, state: 'active', entries_read: 0 });
		expect(String((await row(STATIC.log_id))?.last_error)).toContain('queue send: queue unavailable');
		expect(summary.errors[STATIC.log_id]).toContain('queue unavailable');
		expect(summary.errors[RO.log_id]).toBeUndefined();
	});

	it('fails closed when the kill switches cannot be read: the run throws and makes no fetch', async () => {
		await seed(RO, 'rfc6962', 100, 140);
		await db.prepare('DROP TABLE meta').run();
		const net = fakeNetwork();

		await expect(run(net, fakeQueue())).rejects.toThrow();
		expect(net.calls).toEqual([]);
		expect((await row(RO.log_id))?.next_index).toBe(100);
	});

	it("only the exact value '1' kills it: 'true' is read as not killed, so the reader runs (fails open on a mistyped switch)", async () => {
		await seed(RO, 'rfc6962', 100, 140);
		await db.prepare('INSERT INTO meta (k, v) VALUES (?, ?)').bind(CATCHUP_KILL_KEY, 'true').run();
		const net = fakeNetwork();
		const summary = await run(net, fakeQueue());

		expect(summary.killed).toBe(false);
		expect(net.calls.length).toBeGreaterThan(0);
		expect((await row(RO.log_id))?.next_index).toBe(140);
	});

	describe('two active rows', () => {
		const RO2 = { log_id: 'readonly-two=', url: 'https://readonly.ct.test/2027h2/' };
		/** Serves RO2 from the same fake as RO. */
		const both = (net: { fetch: typeof fetch }, calls: string[] = []) =>
			(async (input: RequestInfo | URL) => {
				const url = String(input instanceof Request ? input.url : input);
				calls.push(url);
				return net.fetch(url.replace(RO2.url, RO.url));
			}) as typeof fetch;

		it('share the fetch budget equally', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			await seed(RO2, 'rfc6962', 0, 1_000);
			const net = fakeNetwork();
			const calls: string[] = [];
			await run({ fetch: both(net, calls) }, fakeQueue(), { maxFetches: 6, pageSize: 8 });

			expect((await row(RO.log_id))?.next_index).toBe(24);
			expect((await row(RO2.log_id))?.next_index).toBe(24);
			expect(calls.filter((url) => url.startsWith(RO.url))).toHaveLength(3);
			expect(calls.filter((url) => url.startsWith(RO2.url))).toHaveLength(3);
		});

		it('share the entry budget equally', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			await seed(RO2, 'rfc6962', 0, 1_000);
			const net = fakeNetwork();
			const fetcher = both(net);
			await run({ fetch: fetcher }, fakeQueue(), { maxEntries: 16, pageSize: 8 });

			expect((await row(RO.log_id))?.next_index).toBe(8);
			expect((await row(RO2.log_id))?.next_index).toBe(8);
		});
	});

	describe('the per-run entry cap', () => {
		it('stops a run on rfc6962 within one page of the cap, leaves the row active, and resumes from its cursor', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			const net = fakeNetwork();
			const queue = fakeQueue();
			const summary = await run(net, queue, { maxEntries: 20, pageSize: 8 });

			expect(net.calls).toHaveLength(3); // 8 + 8 + 8: the third page starts below the cap and ends one page past it
			expect(await row(RO.log_id)).toMatchObject({ next_index: 24, state: 'active', entries_read: 24 });
			expect(summary.entries).toBe(24);
			expect(queue.sent.every((batch) => batch.endIndex <= 24)).toBe(true);

			await run(fakeNetwork(), queue, { maxEntries: 20, pageSize: 8 });
			expect(await row(RO.log_id)).toMatchObject({ next_index: 48, state: 'active', entries_read: 48 });
		});

		it('stops a run on a static-ct log within one tile of the cap and resumes from its cursor', async () => {
			await seed(STATIC, 'static', 0, 3 * TILE_WIDTH);
			const net = fakeNetwork();
			const queue = fakeQueue();
			await run(net, queue, { maxEntries: 300 });

			expect(net.calls).toHaveLength(2);
			expect(await row(STATIC.log_id)).toMatchObject({ next_index: 2 * TILE_WIDTH, state: 'active' });

			const again = fakeNetwork();
			await run(again, queue, { maxEntries: 300 });
			expect(again.calls).toHaveLength(1);
			expect(await row(STATIC.log_id)).toMatchObject({ next_index: 3 * TILE_WIDTH, state: 'done' });
		});

		it('reads the CATCHUP_MAX_ENTRIES var, and an invalid value means the default', async () => {
			await seed(RO, 'rfc6962', 0, 40);
			const queue = fakeQueue();
			const env = (value: string) => ({ CURSORS: db, ENTRIES: queue.queue, CATCHUP_MAX_ENTRIES: value });
			await runCatchup(env('16'), { now: NOW, fetch: fakeNetwork().fetch, pageSize: 8 });
			expect(await row(RO.log_id)).toMatchObject({ next_index: 16, state: 'active' });

			await runCatchup(env('junk'), { now: NOW, fetch: fakeNetwork().fetch, pageSize: 8 });
			expect(await row(RO.log_id)).toMatchObject({ next_index: 40, state: 'done' });
		});
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
