// SPDX-License-Identifier: BUSL-1.1
/**
 * runCatchup (src/tailer/catchup.ts) against miniflare D1, with a fake CT network and a fake ENTRIES queue: it reads
 * [lower, upper) of a log from the row's own url, never at or past upper, advances its own cursor only after the rows
 * are sent, skips expired certificates, and stops on either kill switch.
 */

import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import cursorsSql from '../../../migrations/0001_log_cursors.sql?raw';
import catalogSql from '../../../migrations/0002_catalog.sql?raw';
import cursorErrorsSql from '../../../migrations/0003_cursor_errors.sql?raw';
import backfillSql from '../../../migrations/0006_log_backfill.sql?raw';
import type { Env } from '../../index';
import { LOG_LIST_URL, TILE_WIDTH, tilePath } from '../../tailer/ct';
import { HEADER_SLOTS } from '../../tailer';
import {
	CATCHUP_BACKOFF_MS,
	CATCHUP_KILL_KEY,
	CATCHUP_MAX_ENTRIES,
	CATCHUP_MAX_FETCHES,
	CATCHUP_PAGES_IN_FLIGHT,
	CATCHUP_PHASE_MS,
	CATCHUP_STALE_MS,
	dispatchCatchup,
	nextStreak,
	runCatchup,
	runCatchupMessage,
	type CatchupOptions,
	type CatchupRequest,
} from '../../tailer/catchup';
import type { ObservationBatch } from '../../types';
import {
	RFC6962_PRECERT_FACTS,
	RFC6962_PRECERT_LEAF_INPUT,
	RFC6962_X509_LEAF_INPUT,
	STATIC_PRECERT_TILE_LEAF,
	STATIC_X509_TILE_LEAF,
} from './fixtures';

const db = (env as unknown as Env).CURSORS;
// Not on a probe slot (a stored page size of 32 or more is probed on one 2-minute slot in 30; this is minute 4 of the hour).
const NOW = Date.parse('2026-11-27T06:04:00Z');
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
	/** Milliseconds each get-entries reply takes. */
	delayMs: number;
	inFlight: number;
	maxInFlight: number;
}

function fakeNetwork(pageCap = 8): Network & { fetch: typeof fetch } {
	const net: Network = { pageCap, calls: [], maxEnd: -1, failPrefix: null, delayMs: 0, inFlight: 0, maxInFlight: 0 };
	const fetcher = async (input: RequestInfo | URL) => {
		const url = input instanceof Request ? input.url : String(input);
		net.calls.push(url);
		net.inFlight++;
		net.maxInFlight = Math.max(net.maxInFlight, net.inFlight);
		try {
			if (net.delayMs > 0) await new Promise((resolve) => setTimeout(resolve, net.delayMs));
			return serve(url);
		} finally {
			net.inFlight--;
		}
	};
	const serve = (url: string): Response => {
		if (net.failPrefix && url.startsWith(net.failPrefix)) return new Response('unavailable', { status: 503 });
		if (url.startsWith(`${RO.url}ct/v1/get-entries?`)) {
			const query = new URL(url).searchParams;
			const start = Number(query.get('start'));
			const asked = Number(query.get('end'));
			net.maxEnd = Math.max(net.maxEnd, asked);
			// Like the real logs: a page is cut at the next multiple of the cap.
			const end = Math.min(asked, (Math.floor(start / net.pageCap) + 1) * net.pageCap - 1);
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

/** Milliseconds from NOW to the row's hold_until: the back-off runs from the failure, so a little over CATCHUP_BACKOFF_MS. */
async function holdAfterNow(logId: string): Promise<number> {
	return Date.parse(String((await row(logId))?.hold_until)) - NOW;
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
		// The two failing rows sort ahead of the healthy one; a run reads one row (changed from two: each row now has its own run).
		await db.prepare("UPDATE log_backfill SET updated_at = '2026-01-01T00:00:00.000Z' WHERE log_id LIKE 'bad-%'").run();
		await db.prepare("UPDATE log_backfill SET updated_at = '2026-06-01T00:00:00.000Z' WHERE log_id = ?").bind(RO.log_id).run();
		const net = fakeNetwork();
		const base = net.fetch;
		const flaky = (async (input: RequestInfo | URL) =>
			String(input instanceof Request ? input.url : input).includes('bad-')
				? new Response('down', { status: 503 })
				: base(input)) as typeof fetch;

		await run({ fetch: flaky }, fakeQueue()); // bad-a fails and goes to the back
		await run({ fetch: flaky }, fakeQueue()); // bad-b fails and goes to the back
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
		// Changed: one short page no longer saves a size (it needs two in a row), so the run is given budget for the second.
		await run(net, queue, { pageSize: 32, maxFetches: 12 });

		const after = await row(RO.log_id);
		expect(after).toMatchObject({ entries_read: after?.next_index, state: 'active', page_size: 8 }); // saved on the row
		expect(Number(after?.next_index)).toBeGreaterThanOrEqual(16);

		const next = fakeNetwork(8);
		await run(next, queue, { maxFetches: 3 }); // no pageSize: the learned size of 8 is asked for (after the probe, as 8 < 32)
		const from = Number(after?.next_index);
		expect(next.calls.map((url) => new URL(url).search).slice(1)).toEqual([
			`?start=${from}&end=${from + 7}`,
			`?start=${from + 8}&end=${from + 15}`,
		]);
		expect((await row(RO.log_id))?.next_index).toBe(from + 16);
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
			if (new URL(url).searchParams.get('start') !== '112') return base.fetch(input); // pages from 100 are aligned: 100-103, 104-111, 112-119
			const entries = Array.from({ length: 9 }, () => ({ leaf_input: RFC6962_PRECERT_LEAF_INPUT, extra_data: '' }));
			return Response.json({ entries });
		}) as typeof fetch;
		const queue = fakeQueue();
		const summary = await run({ fetch: greedy }, queue, { pageSize: 8 });

		expect(await row(RO.log_id)).toMatchObject({ next_index: 112, state: 'active', entries_read: 12 });
		expect(String((await row(RO.log_id))?.last_error)).toContain('bad entries array');
		expect(summary.errors[RO.log_id]).toContain('bad entries array');
		expect(queue.sent.every((batch) => batch.endIndex <= 112)).toBe(true);
	});

	it('a failed send on a static row leaves that row at its cursor, and the other row, run on its own, is unaffected', async () => {
		// Changed from one run reading both rows: each row now has its own run, so the failure cannot stop the other.
		await seed(RO, 'rfc6962', 100, 140);
		await seed(STATIC, 'static', 0, TILE_WIDTH);
		const net = fakeNetwork();
		const queue = fakeQueue(async (batch) => {
			if (batch.logId === STATIC.log_id) throw new Error('queue unavailable');
		});
		const failed = await run(net, queue, { only: { logId: STATIC.log_id, upperIndex: TILE_WIDTH } });
		const fine = await run(net, queue, { only: { logId: RO.log_id, upperIndex: 140 } });

		// A row's cursor moves only after all of that row's batches were sent, so the failed row stays where it began.
		expect(await row(RO.log_id)).toMatchObject({ next_index: 140, state: 'done' });
		expect(queue.sent.some((batch) => batch.logId === RO.log_id)).toBe(true);
		expect(await row(STATIC.log_id)).toMatchObject({ next_index: 0, state: 'active', entries_read: 0 });
		expect(String((await row(STATIC.log_id))?.last_error)).toContain('queue send: queue unavailable');
		expect(failed.errors[STATIC.log_id]).toContain('queue unavailable');
		expect(fine.errors[RO.log_id]).toBeUndefined();
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

		// Changed from "share the fetch/entry budget equally" (one run reading both rows): each row now has its own run and
		// the whole of the caps, so two rows read side by side each get a full budget, on their own connection slots.
		it('both rows make progress when read side by side, each with the whole fetch budget', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			await seed(RO2, 'rfc6962', 0, 1_000);
			const net = fakeNetwork();
			const calls: string[] = [];
			const fetcher = both(net, calls);
			const [a, b] = await Promise.all([
				run({ fetch: fetcher }, fakeQueue(), { maxFetches: 3, pageSize: 8, only: { logId: RO.log_id, upperIndex: 1_000 } }),
				run({ fetch: fetcher }, fakeQueue(), { maxFetches: 3, pageSize: 8, only: { logId: RO2.log_id, upperIndex: 1_000 } }),
			]);

			expect((await row(RO.log_id))?.next_index).toBe(24);
			expect((await row(RO2.log_id))?.next_index).toBe(24);
			expect(calls.filter((url) => url.startsWith(RO.url))).toHaveLength(3);
			expect(calls.filter((url) => url.startsWith(RO2.url))).toHaveLength(3);
			expect([a.rows, b.rows]).toEqual([1, 1]);
		});

		it('a run without a named row reads the least recently advanced one, so the rows take turns', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			await seed(RO2, 'rfc6962', 0, 1_000);
			await db.prepare("UPDATE log_backfill SET updated_at = '2026-01-01T00:00:00.000Z' WHERE log_id = ?").bind(RO2.log_id).run();
			await db.prepare("UPDATE log_backfill SET updated_at = '2026-02-01T00:00:00.000Z' WHERE log_id = ?").bind(RO.log_id).run();
			const net = fakeNetwork();
			const fetcher = both(net);
			await run({ fetch: fetcher }, fakeQueue(), { maxFetches: 2, pageSize: 8 });
			expect(await row(RO2.log_id)).toMatchObject({ next_index: 16 });
			expect(await row(RO.log_id)).toMatchObject({ next_index: 0 });
			await run({ fetch: fetcher }, fakeQueue(), { maxFetches: 2, pageSize: 8 });
			expect(await row(RO.log_id)).toMatchObject({ next_index: 16 });
		});

		it('dispatch sends one message per claimable row, and none for a held, paused or done row or when killed', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			await seed(RO2, 'rfc6962', 0, 1_000);
			await seed({ log_id: 'paused=', url: 'https://p.example/' }, 'rfc6962', 0, 1_000, 'paused');
			const batches: Array<Array<{ body: CatchupRequest }>> = [];
			const queue = {
				async sendBatch(messages: Array<{ body: CatchupRequest }>) {
					batches.push(messages);
				},
			};
			const dispatch = (now = NOW) => dispatchCatchup({ CURSORS: db }, queue as never, NOW, { now });

			expect(await dispatch()).toMatchObject({ killed: false, rows: 2, sent: 2, failed: null });
			expect(batches[0]!.map((m) => m.body.logId).sort()).toEqual([RO.log_id, RO2.log_id].sort());
			expect(batches[0]![0]!.body).toMatchObject({ kind: 'catchup', scheduledTime: NOW, upperIndex: 1_000 });

			await db
				.prepare('UPDATE log_backfill SET hold_until = ? WHERE log_id = ?')
				.bind(new Date(NOW + 60_000).toISOString(), RO.log_id)
				.run();
			expect(await dispatch()).toMatchObject({ rows: 1, sent: 1 });
			expect(batches[1]!.map((m) => m.body.logId)).toEqual([RO2.log_id]);
			expect(await dispatch(NOW + 61_000)).toMatchObject({ rows: 2 }); // the hold has passed

			await db.prepare('INSERT INTO meta (k, v) VALUES (?, ?)').bind(CATCHUP_KILL_KEY, '1').run();
			const before = batches.length;
			expect(await dispatch()).toMatchObject({ killed: true, sent: 0 });
			expect(batches).toHaveLength(before);
		});

		it('a dispatch message runs its row only, and one older than CATCHUP_STALE_MS is dropped unread', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			await seed(RO2, 'rfc6962', 0, 1_000);
			await db.prepare("UPDATE log_backfill SET updated_at = '2026-01-01T00:00:00.000Z' WHERE log_id = ?").bind(RO.log_id).run();
			const net = fakeNetwork();
			const message: CatchupRequest = { kind: 'catchup', scheduledTime: NOW, logId: RO2.log_id, upperIndex: 1_000 };
			const env = { CURSORS: db, ENTRIES: fakeQueue().queue };

			const stale = await runCatchupMessage(env, message, { now: NOW + CATCHUP_STALE_MS + 1, fetch: both(net) });
			expect(stale).toEqual({ skipped: 'stale' });
			expect(net.calls).toEqual([]);

			await runCatchupMessage(env, message, { now: NOW + 1_000, fetch: both(net), maxFetches: 2, pageSize: 8 });
			expect(await row(RO2.log_id)).toMatchObject({ next_index: 16 });
			expect(await row(RO.log_id)).toMatchObject({ next_index: 0 }); // first in the list, not named: untouched
		});
	});

	describe('pages in flight', () => {
		it('keeps the configured number of requests in flight, never more, and the default stays within the header slots', async () => {
			expect(CATCHUP_PAGES_IN_FLIGHT).toBeLessThanOrEqual(HEADER_SLOTS);
			await seed(RO, 'rfc6962', 0, 10_000);
			const net = fakeNetwork();
			net.delayMs = 5;
			await run(net, fakeQueue(), { maxFetches: 40, pageSize: 8 });
			expect(net.maxInFlight).toBe(CATCHUP_PAGES_IN_FLIGHT);
			expect(net.calls).toHaveLength(40);

			const three = fakeNetwork();
			three.delayMs = 5;
			await run(three, fakeQueue(), { maxFetches: 20, pageSize: 8, pagesInFlight: 3 });
			expect(three.maxInFlight).toBe(3);
		});

		it('reads the CATCHUP_PAGES_IN_FLIGHT var; an invalid value means the default', async () => {
			await seed(RO, 'rfc6962', 0, 10_000);
			const queue = fakeQueue();
			const withVar = (value: string) => ({ CURSORS: db, ENTRIES: queue.queue, CATCHUP_PAGES_IN_FLIGHT: value });
			const two = fakeNetwork();
			two.delayMs = 5;
			await runCatchup(withVar('2'), { now: NOW, fetch: two.fetch, maxFetches: 12, pageSize: 8 });
			expect(two.maxInFlight).toBe(2);

			const junk = fakeNetwork();
			junk.delayMs = 5;
			await runCatchup(withVar('junk'), { now: NOW, fetch: junk.fetch, maxFetches: 20, pageSize: 8 });
			expect(junk.maxInFlight).toBe(CATCHUP_PAGES_IN_FLIGHT);
		});

		it('slides: a finished page is replaced at once, so a slow page does not idle the others', async () => {
			await seed(RO, 'rfc6962', 0, 10_000);
			const net = fakeNetwork();
			const base = net.fetch;
			let calls = 0;
			// the first page is slow; with a barrier, no page past the first window would start before it ends
			const slowFirst = (async (input: RequestInfo | URL) => {
				if (++calls === 1) await new Promise((resolve) => setTimeout(resolve, 80));
				return base(input);
			}) as typeof fetch;
			const started = await (async () => {
				const task = run({ fetch: slowFirst }, fakeQueue(), { maxFetches: 12, pageSize: 8, pagesInFlight: 3 });
				await new Promise((resolve) => setTimeout(resolve, 40));
				const during = net.calls.length;
				await task;
				return during;
			})();
			expect(started).toBeGreaterThan(3); // more than one window of 3 was already started while page 1 was still out
		});
	});

	describe('the learned page size', () => {
		it('a row with page_size starts aligned from the first request, with no probe of 256', async () => {
			await seed(RO, 'rfc6962', 100, 400);
			await db.prepare('UPDATE log_backfill SET page_size = 32 WHERE log_id = ?').bind(RO.log_id).run();
			const net = fakeNetwork(32);
			await run(net, fakeQueue(), { maxFetches: 3 });

			// the first page ends at the next multiple of 32, so the log does not cut it; the pages after it are whole
			expect(net.calls.map((url) => new URL(url).search)).toEqual(['?start=100&end=127', '?start=128&end=159', '?start=160&end=191']);
			expect(await row(RO.log_id)).toMatchObject({ next_index: 192, page_size: 32 });
		});

		it('a cold start asks for 256, learns what an unaligned first page teaches nothing of, and saves the size the log serves', async () => {
			await seed(RO, 'rfc6962', 100, 2_000);
			const net = fakeNetwork(32);
			await run(net, fakeQueue(), { maxFetches: 14 });
			// 100-255 is cut at 127 (28 entries, off a multiple of 32: teaches nothing); the page at 256 serves 32 and does,
			// and the page at 128 serves 32 again: two consecutive short pages of the same length, so 32 is saved
			expect((await row(RO.log_id))?.page_size).toBe(32);
			expect(Number((await row(RO.log_id))?.next_index)).toBeGreaterThanOrEqual(160);
		});

		it('one short page is not saved: a transient short page must not stick as the size', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			await run(fakeNetwork(8), fakeQueue(), { pageSize: 32, maxFetches: 4 });
			expect(await row(RO.log_id)).toMatchObject({ next_index: 8, page_size: null });
		});

		it('a size under 8 is saved only after 4 consecutive short pages', async () => {
			// two pages in flight, so each short page has a later page as evidence; every short page costs a reset and two fetches
			await seed(RO, 'rfc6962', 0, 1_000);
			await run(fakeNetwork(4), fakeQueue(), { pageSize: 32, pagesInFlight: 2, maxFetches: 3 }); // one short page
			expect((await row(RO.log_id))?.page_size).toBeNull();
			await run(fakeNetwork(4), fakeQueue(), { pageSize: 32, pagesInFlight: 2, maxFetches: 30 }); // many in a row
			expect((await row(RO.log_id))?.page_size).toBe(4);
		});

		it('the streak thresholds: 2 consecutive pages from 8 entries up, 4 below, and a different length starts again', () => {
			let s = nextStreak(null, 32);
			expect(s.learn).toBe(false);
			s = nextStreak(s.streak, 32);
			expect(s.learn).toBe(true);
			expect(nextStreak(nextStreak(null, 7).streak, 7).learn).toBe(false);
			let small = nextStreak(null, 4);
			for (let i = 0; i < 2; i++) small = nextStreak(small.streak, 4);
			expect(small.learn).toBe(false); // the third
			small = nextStreak(small.streak, 4);
			expect(small.learn).toBe(true); // the fourth
			expect(nextStreak(nextStreak(null, 32).streak, 31).learn).toBe(false); // a different length restarts at 1
			expect(nextStreak(null, 1).learn).toBe(false);
		});

		it('a full page between short pages breaks the streak', async () => {
			// a log serving 8 a page, asked 8 at a time: every page is full and no short length is ever recorded
			await seed(RO, 'rfc6962', 0, 1_000);
			await run(fakeNetwork(8), fakeQueue(), { pageSize: 8, maxFetches: 6 });
			expect((await row(RO.log_id))?.page_size).toBeNull();
		});

		it('a stored size that is too small is raised by the probe, on every run while it is under 32', async () => {
			await seed(RO, 'rfc6962', 0, 10_000);
			await db.prepare('UPDATE log_backfill SET page_size = 8 WHERE log_id = ?').bind(RO.log_id).run();
			const net = fakeNetwork(32);
			await run(net, fakeQueue(), { maxFetches: 3 });

			expect(new URL(net.calls[0]!).search).toBe('?start=0&end=255'); // the probe: one full page at an aligned start
			expect((await row(RO.log_id))?.page_size).toBe(32);
			expect(net.calls.slice(1).map((url) => new URL(url).search)).toEqual(['?start=0&end=31', '?start=32&end=63']);
		});

		it('a stored size of 32 or more is probed on one run in 30, by the clock, and not otherwise', async () => {
			await seed(RO, 'rfc6962', 0, 10_000);
			await db.prepare('UPDATE log_backfill SET page_size = 32 WHERE log_id = ?').bind(RO.log_id).run();
			const onSlot = Date.parse('2026-11-27T06:00:00Z'); // minute 0 of the hour: slot 0 of 30
			const probed = fakeNetwork(64);
			await run(probed, fakeQueue(), { maxFetches: 2 }, onSlot);
			expect(new URL(probed.calls[0]!).search).toBe('?start=0&end=255');
			expect((await row(RO.log_id))?.page_size).toBe(64);

			const from = Number((await row(RO.log_id))?.next_index);
			await db.prepare('UPDATE log_backfill SET hold_until = NULL, page_size = 32').run();
			const off = fakeNetwork(64);
			await run(off, fakeQueue(), { maxFetches: 2 }, onSlot + 120_000);
			expect(new URL(off.calls[0]!).search).toBe(`?start=${from}&end=${from + 31}`); // no probe
		});

		it('a probe that finds the same size, or a size that does not divide its start, changes nothing', async () => {
			await seed(RO, 'rfc6962', 0, 10_000);
			await db.prepare('UPDATE log_backfill SET page_size = 8 WHERE log_id = ?').bind(RO.log_id).run();
			await run(fakeNetwork(8), fakeQueue(), { maxFetches: 2 });
			expect((await row(RO.log_id))?.page_size).toBe(8);

			await db.prepare('UPDATE log_backfill SET hold_until = NULL WHERE log_id = ?').bind(RO.log_id).run();
			await run(fakeNetwork(20), fakeQueue(), { maxFetches: 2 }); // 256 % 20 != 0: not a cap this log is aligned to
			expect((await row(RO.log_id))?.page_size).toBe(8);
		});

		it('rejects a page_size outside 1..256', async () => {
			await seed(RO, 'rfc6962', 0, 10);
			for (const size of [0, 257]) {
				await expect(db.prepare('UPDATE log_backfill SET page_size = ? WHERE log_id = ?').bind(size, RO.log_id).run()).rejects.toThrow();
			}
		});
	});

	describe('overlap, back-off and the log line', () => {
		it('an overlapping run finds the row held and reads nothing, so the load is not doubled', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			const net = fakeNetwork();
			let release: () => void = () => {};
			const gate = new Promise<void>((resolve) => (release = resolve));
			const slow = (async (input: RequestInfo | URL) => {
				await gate;
				return net.fetch(input);
			}) as typeof fetch;
			const first = run({ fetch: slow }, fakeQueue(), { maxFetches: 2, pageSize: 8 });
			await vi.waitFor(async () => expect((await row(RO.log_id))?.hold_until).not.toBeNull());

			const calls: string[] = [];
			const second = await run(
				{ fetch: (async (input: RequestInfo | URL) => (calls.push(String(input)), net.fetch(input))) as typeof fetch },
				fakeQueue(),
				{
					maxFetches: 2,
					pageSize: 8,
					only: { logId: RO.log_id, upperIndex: 1_000 },
				},
			);
			expect(second).toMatchObject({ rows: 0, held: 1, entries: 0 });
			expect(calls).toEqual([]);

			release();
			await first;
			// the lease is released at the end of a normal run; the next run takes the row
			expect((await row(RO.log_id))?.hold_until).toBeNull();
			expect(await row(RO.log_id)).toMatchObject({ next_index: 16 });
			await run(fakeNetwork(), fakeQueue(), { maxFetches: 1, pageSize: 8 });
			expect((await row(RO.log_id))?.next_index).toBe(24);
		});

		it('a lease that has expired (a run that died) does not hold the row', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			await db
				.prepare('UPDATE log_backfill SET hold_until = ? WHERE log_id = ?')
				.bind(new Date(NOW - 1).toISOString(), RO.log_id)
				.run();
			await run(fakeNetwork(), fakeQueue(), { maxFetches: 1, pageSize: 8 });
			expect((await row(RO.log_id))?.next_index).toBe(8);
		});

		it('a 429 stops further requests, defers the row for CATCHUP_BACKOFF_MS, and does not hammer', async () => {
			await seed(RO, 'rfc6962', 0, 100_000);
			const net = fakeNetwork();
			const limited = (async (input: RequestInfo | URL) => (
				net.calls.push(String(input)),
				new Response('slow down', { status: 429 })
			)) as typeof fetch;
			const summary = await run({ fetch: limited }, fakeQueue(), { pageSize: 8 });

			expect(net.calls.length).toBeLessThanOrEqual(CATCHUP_PAGES_IN_FLIGHT); // the first wave, and no second one
			expect(summary.perRow[0]).toMatchObject({ rateLimited: net.calls.length, deferrals: 0 });
			expect(await holdAfterNow(RO.log_id)).toBeGreaterThanOrEqual(CATCHUP_BACKOFF_MS);
			expect(await holdAfterNow(RO.log_id)).toBeLessThan(CATCHUP_BACKOFF_MS + 5_000);

			const early = fakeNetwork();
			await run(early, fakeQueue(), {}, NOW + CATCHUP_BACKOFF_MS - 1);
			expect(early.calls).toEqual([]);
			const later = fakeNetwork();
			await run(later, fakeQueue(), { maxFetches: 1, pageSize: 8 }, NOW + CATCHUP_BACKOFF_MS + 5_000);
			expect(later.calls).toHaveLength(1);
		});

		it('a 5xx stops further requests and backs the row off the same way', async () => {
			await seed(RO, 'rfc6962', 0, 100_000);
			const calls: string[] = [];
			const down = (async (input: RequestInfo | URL) => (calls.push(String(input)), new Response('down', { status: 503 }))) as typeof fetch;
			const summary = await run({ fetch: down }, fakeQueue(), { pageSize: 8 });

			expect(calls.length).toBeLessThanOrEqual(CATCHUP_PAGES_IN_FLIGHT);
			expect(summary.perRow[0]).toMatchObject({ httpErrors: calls.length });
			expect(summary.errors[RO.log_id]).toContain('HTTP 503');
			expect(await holdAfterNow(RO.log_id)).toBeGreaterThanOrEqual(CATCHUP_BACKOFF_MS);
		});

		it('the phase ending is not a failure: no error, no back-off, the lease is released', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			const summary = await run(fakeNetwork(), fakeQueue(), { phaseMs: 0 });
			expect(summary).toMatchObject({ rows: 1, errors: {}, deferred: {} });
			expect(await row(RO.log_id)).toMatchObject({ next_index: 0, hold_until: null, last_error: null });
		});

		it('reports per row entries, fetches, median and max page latency, timeouts and deferrals', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			const net = fakeNetwork();
			net.delayMs = 10;
			const summary = await run(net, fakeQueue(), { maxFetches: 4, pageSize: 8 });
			const stats = summary.perRow[0]!;
			expect(stats).toMatchObject({
				logId: RO.log_id,
				entries: 32,
				fetches: 4,
				pages: 4,
				timeouts: 0,
				rateLimited: 0,
				httpErrors: 0,
				deferrals: 0,
			});
			expect(stats.medianMs).toBeGreaterThanOrEqual(8);
			expect(stats.maxMs).toBeGreaterThanOrEqual(stats.medianMs!);

			await db.prepare('UPDATE log_backfill SET hold_until = NULL, updated_at = NULL').run();
			const timedOut = (async () => {
				throw new DOMException('The operation timed out', 'TimeoutError');
			}) as typeof fetch;
			const failed = await run({ fetch: timedOut }, fakeQueue(), { maxFetches: 2, pageSize: 8 });
			expect(failed.perRow[0]).toMatchObject({ timeouts: 2, pages: 0, medianMs: null, maxMs: null });

			await db.prepare('UPDATE log_backfill SET hold_until = NULL').run();
			const empty = await run({ fetch: (async () => Response.json({ entries: [] })) as typeof fetch }, fakeQueue(), {
				maxFetches: 1,
				pageSize: 8,
			});
			expect(empty.perRow[0]).toMatchObject({ deferrals: 1, rateLimited: 0 });
		});
	});

	describe('a discarded page, a lost lease and a kill', () => {
		it('a discarded page that fails after a short-page reset does not halt the run', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			const net = fakeNetwork(8);
			net.delayMs = 20; // every reply takes 20 ms, so the run is still going when the late 429 arrives
			const base = net.fetch;
			let late = 0;
			// asked 32 at a time from 0 the log serves 8; the page at 64 is in flight (and slow) when the short first page resets
			// the pipeline, and its 429 then arrives for a page no one is reading any more
			const flaky = (async (input: RequestInfo | URL) => {
				const start = new URL(String(input instanceof Request ? input.url : input)).searchParams.get('start');
				if (start === '64' && late++ === 0) {
					await new Promise((resolve) => setTimeout(resolve, 25));
					return new Response('slow down', { status: 429 });
				}
				return base(input);
			}) as typeof fetch;
			const summary = await run({ fetch: flaky }, fakeQueue(), { pageSize: 32, maxFetches: 40 });

			expect(summary.deferred).toEqual({});
			expect(summary.errors).toEqual({});
			expect(Number((await row(RO.log_id))?.next_index)).toBeGreaterThan(24); // the run carried on past the reset
			expect((await row(RO.log_id))?.hold_until).toBeNull();
		});

		it('a run that outlived its lease writes nothing to the row and records no error', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			let release: () => void = () => {};
			const gate = new Promise<void>((resolve) => (release = resolve));
			const failing = (async () => {
				await gate;
				return new Response('down', { status: 503 });
			}) as typeof fetch;
			const first = run({ fetch: failing }, fakeQueue(), { maxFetches: 1, pageSize: 8 });
			await vi.waitFor(async () => expect((await row(RO.log_id))?.hold_until).not.toBeNull());
			// another run took the row over (this one's lease expired): its lease is what the row holds now
			const newer = new Date(NOW + 600_000).toISOString();
			await db.prepare('UPDATE log_backfill SET hold_until = ? WHERE log_id = ?').bind(newer, RO.log_id).run();
			release();
			const summary = await first;

			expect(summary.errors).toEqual({});
			expect(await row(RO.log_id)).toMatchObject({ hold_until: newer, last_error: null, last_error_at: null });
		});

		it('measures the back-off from the failure, not from the start of the run', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			const slowDown = (async () => {
				await new Promise((resolve) => setTimeout(resolve, 60));
				return new Response('down', { status: 503 });
			}) as typeof fetch;
			await run({ fetch: slowDown }, fakeQueue(), { maxFetches: 1, pageSize: 8 });
			expect(await holdAfterNow(RO.log_id)).toBeGreaterThanOrEqual(CATCHUP_BACKOFF_MS + 50);
		});

		it('hold_until must be ISO-8601 with T and Z', async () => {
			await seed(RO, 'rfc6962', 0, 1_000);
			for (const bad of ['12/1/2026', '2026-12-01 00:00:00', '2026-12-01T00:00:00', 'z']) {
				await expect(
					db.prepare('UPDATE log_backfill SET hold_until = ? WHERE log_id = ?').bind(bad, RO.log_id).run(),
					bad,
				).rejects.toThrow();
			}
			await db.prepare('UPDATE log_backfill SET hold_until = ? WHERE log_id = ?').bind('2026-12-01T00:00:00.000Z', RO.log_id).run();
			await db.prepare('UPDATE log_backfill SET hold_until = NULL WHERE log_id = ?').bind(RO.log_id).run();
		});

		it('no request starts after the kill switch read returns killed', async () => {
			await seed(RO, 'rfc6962', 0, 100_000);
			const net = fakeNetwork();
			net.delayMs = 5;
			let callsWhenKilled: number | null = null;
			const spied = new Proxy(db, {
				get(target, prop) {
					if (prop !== 'batch') return Reflect.get(target, prop).bind?.(target) ?? Reflect.get(target, prop);
					return async (statements: D1PreparedStatement[]) => {
						const result = await target.batch(statements);
						if (callsWhenKilled === null && JSON.stringify(result[1]?.results ?? []).includes('"1"')) callsWhenKilled = net.calls.length;
						return result;
					};
				},
			});
			// the switch is thrown by the third request; the next re-read (killRecheckMs 0) finds it
			const base = net.fetch;
			let served = 0;
			const fetcher = (async (input: RequestInfo | URL) => {
				if (++served === 3) await db.prepare('INSERT INTO meta (k, v) VALUES (?, ?)').bind(CATCHUP_KILL_KEY, '1').run();
				return base(input);
			}) as typeof fetch;
			const summary = await runCatchup(
				{ CURSORS: spied as unknown as D1Database, ENTRIES: fakeQueue().queue },
				{ now: NOW, fetch: fetcher, pageSize: 8, pagesInFlight: 3, killRecheckMs: 0 },
			);

			expect(summary.killed).toBe(true);
			expect(callsWhenKilled).not.toBeNull();
			expect(net.calls.length).toBe(callsWhenKilled);
		});
	});

	describe('the default caps', () => {
		it('bound a run by numbers: entries within one page of CATCHUP_MAX_ENTRIES and fetches within CATCHUP_MAX_FETCHES', async () => {
			expect(CATCHUP_MAX_ENTRIES).toBe(24_000);
			expect(CATCHUP_MAX_FETCHES).toBe(800);
			expect(CATCHUP_PHASE_MS).toBe(100_000);
			await seed(RO, 'rfc6962', 0, 1_000_000);
			await db.prepare('UPDATE log_backfill SET page_size = 32 WHERE log_id = ?').bind(RO.log_id).run();
			const net = fakeNetwork(32);
			const summary = await run(net, fakeQueue()); // no overrides: the shipped defaults

			expect(summary.entries).toBe(24_000); // 750 whole pages of 32
			expect(net.calls).toHaveLength(750);
			expect(net.calls.length).toBeLessThanOrEqual(CATCHUP_MAX_FETCHES);
			expect((await row(RO.log_id))?.next_index).toBe(24_000);
		}, 60_000);
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
