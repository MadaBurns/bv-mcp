// SPDX-License-Identifier: BUSL-1.1
/**
 * runTailer end to end against miniflare D1, with a fake CT network and a fake ENTRIES queue (no live
 * network): forward-only start, paged RFC 6962 and full-tile static-ct reads, cursor advance only after the
 * send resolves, per-log error isolation, the kill switch, the Geomys/IPng exclusion and the ops ledger.
 */

import { env } from 'cloudflare:workers';
import { beforeEach, describe, expect, it } from 'vitest';
import cursorsSql from '../../../migrations/0001_log_cursors.sql?raw';
import catalogSql from '../../../migrations/0002_catalog.sql?raw';
import cursorErrorsSql from '../../../migrations/0003_cursor_errors.sql?raw';
import { nameKey } from '../../codec';
import type { Env } from '../../index';
import { LOG_LIST_URL, TILE_WIDTH, tilePath } from '../../tailer/ct';
import { resetLogListMemo, runTailer } from '../../tailer';
import type { ObservationBatch } from '../../types';
import {
	MULTI_APEX_TILE_LEAF,
	RFC6962_PRECERT_FACTS,
	RFC6962_PRECERT_LEAF_INPUT,
	RFC6962_X509_LEAF_INPUT,
	STATIC_PRECERT_FACTS,
	STATIC_PRECERT_TILE_LEAF,
	STATIC_X509_TILE_LEAF,
} from './fixtures';

const db = (env as unknown as Env).CURSORS;
const NOW = Date.parse('2026-10-17T06:00:00Z');
const DAY = '2026-10-17';
const RFC = { log_id: 'rfc-log-id=', url: 'https://rfc.ct.test/2027h1/' };
const STATIC = { log_id: 'static-log-id=', monitoring_url: 'https://static.ct.test/2027h1/' };
const GEOMYS = { log_id: 'geomys-log-id=', monitoring_url: 'https://tuscolo.geomys.test/2027h1/' };
const interval = { start_inclusive: '2027-01-01T00:00:00Z', end_exclusive: '2027-07-01T00:00:00Z' };
const LIST = {
	operators: [
		{ name: 'DigiCert', logs: [{ ...RFC, state: { usable: {} }, temporal_interval: interval }], tiled_logs: [] },
		{ name: "Let's Encrypt", logs: [], tiled_logs: [{ ...STATIC, state: { usable: {} }, temporal_interval: interval }] },
		{ name: 'Geomys', logs: [], tiled_logs: [{ ...GEOMYS, state: { usable: {} }, temporal_interval: interval }] },
	],
};

const bytes = (base64: string) => Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
/** A full data tile from real TileLeaf records: entry 3 a precert, entry 4 the >32-apex precert, the rest x509. */
const TILE = new Uint8Array(
	Array.from({ length: TILE_WIDTH }, (_, i) =>
		i === 3 ? bytes(STATIC_PRECERT_TILE_LEAF) : i === 4 ? bytes(MULTI_APEX_TILE_LEAF) : bytes(STATIC_X509_TILE_LEAF),
	).flatMap((leaf) => [...leaf]),
);

interface Network {
	rfcSize: number;
	staticSize: number;
	/** Entries per get-entries page, like the real logs' caps. */
	pageCap: number;
	failures: Map<string, number>;
	calls: string[];
}

function fakeNetwork(overrides: Partial<Network> = {}): Network & { fetch: typeof fetch } {
	const net: Network = { rfcSize: 1_000, staticSize: 5 * TILE_WIDTH + 17, pageCap: 8, failures: new Map(), calls: [], ...overrides };
	const fetcher = async (input: RequestInfo | URL) => {
		const url = input instanceof Request ? input.url : String(input);
		net.calls.push(url);
		const failure = [...net.failures].find(([prefix]) => url.startsWith(prefix));
		if (failure) return new Response('unavailable', { status: failure[1] });
		if (url === LOG_LIST_URL) return Response.json(LIST);
		if (url === `${RFC.url}ct/v1/get-sth`) return Response.json({ tree_size: net.rfcSize, timestamp: NOW });
		if (url.startsWith(`${RFC.url}ct/v1/get-entries?`)) {
			const query = new URL(url).searchParams;
			const start = Number(query.get('start'));
			const end = Math.min(Number(query.get('end')), start + net.pageCap - 1);
			const entries = Array.from({ length: end - start + 1 }, (_, k) => ({
				leaf_input: (start + k) % 2 === 0 ? RFC6962_PRECERT_LEAF_INPUT : RFC6962_X509_LEAF_INPUT,
				extra_data: '',
			}));
			return Response.json({ entries });
		}
		if (url === `${STATIC.monitoring_url}checkpoint`) return new Response(`static.ct.test/2027h1\n${net.staticSize}\nAAAA\n\n— sig\n`);
		if (url.startsWith(`${STATIC.monitoring_url}tile/data/`)) {
			const full = Math.floor(net.staticSize / TILE_WIDTH);
			const ok = Array.from({ length: full }, (_, t) => `${STATIC.monitoring_url}tile/data/${tilePath(t)}`);
			return ok.includes(url) ? new Response(TILE) : new Response('not found', { status: 404 });
		}
		return new Response('unexpected request', { status: 599 });
	};
	return Object.assign(net, { fetch: fetcher as typeof fetch });
}

interface FakeQueue {
	queue: Queue<ObservationBatch>;
	sent: ObservationBatch[];
	options: unknown[];
}

function fakeQueue(onSend: (batch: ObservationBatch) => Promise<void> = async () => {}): FakeQueue {
	const sent: ObservationBatch[] = [];
	const options: unknown[] = [];
	const queue = {
		async send(batch: ObservationBatch, sendOptions?: unknown) {
			options.push(sendOptions);
			await onSend(batch);
			sent.push(JSON.parse(JSON.stringify(batch)));
		},
		async sendBatch() {
			throw new Error('not used');
		},
	} as unknown as Queue<ObservationBatch>;
	return { queue, sent, options };
}

async function cursor(logId: string) {
	return db.prepare('SELECT * FROM log_cursors WHERE log_id = ?').bind(logId).first<Record<string, unknown>>();
}

async function seed(logId: string, kind: 'rfc6962' | 'static', url: string, nextIndex: number) {
	await db
		.prepare('INSERT INTO log_cursors (log_id, kind, url, next_index, tree_size, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
		.bind(logId, kind, url, nextIndex, nextIndex, '2026-10-17T05:59:00Z')
		.run();
}

const run = (net: { fetch: typeof fetch }, queue: FakeQueue, scheduledTime = NOW) =>
	runTailer({ CURSORS: db, ENTRIES: queue.queue }, { scheduledTime, now: NOW, fetch: net.fetch });

beforeEach(async () => {
	resetLogListMemo();
	// D1 state persists across the tests of a file: rebuild the schema from the real migrations each time.
	await db.batch(['log_cursors', 'runs', 'meta', 'ops_ledger'].map((table) => db.prepare(`DROP TABLE IF EXISTS ${table}`)));
	for (const sql of [cursorsSql, catalogSql, cursorErrorsSql]) {
		// Comments go first: 0001's comment holds a ';'.
		const statements = sql
			.replace(/--.*$/gm, '')
			.split(';')
			.map((statement) => statement.trim())
			.filter((statement) => statement !== '');
		await db.batch(statements.map((statement) => db.prepare(statement)));
	}
});

describe('runTailer', () => {
	it('starts a log it has never seen at its current tree size and reads no entries (forward-only)', async () => {
		const net = fakeNetwork();
		const queue = fakeQueue();
		const summary = await run(net, queue);

		expect(await cursor(RFC.log_id)).toMatchObject({
			kind: 'rfc6962',
			url: RFC.url,
			next_index: 1_000,
			tree_size: 1_000,
			last_error: null,
		});
		expect(await cursor(STATIC.log_id)).toMatchObject({ kind: 'static', url: STATIC.monitoring_url, next_index: 5 * TILE_WIDTH + 17 });
		expect(net.calls.filter((url) => url.includes('get-entries') || url.includes('/tile/'))).toEqual([]);
		expect(queue.sent).toEqual([]);
		expect(summary).toMatchObject({ killed: false, logs: 2, cursorsWritten: 2, entries: 0 });
	});

	it('pages RFC 6962 entries and reads full static tiles, sends precert observations, then advances the cursors', async () => {
		await seed(RFC.log_id, 'rfc6962', RFC.url, 980);
		await seed(STATIC.log_id, 'static', STATIC.monitoring_url, 3 * TILE_WIDTH + 2); // inside tile 3: entries 2.. of it
		const net = fakeNetwork();
		const queue = fakeQueue();
		const summary = await run(net, queue);

		// 20 RFC entries in 8-entry pages; tiles 3 and 4 (the full ones); never the partial tile 5.
		expect(net.calls.filter((url) => url.includes('get-entries'))).toHaveLength(3);
		expect(net.calls.filter((url) => url.includes('/tile/data/'))).toEqual([
			`${STATIC.monitoring_url}tile/data/${tilePath(3)}`,
			`${STATIC.monitoring_url}tile/data/${tilePath(4)}`,
		]);
		expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 1_000, tree_size: 1_000 });
		expect(await cursor(STATIC.log_id)).toMatchObject({ next_index: 5 * TILE_WIDTH, tree_size: 5 * TILE_WIDTH + 17 });
		// x509 entries are skipped: 10 of 20 RFC entries, and 2 of the 254 + 256 tile entries, are precerts.
		expect(summary).toMatchObject({ entries: 20 + 254 + 256, precerts: 10 + 4, badEntries: 0 });

		const rfcBatch = queue.sent.find((batch) => batch.logId === RFC.log_id)!;
		expect(rfcBatch).toMatchObject({ startIndex: 980, endIndex: 1_000, siblings: [] });
		expect(rfcBatch.names).toEqual([
			{
				key: nameKey('4f6k.com').key,
				name: '4f6k.com',
				apex: '4f6k.com',
				firstSeen: RFC6962_PRECERT_FACTS.notBefore,
				notAfter: RFC6962_PRECERT_FACTS.notAfter,
				issuer: RFC6962_PRECERT_FACTS.issuer,
				wildcard: true,
			},
		]);
		const staticBatches = queue.sent.filter((batch) => batch.logId === STATIC.log_id);
		expect(staticBatches.every((batch) => batch.startIndex === 3 * TILE_WIDTH + 2 && batch.endIndex === 5 * TILE_WIDTH)).toBe(true);
		const staticNames = staticBatches.flatMap((batch) => batch.names);
		expect(staticNames.find((row) => row.name === 'bluemoonstudio.au')).toMatchObject({
			wildcard: true,
			firstSeen: STATIC_PRECERT_FACTS.notBefore,
		});
		expect(staticNames.some((row) => row.apex === 'agoda.com')).toBe(true);
		// Siblings come only from the 2-apex precert; the >32-apex precert contributes names but no pairs.
		expect(staticBatches.flatMap((batch) => batch.siblings).map((row) => `${row.apex}>${row.sibling}`)).toEqual([
			'bluemoonstudio.au>totallyrenewableyack.org.au',
			'totallyrenewableyack.org.au>bluemoonstudio.au',
		]);
		expect(queue.options.every((options) => (options as { contentType?: string }).contentType === 'json')).toBe(true);
	});

	it('writes no cursor until the send has resolved', async () => {
		await seed(RFC.log_id, 'rfc6962', RFC.url, 990);
		await seed(STATIC.log_id, 'static', STATIC.monitoring_url, 5 * TILE_WIDTH + 17);
		let release!: () => void;
		let sendStarted!: () => void;
		const started = new Promise<void>((resolve) => (sendStarted = resolve));
		const queue = fakeQueue(() => {
			sendStarted();
			return new Promise<void>((resolve) => (release = resolve));
		});
		const tick = run(fakeNetwork(), queue);

		await started;
		expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 990 });
		release();
		await tick;
		expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 1_000 });
	});

	it('keeps the cursor and records the error when a send fails, and sends nothing for later logs', async () => {
		await seed(RFC.log_id, 'rfc6962', RFC.url, 990);
		await seed(STATIC.log_id, 'static', STATIC.monitoring_url, 4 * TILE_WIDTH);
		const queue = fakeQueue(async () => {
			throw new Error('queue unavailable');
		});
		// Tick 0 rotates the log order to [rfc, static] (log ids sort that way): the RFC log sends first and fails.
		const summary = await run(fakeNetwork(), queue, 0);

		expect(await cursor(RFC.log_id)).toMatchObject({
			next_index: 990,
			last_error: 'queue send: queue unavailable',
			last_error_at: '2026-10-17T06:00:00.000Z',
		});
		expect(await cursor(STATIC.log_id)).toMatchObject({ next_index: 4 * TILE_WIDTH, last_error: null });
		expect(queue.options).toHaveLength(1);
		expect(summary.errors).toEqual({ [RFC.log_id]: 'queue send: queue unavailable' });
	});

	it('isolates a failing log: its error is recorded and the other log still advances', async () => {
		await seed(RFC.log_id, 'rfc6962', RFC.url, 990);
		await seed(STATIC.log_id, 'static', STATIC.monitoring_url, 4 * TILE_WIDTH);
		const net = fakeNetwork({ failures: new Map([[`${RFC.url}ct/v1/get-sth`, 503]]) });
		const summary = await run(net, fakeQueue());

		expect(await cursor(RFC.log_id)).toMatchObject({
			next_index: 990,
			tree_size: 990,
			updated_at: '2026-10-17T05:59:00Z',
			last_error: `HTTP 503 from ${RFC.url}ct/v1/get-sth`,
		});
		expect(await cursor(STATIC.log_id)).toMatchObject({ next_index: 5 * TILE_WIDTH, last_error: null });
		expect(Object.keys(summary.errors)).toEqual([RFC.log_id]);
	});

	it('keeps progress up to the last complete page when a later page fails', async () => {
		await seed(RFC.log_id, 'rfc6962', RFC.url, 980);
		const net = fakeNetwork();
		const original = net.fetch;
		net.fetch = (async (input: RequestInfo | URL) =>
			String(input).includes('get-entries?start=988') ? new Response('busy', { status: 503 }) : original(input)) as typeof fetch;
		await run(net, fakeQueue());

		expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 988, last_error: expect.stringContaining('HTTP 503') });
	});

	// SQ-355: the prod error shapes of 2026-10-17. A log that has not served the next entries yet, or that rate
	// limits, defers: the visit ends, progress stands, no last_error, and the next tick picks up from the cursor.
	describe('deferrals (SQ-355)', () => {
		/** Wraps the fake network: `answer` may replace the response for a URL. */
		const intercept = (net: ReturnType<typeof fakeNetwork>, answer: (url: string) => Response | undefined) => {
			const original = net.fetch;
			net.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
				const url = String(input);
				const replaced = answer(url);
				if (!replaced) return original(input, init);
				net.calls.push(url);
				return replaced;
			}) as typeof fetch;
			return net;
		};

		it('defers a single-entry range at the tree tip that comes back empty (Sectigo Tiger2027h2 31011-31011), then reads it next tick', async () => {
			await seed(RFC.log_id, 'rfc6962', RFC.url, 999);
			const lagging = intercept(fakeNetwork(), (url) =>
				url.includes('get-entries?start=999&end=999') ? Response.json({ entries: [] }) : undefined,
			);
			const summary = await run(lagging, fakeQueue());

			expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 999, tree_size: 1_000, last_error: null });
			expect(summary.errors).toEqual({});
			expect(summary.deferred).toEqual({ [RFC.log_id]: 'get-entries 999-999: no entries served yet' });

			resetLogListMemo();
			const next = await run(fakeNetwork(), fakeQueue());
			expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 1_000, last_error: null });
			expect(next).toMatchObject({ entries: 1, deferred: {} });
		});

		it('advances by a short page and defers at the empty one after it (Sectigo Elephant2026h2, 204 of 256)', async () => {
			await seed(RFC.log_id, 'rfc6962', RFC.url, 400);
			const net = intercept(fakeNetwork({ pageCap: 256 }), (url) => {
				const query = new URL(url).searchParams;
				if (!url.includes('get-entries?')) return undefined;
				const start = Number(query.get('start'));
				// The replica holds entries below 604: a 204-entry page from 400, then nothing.
				const entries = Array.from({ length: Math.max(0, Math.min(Number(query.get('end')), 603) - start + 1) }, () => ({
					leaf_input: RFC6962_PRECERT_LEAF_INPUT,
					extra_data: '',
				}));
				return Response.json({ entries });
			});
			const summary = await run(net, fakeQueue());

			expect(net.calls.filter((url) => url.includes('get-entries'))).toEqual([
				`${RFC.url}ct/v1/get-entries?start=400&end=655`,
				`${RFC.url}ct/v1/get-entries?start=604&end=859`,
			]);
			expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 604, last_error: null });
			expect(summary).toMatchObject({ entries: 204, errors: {}, deferred: { [RFC.log_id]: 'get-entries 604-859: no entries served yet' } });
		});

		it('still records an error for an entries array longer than the range asked for', async () => {
			await seed(RFC.log_id, 'rfc6962', RFC.url, 999);
			const net = intercept(fakeNetwork(), (url) =>
				url.includes('get-entries?') ? Response.json({ entries: [{ leaf_input: RFC6962_PRECERT_LEAF_INPUT }, { leaf_input: RFC6962_PRECERT_LEAF_INPUT }] }) : undefined,
			);
			const summary = await run(net, fakeQueue());

			expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 999, last_error: 'get-entries 999-999: bad entries array' });
			expect(summary.deferred).toEqual({});
		});

		it('defers a checkpoint-covered data tile the CDN still answers 404 for (TrustAsia Luoshu2027), then reads it next tick', async () => {
			await seed(STATIC.log_id, 'static', STATIC.monitoring_url, 3 * TILE_WIDTH);
			const tile4 = `${STATIC.monitoring_url}tile/data/${tilePath(4)}`;
			const cached404 = intercept(fakeNetwork(), (url) => (url === tile4 ? new Response('404', { status: 404 }) : undefined));
			const summary = await run(cached404, fakeQueue());

			// Tile 3 is read and kept; tile 4 (full per the checkpoint of 5 * 256 + 17) defers.
			expect(await cursor(STATIC.log_id)).toMatchObject({ next_index: 4 * TILE_WIDTH, tree_size: 5 * TILE_WIDTH + 17, last_error: null });
			expect(summary.errors).toEqual({});
			expect(summary.deferred).toEqual({ [STATIC.log_id]: 'data tile 4: HTTP 404, not served yet' });

			resetLogListMemo();
			await run(fakeNetwork(), fakeQueue());
			expect(await cursor(STATIC.log_id)).toMatchObject({ next_index: 5 * TILE_WIDTH, last_error: null });
		});

		it('still records an error for a 404 on the checkpoint itself', async () => {
			await seed(STATIC.log_id, 'static', STATIC.monitoring_url, 3 * TILE_WIDTH);
			await run(fakeNetwork({ failures: new Map([[`${STATIC.monitoring_url}checkpoint`, 404]]) }), fakeQueue());
			expect(await cursor(STATIC.log_id)).toMatchObject({
				next_index: 3 * TILE_WIDTH,
				last_error: `HTTP 404 from ${STATIC.monitoring_url}checkpoint`,
			});
		});

		it('skips the rest of the tick on HTTP 429 (TrustAsia log2026a), keeping the pages read before it and recording no error', async () => {
			await seed(RFC.log_id, 'rfc6962', RFC.url, 980);
			const net = intercept(fakeNetwork(), (url) => (url.includes('get-entries?start=988') ? new Response('', { status: 429 }) : undefined));
			const summary = await run(net, fakeQueue());

			expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 988, last_error: null });
			expect(net.calls.filter((url) => url.includes('get-entries?start=988'))).toHaveLength(1);
			expect(summary.errors).toEqual({});
			expect(summary.deferred).toEqual({ [RFC.log_id]: `rate limited: HTTP 429 from ${RFC.url}ct/v1/get-entries?start=988&end=999` });
		});

		it('defers a log whose head answers 429 without inventing or moving its cursor', async () => {
			await seed(RFC.log_id, 'rfc6962', RFC.url, 980);
			const summary = await run(fakeNetwork({ failures: new Map([[`${RFC.url}ct/v1/get-sth`, 429]]) }), fakeQueue());
			expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 980, tree_size: 980, last_error: null });
			expect(Object.keys(summary.deferred)).toEqual([RFC.log_id]);
		});

		it('a log that hangs until the fetch timeout (Microsec Eszigno2026h2) records a named timeout and does not stall the other log', async () => {
			await seed(RFC.log_id, 'rfc6962', RFC.url, 980);
			await seed(STATIC.log_id, 'static', STATIC.monitoring_url, 3 * TILE_WIDTH);
			const net = fakeNetwork();
			const original = net.fetch;
			const hanging = `${RFC.url}ct/v1/get-entries?start=980`;
			net.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
				const url = String(input);
				if (!url.startsWith(hanging)) return original(input, init);
				net.calls.push(url);
				const signal = init!.signal!;
				return new Promise<Response>((_, reject) => signal.addEventListener('abort', () => reject(signal.reason)));
			}) as typeof fetch;
			// Tick 0 visits the RFC log first, so the hang starts before the static log is read.
			const summary = await runTailer({ CURSORS: db, ENTRIES: fakeQueue().queue }, { scheduledTime: 0, now: NOW, fetch: net.fetch, fetchTimeoutMs: 50 });

			expect(net.calls.filter((url) => url.startsWith(hanging))).toHaveLength(1);
			expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 980, last_error: expect.stringMatching(/timeout.*\(https:\/\/rfc\.ct\.test\/2027h1\/ct\/v1\/get-entries\?start=980&end=999\)$/i) });
			expect(await cursor(STATIC.log_id)).toMatchObject({ next_index: 5 * TILE_WIDTH, last_error: null });
			expect(Object.keys(summary.errors)).toEqual([RFC.log_id]);
		});
	});

	it('records a head failure for a new log without inventing a cursor, and starts it once the head answers', async () => {
		const failing = fakeNetwork({ failures: new Map([[`${STATIC.monitoring_url}checkpoint`, 500]]) });
		await run(failing, fakeQueue());
		expect(await cursor(STATIC.log_id)).toMatchObject({ next_index: null, last_error: expect.stringContaining('HTTP 500') });

		resetLogListMemo();
		await run(fakeNetwork(), fakeQueue());
		expect(await cursor(STATIC.log_id)).toMatchObject({ next_index: 5 * TILE_WIDTH + 17 });
	});

	it('does nothing at all while the ops ledger kill switch is set', async () => {
		await seed(RFC.log_id, 'rfc6962', RFC.url, 990);
		await db
			.prepare('INSERT INTO ops_ledger (day, r2_class_a, r2_class_b, d1_rows, killed) VALUES (?, 0, 7, 7, 1)')
			.bind('2026-10-16')
			.run();
		const net = fakeNetwork();
		const queue = fakeQueue();
		const summary = await run(net, queue);

		expect(summary).toMatchObject({ killed: true, logs: 0, subrequests: 0 });
		expect(net.calls).toEqual([]);
		expect(queue.sent).toEqual([]);
		expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 990 });
		expect(await db.prepare('SELECT * FROM ops_ledger WHERE day = ?').bind(DAY).first()).toBeNull();
	});

	it('never contacts or records a Geomys or IPng log', async () => {
		const net = fakeNetwork();
		await run(net, fakeQueue());
		expect(net.calls.some((url) => url.includes('geomys'))).toBe(false);
		expect(await cursor(GEOMYS.log_id)).toBeNull();
	});

	it('adds its subrequests (as reads) and D1 rows to the day of the ops ledger', async () => {
		await seed(RFC.log_id, 'rfc6962', RFC.url, 980);
		const queue = fakeQueue();
		const first = await run(fakeNetwork(), queue);
		// Log list, two heads, three get-entries pages, one send.
		expect(first.subrequests).toBe(1 + 2 + 3 + 1);
		const second = await run(fakeNetwork(), fakeQueue());
		const ledger = await db.prepare('SELECT * FROM ops_ledger WHERE day = ?').bind(DAY).first<Record<string, number>>();
		expect(ledger).toMatchObject({ r2_class_a: 0, r2_class_b: first.subrequests + second.subrequests, killed: 0 });
		expect(ledger!.d1_rows).toBe(first.d1Rows + second.d1Rows);
		expect(first.d1Rows).toBeGreaterThan(0);
	});

	it('rotates which log is visited first from tick to tick', async () => {
		const firstHead = async (scheduledTime: number) => {
			resetLogListMemo();
			const net = fakeNetwork();
			await run(net, fakeQueue(), scheduledTime);
			return net.calls.find((url) => url !== LOG_LIST_URL);
		};
		expect(await firstHead(0)).toBe(`${RFC.url}ct/v1/get-sth`);
		expect(await firstHead(60_000)).toBe(`${STATIC.monitoring_url}checkpoint`);
	});

	it('does not move a cursor that another tick moved meanwhile', async () => {
		await seed(RFC.log_id, 'rfc6962', RFC.url, 990);
		const queue = fakeQueue(async () => {
			// An overlapping tick advanced the cursor while this one was sending.
			await db.prepare('UPDATE log_cursors SET next_index = 995 WHERE log_id = ?').bind(RFC.log_id).run();
		});
		await run(fakeNetwork(), queue);
		expect(await cursor(RFC.log_id)).toMatchObject({ next_index: 995 });
	});
});
