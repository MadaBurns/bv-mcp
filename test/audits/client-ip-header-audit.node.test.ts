// SPDX-License-Identifier: BUSL-1.1
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { assessClientIpHeaders, clientIpHeaderAuditSql } from '../../scripts/audits/client-ip-header-audit.mjs';
import {
	assessClientIpHeaders as assessSsot,
	clientIpHeaderAuditSql as sqlSsot,
	CLIENT_IP_AUDIT_MIN_SAMPLES,
	CLIENT_IP_HEADER_MISSING_ALERT_KIND,
} from '../../src/lib/client-ip-audit';
import { CLIENT_IP_ALERT_COOLDOWN_KEY, handleClientIpHeaderAudit } from '../../src/scheduled';

describe('public client-IP header audit', () => {
	it('detects missing-header regressions using aggregate counts', () => {
		expect(assessClientIpHeaders({ total: 100, missing: 25 })).toMatchObject({ status: 'degraded', exitCode: 1, missingRatio: 0.25 });
		expect(assessClientIpHeaders({ total: 100, missing: 5 })).toMatchObject({ status: 'healthy', exitCode: 0 });
	});
	it.each([undefined, {}, { total: 0, missing: 0 }, { total: 10, missing: 0 }, { total: 20, missing: 21 }, { total: 20, missing: -1 }])(
		'never calls absent, sparse, or invalid observations healthy',
		(row) => {
			expect(assessClientIpHeaders(row)).toMatchObject({ status: 'unknown', exitCode: 2 });
		},
	);
	it('queries only public aggregate observations in a bounded window', () => {
		const sql = clientIpHeaderAuditSql(24);
		expect(sql).toContain("COALESCE(source, 'public') = 'public'");
		expect(sql).toContain("'-24 hours'");
		expect(sql).not.toMatch(/SELECT\s+\*/i);
	});
	it('executes against epoch-second timestamps and excludes internal/old rows', () => {
		const db = new DatabaseSync(':memory:');
		try {
			db.exec('CREATE TABLE mcp_access_log (created_at INTEGER, source TEXT, ip_masked TEXT)');
			const insert = db.prepare('INSERT INTO mcp_access_log VALUES (?, ?, ?)');
			const now = Math.floor(Date.now() / 1000);
			insert.run(now, 'public', 'no-cf-header');
			insert.run(now, null, 'masked');
			insert.run(now, 'internal', 'no-cf-header');
			insert.run(now - 7200, 'public', 'no-cf-header');
			expect({ ...db.prepare(clientIpHeaderAuditSql(1)).get() }).toEqual({ total: 2, missing: 1 });
		} finally {
			db.close();
		}
	});
	it.each([0, 169, NaN, 1.5, "1'); DELETE FROM mcp_access_log;--"])('rejects an invalid window', (hours) => {
		expect(() => clientIpHeaderAuditSql(hours as number)).toThrow();
	});
});

// #896: the CLI script cannot import TypeScript under bare `node`, so it carries a
// copy of the two pure functions. This pins the copy to the SSOT
// (src/lib/client-ip-audit.ts) — a one-sided edit to either fails here.
describe('script ↔ src/lib/client-ip-audit.ts parity (SSOT pin)', () => {
	it('emits byte-identical SQL for every legal window', () => {
		for (const hours of [1, 2, 24, 168]) expect(clientIpHeaderAuditSql(hours)).toBe(sqlSsot(hours));
	});
	it('returns identical verdicts across the threshold boundaries', () => {
		const rows: unknown[] = [
			undefined,
			null,
			{},
			{ total: 0, missing: 0 },
			{ total: 19, missing: 0 },
			{ total: 19, missing: 19 },
			{ total: 20, missing: 0 },
			{ total: 20, missing: 1 },
			{ total: 20, missing: 2 },
			{ total: 20, missing: 21 },
			{ total: 20, missing: -1 },
			{ total: 20.5, missing: 1 },
			{ total: 54, missing: 51 },
			{ total: 404, missing: 321 },
		];
		for (const row of rows) expect(assessClientIpHeaders(row), JSON.stringify(row)).toEqual(assessSsot(row as never));
	});
});

// #896: prove the cron lane's SQL actually executes against a REAL D1 (Miniflare),
// not only a string-asserted fake — the same shape as the brand-audit cron D1 test.
describe('handleClientIpHeaderAudit against real D1', () => {
	let miniflare: Miniflare | undefined;
	let originalFetch: typeof globalThis.fetch;
	const ALERT_WEBHOOK = 'https://hooks.example.test/client-ip-896-d1';

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		await miniflare?.dispose();
		miniflare = undefined;
	});

	async function seeded(rows: Array<[number, string | null, string]>) {
		miniflare = new Miniflare(
			convertV4MiniflareOptions({
				modules: true,
				script: 'export default { fetch() { return new Response("ok") } }',
				d1Databases: { INTEL: `client-ip-audit-${crypto.randomUUID()}` },
				kvNamespaces: ['RATE_LIMIT'],
			}),
		);
		const db = (await miniflare.getD1Database('INTEL')) as unknown as D1Database;
		const kv = (await miniflare.getKVNamespace('RATE_LIMIT')) as unknown as KVNamespace;
		// Minimal projection of scripts/intelligence/sql/0001 + 0003 — only the columns the query reads.
		await db.exec(
			'CREATE TABLE mcp_access_log (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, ip_hash TEXT NOT NULL, ip_masked TEXT, tool_name TEXT NOT NULL, domain TEXT NOT NULL, source TEXT)',
		);
		const stmt = db.prepare(
			'INSERT INTO mcp_access_log (created_at, ip_hash, ip_masked, tool_name, domain, source) VALUES (?, ?, ?, ?, ?, ?)',
		);
		if (rows.length > 0) {
			await db.batch(
				rows.map(([createdAt, source, ipMasked]) => stmt.bind(createdAt, 'n_locality', ipMasked, 'check_spf', 'example.com', source)),
			);
		}
		const webhookCalls: string[] = [];
		originalFetch = globalThis.fetch;
		globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
			if (url.startsWith(ALERT_WEBHOOK)) {
				webhookCalls.push(typeof init?.body === 'string' ? init.body : '');
				return new Response('ok', { status: 200 });
			}
			return originalFetch(input as RequestInfo, init);
		}) as typeof fetch;
		return { db, kv, webhookCalls };
	}

	it('counts only public-door rows inside the window, pages once, then honours the cooldown', async () => {
		const now = Math.floor(Date.now() / 1000);
		const rows: Array<[number, string | null, string]> = [];
		// 30 public rows in-window: 27 missing the header, 3 masked → 0.9 ratio.
		for (let i = 0; i < 27; i++) rows.push([now - i, i % 2 ? 'public' : null, 'no-cf-header']);
		for (let i = 0; i < 3; i++) rows.push([now - i, 'public', '203.0.113.xxx']);
		// Noise that MUST be excluded: internal door, and public rows older than 1h.
		for (let i = 0; i < 40; i++) rows.push([now - i, 'internal', 'no-cf-header']);
		for (let i = 0; i < 40; i++) rows.push([now - 7200 - i, 'public', 'no-cf-header']);
		const { db, kv, webhookCalls } = await seeded(rows);

		const lane = { INTELLIGENCE_DB: db, RATE_LIMIT: kv, ALERT_WEBHOOK_URL: ALERT_WEBHOOK };
		await handleClientIpHeaderAudit(lane);
		expect(webhookCalls).toHaveLength(1);
		const text = (JSON.parse(webhookCalls[0]) as { text: string }).text;
		expect(text).toContain(CLIENT_IP_HEADER_MISSING_ALERT_KIND);
		expect(text).toContain('total_public_calls: 30');
		expect(text).toContain('missing_header: 27');
		expect(text).toContain('missing_ratio: 0.9');
		expect(text).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/);
		expect(await kv.get(CLIENT_IP_ALERT_COOLDOWN_KEY)).not.toBeNull();

		await handleClientIpHeaderAudit(lane);
		expect(webhookCalls).toHaveLength(1);
	});

	it('an empty table is `unknown`, not `healthy`, and never pages (positive control above proves the query works)', async () => {
		const { db, kv, webhookCalls } = await seeded([]);
		const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		let logged = '';
		try {
			await handleClientIpHeaderAudit({ INTELLIGENCE_DB: db, RATE_LIMIT: kv, ALERT_WEBHOOK_URL: ALERT_WEBHOOK });
			// Read BEFORE mockRestore — restore also resets the recorded calls.
			logged = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
		} finally {
			logSpy.mockRestore();
		}
		expect(webhookCalls).toHaveLength(0);
		expect(logged).toContain('"status":"unknown"');
		expect(logged).toContain(`"minSamples":${CLIENT_IP_AUDIT_MIN_SAMPLES}`);
		expect(await kv.get(CLIENT_IP_ALERT_COOLDOWN_KEY)).toBeNull();
	});
});
