// SPDX-License-Identifier: BUSL-1.1
//
// #896 — the public-door `cf-connecting-ip` audit must be self-reporting.
//
// Contract under test:
//   - `assessClientIpHeaders` (SSOT in src/lib/client-ip-audit.ts) never calls a
//     window with fewer than CLIENT_IP_AUDIT_MIN_SAMPLES rows `healthy` (fail-open
//     doctrine: "0 missing of 0" is `unknown`), and `degraded` is strictly ABOVE
//     the 5% ratio, so exactly 1-in-20 is still healthy.
//   - `handleClientIpHeaderAudit` runs ONE aggregate D1 query on the 15-min cron,
//     pages the operator webhook once per cooldown window on `degraded`, only
//     logs on `unknown`/`healthy`, never carries raw IPs / key hashes / session
//     IDs in the payload, and honours the existing "no webhook → no alerting"
//     gate.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { env } from 'cloudflare:test';
import {
	CLIENT_IP_AUDIT_MAX_MISSING_RATIO,
	CLIENT_IP_AUDIT_MIN_SAMPLES,
	CLIENT_IP_AUDIT_WINDOW_HOURS,
	CLIENT_IP_HEADER_MISSING_ALERT_KIND,
	assessClientIpHeaders,
	clientIpHeaderAuditSql,
	coerceClientIpAuditRow,
} from '../src/lib/client-ip-audit';
import { CLIENT_IP_ALERT_COOLDOWN_KEY, handleClientIpHeaderAudit, handleDailyDigest } from '../src/scheduled';
import { buildDigestPayload } from '../src/lib/alerting';

// handleDailyDigest runs the SPF canary first (20 real outbound DoH probes). Stub it:
// the digest tests below only care about the client-IP line riding along.
vi.mock('../src/lib/spf-canary', async () => {
	const actual = await vi.importActual<typeof import('../src/lib/spf-canary')>('../src/lib/spf-canary');
	return {
		...actual,
		runSpfCanary: async () => ({ totalProbed: 0, nullCount: 0, errorCount: 0, nullRate: 0, nullDomains: [], errorDomains: [] }),
	};
});

const ALERT_WEBHOOK = 'https://hooks.example.test/client-ip-896';

describe('assessClientIpHeaders — thresholds (SSOT)', () => {
	it('exposes the documented thresholds', () => {
		expect(CLIENT_IP_AUDIT_MIN_SAMPLES).toBe(20);
		expect(CLIENT_IP_AUDIT_MAX_MISSING_RATIO).toBe(0.05);
		expect(CLIENT_IP_HEADER_MISSING_ALERT_KIND).toBe('client_ip_header_missing');
		// 24h, not 1h: at the measured ~2.3 public rows/hour a 1h window never reaches
		// the 20-sample floor, so the lane would sit at `unknown` on every tick.
		expect(CLIENT_IP_AUDIT_WINDOW_HOURS).toBe(24);
	});

	it('is `unknown` (never healthy) below the sample floor, including 0 of 0', () => {
		expect(assessClientIpHeaders({ total: 0, missing: 0 })).toMatchObject({
			status: 'unknown',
			reason: 'insufficient_samples',
			exitCode: 2,
		});
		expect(assessClientIpHeaders({ total: 19, missing: 0 })).toMatchObject({ status: 'unknown', reason: 'insufficient_samples' });
		expect(assessClientIpHeaders({ total: 19, missing: 19 })).toMatchObject({ status: 'unknown', reason: 'insufficient_samples' });
	});

	it('is healthy at exactly the ratio boundary and degraded strictly above it', () => {
		// 1/20 = 0.05 is NOT > 0.05 → healthy.
		expect(assessClientIpHeaders({ total: 20, missing: 1 })).toMatchObject({ status: 'healthy', exitCode: 0, missingRatio: 0.05 });
		// 2/20 = 0.10 → degraded.
		expect(assessClientIpHeaders({ total: 20, missing: 2 })).toMatchObject({ status: 'degraded', exitCode: 1, missingRatio: 0.1 });
		expect(assessClientIpHeaders({ total: 20, missing: 0 })).toMatchObject({ status: 'healthy', missingRatio: 0 });
		// The live 2026-09-09 measurement.
		expect(assessClientIpHeaders({ total: 54, missing: 51 })).toMatchObject({ status: 'degraded' });
	});

	it.each([undefined, null, {}, { total: 20 }, { total: 20, missing: 21 }, { total: 20, missing: -1 }, { total: 20.5, missing: 1 }])(
		'is `unknown`/invalid_aggregate for a malformed row: %o',
		(row) => {
			expect(assessClientIpHeaders(row as never)).toMatchObject({ status: 'unknown', reason: 'invalid_aggregate', exitCode: 2 });
		},
	);

	it('coerces numeric-string D1 rows and refuses anything else', () => {
		expect(coerceClientIpAuditRow({ total: '54', missing: '51' })).toEqual({ total: 54, missing: 51 });
		expect(coerceClientIpAuditRow({ total: 54, missing: 51 })).toEqual({ total: 54, missing: 51 });
		expect(coerceClientIpAuditRow({ total: 'x', missing: 1 })).toEqual({ total: undefined, missing: 1 });
		expect(coerceClientIpAuditRow(null)).toBeUndefined();
		expect(assessClientIpHeaders(coerceClientIpAuditRow({ total: 'x', missing: 1 }))).toMatchObject({ status: 'unknown' });
	});

	it('builds a bounded, public-only aggregate query and rejects invalid windows', () => {
		const sql = clientIpHeaderAuditSql();
		expect(sql).toBe(clientIpHeaderAuditSql(CLIENT_IP_AUDIT_WINDOW_HOURS));
		expect(sql).toContain("COALESCE(source, 'public') = 'public'");
		expect(sql).toContain("ip_masked = 'no-cf-header'");
		expect(sql).toContain("'-24 hours'");
		expect(sql).not.toMatch(/SELECT\s+\*/i);
		for (const bad of [0, 169, NaN, 1.5, "1'); DELETE FROM mcp_access_log;--"]) {
			expect(() => clientIpHeaderAuditSql(bad as number)).toThrow();
		}
	});
});

/** D1 fake: `.prepare(sql).first()` returns `row` (or throws when `row` is an Error). */
function fakeIntelDb(row: unknown) {
	const first = vi.fn(async () => {
		if (row instanceof Error) throw row;
		return row;
	});
	const stmt = { bind: vi.fn(() => stmt), first, all: vi.fn(), run: vi.fn() };
	const prepare = vi.fn(() => stmt);
	return { db: { prepare } as unknown as D1Database, prepare, first };
}

let originalFetch: typeof globalThis.fetch;
let webhookCalls: { url: string; body: string }[] = [];
/** HTTP status the stubbed webhook answers with (tests flip it to simulate an outage). */
let webhookStatus = 200;

beforeEach(async () => {
	await env.RATE_LIMIT.delete(CLIENT_IP_ALERT_COOLDOWN_KEY);
	webhookCalls = [];
	webhookStatus = 200;
	originalFetch = globalThis.fetch;
	globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
		if (url.startsWith(ALERT_WEBHOOK)) {
			webhookCalls.push({ url, body: typeof init?.body === 'string' ? init.body : '' });
			return new Response(webhookStatus === 200 ? 'ok' : 'nope', { status: webhookStatus });
		}
		if (url.includes('/analytics_engine/sql')) {
			// Daily-digest AE query stub: no tier rows, so the digest takes the empty branch.
			return new Response(JSON.stringify({ data: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
		}
		return originalFetch(input as RequestInfo, init);
	}) as typeof fetch;
});

afterEach(async () => {
	globalThis.fetch = originalFetch;
	await env.RATE_LIMIT.delete(CLIENT_IP_ALERT_COOLDOWN_KEY);
	vi.restoreAllMocks();
});

describe('handleClientIpHeaderAudit — 15-min cron lane', () => {
	it('degraded window → exactly one alert carrying the kind, counts and ratio (aggregates only)', async () => {
		const intel = fakeIntelDb({ total: 54, missing: 51 });
		await handleClientIpHeaderAudit({ INTELLIGENCE_DB: intel.db, RATE_LIMIT: env.RATE_LIMIT, ALERT_WEBHOOK_URL: ALERT_WEBHOOK });

		// ONE aggregate query, executed via the SSOT SQL — not a hand-rolled copy.
		expect(intel.prepare).toHaveBeenCalledTimes(1);
		expect(intel.prepare).toHaveBeenCalledWith(clientIpHeaderAuditSql(CLIENT_IP_AUDIT_WINDOW_HOURS));
		expect(intel.first).toHaveBeenCalledTimes(1);

		expect(webhookCalls).toHaveLength(1);
		const body = JSON.parse(webhookCalls[0].body) as { text: string };
		expect(body.text).toContain('[Blackveil DNS] Critical');
		expect(body.text).toContain(CLIENT_IP_HEADER_MISSING_ALERT_KIND);
		expect(body.text).toContain('total_public_calls: 54');
		expect(body.text).toContain('missing_header: 51');
		expect(body.text).toContain('missing_ratio: 0.944');
		expect(body.text).toContain('#896');
		// Aggregates only — nothing that looks like an IP, a 16-hex key hash, or a 64-hex session id.
		expect(body.text).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/);
		expect(body.text).not.toMatch(/\b[a-f0-9]{16,}\b/);
	});

	it('degraded but below half the traffic → warning, not critical', async () => {
		const intel = fakeIntelDb({ total: 100, missing: 10 });
		await handleClientIpHeaderAudit({ INTELLIGENCE_DB: intel.db, RATE_LIMIT: env.RATE_LIMIT, ALERT_WEBHOOK_URL: ALERT_WEBHOOK });
		expect(webhookCalls).toHaveLength(1);
		expect(JSON.parse(webhookCalls[0].body).text).toContain('[Blackveil DNS] Warning');
	});

	it('second tick inside the cooldown is suppressed; the marker is only written after a dispatch', async () => {
		const intel = fakeIntelDb({ total: 54, missing: 51 });
		const lane = { INTELLIGENCE_DB: intel.db, RATE_LIMIT: env.RATE_LIMIT, ALERT_WEBHOOK_URL: ALERT_WEBHOOK };

		await handleClientIpHeaderAudit(lane);
		expect(webhookCalls).toHaveLength(1);
		expect(await env.RATE_LIMIT.get(CLIENT_IP_ALERT_COOLDOWN_KEY)).not.toBeNull();

		webhookCalls.length = 0;
		await handleClientIpHeaderAudit(lane);
		expect(webhookCalls).toHaveLength(0);
		// The query still runs every tick (cheap, and the log line stays greppable).
		expect(intel.first).toHaveBeenCalledTimes(2);
	});

	it('rejected webhook (non-2xx) → no cooldown marker, so the next tick retries and lands once the webhook recovers', async () => {
		const intel = fakeIntelDb({ total: 54, missing: 51 });
		const lane = { INTELLIGENCE_DB: intel.db, RATE_LIMIT: env.RATE_LIMIT, ALERT_WEBHOOK_URL: ALERT_WEBHOOK };

		webhookStatus = 500;
		await handleClientIpHeaderAudit(lane);
		expect(webhookCalls).toHaveLength(1);
		expect(await env.RATE_LIMIT.get(CLIENT_IP_ALERT_COOLDOWN_KEY)).toBeNull();

		webhookStatus = 200;
		await handleClientIpHeaderAudit(lane);
		expect(webhookCalls).toHaveLength(2);
		expect(await env.RATE_LIMIT.get(CLIENT_IP_ALERT_COOLDOWN_KEY)).not.toBeNull();
	});

	it('healthy window → no alert and no cooldown marker', async () => {
		const intel = fakeIntelDb({ total: 100, missing: 3 });
		await handleClientIpHeaderAudit({ INTELLIGENCE_DB: intel.db, RATE_LIMIT: env.RATE_LIMIT, ALERT_WEBHOOK_URL: ALERT_WEBHOOK });
		expect(intel.first).toHaveBeenCalledTimes(1);
		expect(webhookCalls).toHaveLength(0);
		expect(await env.RATE_LIMIT.get(CLIENT_IP_ALERT_COOLDOWN_KEY)).toBeNull();
	});

	it('insufficient evidence (0 of 0, or < 20 rows) → logged as `unknown`, never alerted', async () => {
		const spy = vi.spyOn(console, 'log').mockImplementation(() => {});

		for (const row of [
			{ total: 0, missing: 0 },
			{ total: 19, missing: 19 },
		]) {
			spy.mockClear();
			const intel = fakeIntelDb(row);
			await handleClientIpHeaderAudit({ INTELLIGENCE_DB: intel.db, RATE_LIMIT: env.RATE_LIMIT, ALERT_WEBHOOK_URL: ALERT_WEBHOOK });
			expect(webhookCalls).toHaveLength(0);
			const logged = spy.mock.calls.map((c) => String(c[0])).join('\n');
			expect(logged).toContain('client_ip_header_audit');
			expect(logged).toContain('"status":"unknown"');
			expect(logged).toContain('insufficient_samples');
			expect(logged).not.toContain('"status":"healthy"');
		}
	});

	it('a malformed / unmigrated aggregate row is `unknown`, not `healthy`', async () => {
		const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
		const intel = fakeIntelDb({ total: 500 }); // `missing` column absent
		await handleClientIpHeaderAudit({ INTELLIGENCE_DB: intel.db, RATE_LIMIT: env.RATE_LIMIT, ALERT_WEBHOOK_URL: ALERT_WEBHOOK });
		expect(webhookCalls).toHaveLength(0);
		const logged = spy.mock.calls.map((c) => String(c[0])).join('\n');
		expect(logged).toContain('invalid_aggregate');
	});

	it('D1 failure is logged and fail-soft — no throw, no alert', async () => {
		// logError routes through logEvent → console.log (src/lib/log.ts), not console.error.
		const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
		const intel = fakeIntelDb(new Error('D1_ERROR: no such table: mcp_access_log'));
		await expect(
			handleClientIpHeaderAudit({ INTELLIGENCE_DB: intel.db, RATE_LIMIT: env.RATE_LIMIT, ALERT_WEBHOOK_URL: ALERT_WEBHOOK }),
		).resolves.toBeUndefined();
		expect(webhookCalls).toHaveLength(0);
		expect(spy.mock.calls.map((c) => String(c[0])).join('\n')).toContain('client_ip_header_audit_failed');
	});

	it('no INTELLIGENCE_DB → no-op (BSL self-hosts without the access log)', async () => {
		await handleClientIpHeaderAudit({ RATE_LIMIT: env.RATE_LIMIT, ALERT_WEBHOOK_URL: ALERT_WEBHOOK });
		expect(webhookCalls).toHaveLength(0);
	});

	it('no webhook → existing "alerts disabled" gate: the query is never issued', async () => {
		const intel = fakeIntelDb({ total: 54, missing: 51 });
		await handleClientIpHeaderAudit({ INTELLIGENCE_DB: intel.db, RATE_LIMIT: env.RATE_LIMIT });
		expect(intel.prepare).not.toHaveBeenCalled();
		expect(webhookCalls).toHaveLength(0);
	});

	it('RATE_LIMIT KV absent → still alerts (fail-loud, no cooldown available)', async () => {
		const intel = fakeIntelDb({ total: 54, missing: 51 });
		await handleClientIpHeaderAudit({ INTELLIGENCE_DB: intel.db, ALERT_WEBHOOK_URL: ALERT_WEBHOOK });
		expect(webhookCalls).toHaveLength(1);
	});
});

describe('daily digest positive control (#896)', () => {
	const digestEnv = (db?: D1Database) => ({
		INTELLIGENCE_DB: db,
		RATE_LIMIT: env.RATE_LIMIT,
		ALERT_WEBHOOK_URL: ALERT_WEBHOOK,
		CF_ACCOUNT_ID: 'acct',
		CF_ANALYTICS_TOKEN: 'token',
	});

	/** The digest text minus its other sections — only the Checks line matters here. */
	const digestChecksLine = () => {
		const digest = webhookCalls.map((c) => JSON.parse(c.body) as { text: string }).find((b) => b.text.includes('Daily Tier Digest'));
		expect(digest, 'digest was sent').toBeDefined();
		return digest!.text.split('\n').find((line) => line.includes('client_ip_audit:')) ?? '';
	};

	it('buildDigestPayload renders extra lines in BOTH the empty and the populated branch', () => {
		expect(buildDigestPayload([], 1, ['client_ip_audit: unknown (0/0, last 24h)']).text).toContain(
			'Checks:\n  client_ip_audit: unknown (0/0, last 24h)',
		);
		expect(buildDigestPayload([{ tier: 'free', total_calls: 3 }], 1, ['client_ip_audit: healthy (1/40, last 24h)']).text).toContain(
			'Checks:\n  client_ip_audit: healthy (1/40, last 24h)',
		);
		expect(buildDigestPayload([], 1).text).not.toContain('Checks:');
	});

	it('carries the lane verdict with counts (degraded / unknown) using the same 24h SSOT query', async () => {
		const degraded = fakeIntelDb({ total: 54, missing: 51 });
		await handleDailyDigest(digestEnv(degraded.db));
		expect(degraded.prepare).toHaveBeenCalledWith(clientIpHeaderAuditSql(CLIENT_IP_AUDIT_WINDOW_HOURS));
		expect(digestChecksLine()).toBe('  client_ip_audit: degraded (51/54, last 24h)');

		webhookCalls.length = 0;
		await handleDailyDigest(digestEnv(fakeIntelDb({ total: 0, missing: 0 }).db));
		expect(digestChecksLine()).toBe('  client_ip_audit: unknown (0/0, last 24h)');
	});

	it('an erroring or unbound lane is a visible word in the digest, never a missing line', async () => {
		await handleDailyDigest(digestEnv(fakeIntelDb(new Error('D1_ERROR: no such column: source')).db));
		expect(digestChecksLine()).toContain('client_ip_audit: error');

		webhookCalls.length = 0;
		await handleDailyDigest(digestEnv(undefined));
		expect(digestChecksLine()).toContain('client_ip_audit: unbound');
	});
});
