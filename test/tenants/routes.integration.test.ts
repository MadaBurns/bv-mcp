// SPDX-License-Identifier: BUSL-1.1

/**
 * Integration tests for the three Tenant orchestrator endpoints:
 *
 *   - POST /internal/tenants/portfolio
 *   - POST /internal/tenants/scan
 *   - GET  /internal/tenants/report/:cycle_id
 *
 * One observable behaviour per test (TDD discipline).
 *
 * Scope: routing, header validation, Zod payload validation, body-size limit,
 * tenant resolution (registry D1 lookup), and per-tenant D1 binding selection.
 * The actual scan execution path delegates to handleToolsCall which is
 * already covered by the rest of the suite — these tests stub the per-tenant
 * D1 with a recording fake so we assert "wrote N rows", not the row contents.
 */

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import worker from '../../src';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';
import { MAX_INTERNAL_BATCH_BODY_BYTES, MAX_TENANT_PORTFOLIO_BODY_BYTES } from '../../src/lib/config';

const TEST_INTERNAL_KEY = 'tenant-orchestrator-internal-key';
const TEST_TENANT_ID = 'tenant-1';
/** Derived binding name: hyphens to underscores, uppercased, prefixed TENANT_DB_. */
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';

type TestEnv = typeof env & {
	BV_WEB_INTERNAL_KEY?: string;
	REQUIRE_INTERNAL_AUTH?: string;
	TENANT_REGISTRY_DB?: D1Database;
	[k: string]: unknown;
};

type RecordedCall = { sql: string; binds: unknown[] };

function makeMockD1(rowsBySql: Record<string, unknown[]> = {}) {
	const calls: RecordedCall[] = [];
	const db: D1Database = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					calls.push({ sql, binds });
					const rows = rowsBySql[sql] ?? [];
					return (rows[0] as T | undefined) ?? null;
				},
				async all<T = unknown>() {
					calls.push({ sql, binds });
					const rows = rowsBySql[sql] ?? [];
					return { results: rows as T[], success: true, meta: {} } as unknown as D1Result<T>;
				},
				async run() {
					calls.push({ sql, binds });
					return {
						success: true,
						meta: { changes: 1, last_row_id: 0, duration: 0, rows_read: 0, rows_written: 1, size_after: 0 },
					} as unknown as D1Response;
				},
				async raw() {
					calls.push({ sql, binds });
					return [] as unknown[];
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
		async batch<T = unknown>(stmts: D1PreparedStatement[]): Promise<D1Result<T>[]> {
			const out: D1Result<T>[] = [];
			for (const s of stmts) {
				const r = (await (s as unknown as { run: () => Promise<unknown> }).run()) as D1Result<T>;
				out.push(r);
			}
			return out;
		},
		async exec() {
			return { count: 0, duration: 0 } as unknown as D1ExecResult;
		},
		dump() {
			throw new Error('not implemented');
		},
		withSession() {
			throw new Error('not implemented');
		},
	} as unknown as D1Database;
	return { db, calls };
}

const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';

function buildEnvWithTenant() {
	const registry = makeMockD1({
		[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
	});
	const tenant = makeMockD1();
	const customEnv = {
		...env,
		BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
		REQUIRE_INTERNAL_AUTH: 'true',
		TENANT_REGISTRY_DB: registry.db,
		[TEST_TENANT_BINDING]: tenant.db,
	} as TestEnv;
	return { customEnv, tenantCalls: tenant.calls, registryCalls: registry.calls };
}

async function sendRequest(req: Request, customEnv: TestEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

beforeEach(() => {
	resetTenantResolverCache();
});
afterEach(() => {
	resetTenantResolverCache();
});

describe('POST /internal/tenants/portfolio', () => {
	function makeReq(body: unknown, headers: Record<string, string> = {}): Request {
		return new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/portfolio', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
				...headers,
			},
			body: JSON.stringify(body),
		});
	}

	it('returns 200 with insertion summary on the happy path', async () => {
		const { customEnv } = buildEnvWithTenant();
		const res = await sendRequest(makeReq({ domains: ['example.com', 'foo.com'] }), customEnv);
		expect(res.status).toBe(200);
		const json = (await res.json()) as { inserted: number; updated: number; skipped: number; total: number };
		expect(json.total).toBe(2);
		expect(json.inserted + json.updated + json.skipped).toBe(2);
	});

	it('writes an audit_events row via ctx.waitUntil after a successful portfolio upsert', async () => {
		const { customEnv, registryCalls } = buildEnvWithTenant();
		const before = registryCalls.length;
		await sendRequest(makeReq({ domains: ['example.com'] }), customEnv);
		const auditCalls = registryCalls.slice(before).filter((c) => /insert\s+into\s+["`]?audit_events["`]?/i.test(c.sql));
		expect(auditCalls.length).toBe(1);
		// binds order matches recordAuditEvent's row builder. We don't pin a specific
		// index — just assert the action token is somewhere in the binds.
		expect(auditCalls[0].binds.some((b) => b === 'portfolio.upsert')).toBe(true);
		expect(auditCalls[0].binds.some((b) => b === TEST_TENANT_ID)).toBe(true);
		expect(auditCalls[0].binds.some((b) => b === 'success')).toBe(true);
	});

	it('returns 401 when REQUIRE_INTERNAL_AUTH=true and bearer is missing', async () => {
		const { customEnv } = buildEnvWithTenant();
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/portfolio', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'X-Tenant': TEST_TENANT_ID },
			body: JSON.stringify({ domains: ['example.com'] }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(401);
	});

	it('returns 400 when X-Tenant header is missing', async () => {
		const { customEnv } = buildEnvWithTenant();
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/portfolio', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TEST_INTERNAL_KEY}` },
			body: JSON.stringify({ domains: ['example.com'] }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(400);
	});

	it('returns 400 when X-Tenant header is malformed (cross-tenant leak guard)', async () => {
		const { customEnv } = buildEnvWithTenant();
		const res = await sendRequest(makeReq({ domains: ['example.com'] }, { 'X-Tenant': 'BAD;DROP' }), customEnv);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/Invalid tenant identifier/);
	});

	it('returns 400 when the body fails Zod validation (missing domains)', async () => {
		const { customEnv } = buildEnvWithTenant();
		const res = await sendRequest(makeReq({}), customEnv);
		expect(res.status).toBe(400);
	});

	it('returns 404 for an unknown sub-tenant', async () => {
		const registry = makeMockD1({ [REGISTRY_LOOKUP_SQL]: [] });
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
		} as TestEnv;
		const res = await sendRequest(makeReq({ domains: ['example.com'] }), customEnv);
		expect(res.status).toBe(404);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/Tenant not found/);
	});

	it('returns 413 when the body exceeds MAX_TENANT_PORTFOLIO_BODY_BYTES', async () => {
		const { customEnv } = buildEnvWithTenant();
		const big = 'x'.repeat(MAX_TENANT_PORTFOLIO_BODY_BYTES + 100);
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/portfolio', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
			},
			body: JSON.stringify({ domains: ['example.com'], _pad: big }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(413);
	});

	it('rejects invalid domain entries with 400', async () => {
		const { customEnv } = buildEnvWithTenant();
		const res = await sendRequest(makeReq({ domains: ['not a domain!'] }), customEnv);
		expect(res.status).toBe(400);
	});
});

describe('POST /internal/tenants/scan', () => {
	function makeReq(body: unknown, headers: Record<string, string> = {}): Request {
		return new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/scan', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
				...headers,
			},
			body: JSON.stringify(body),
		});
	}

	it('returns 200 with a cycle summary when given an explicit domains list', async () => {
		const { mockTxtRecords } = await import('../helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const { customEnv } = buildEnvWithTenant();
		const res = await sendRequest(makeReq({ domains: ['example.com'] }), customEnv);
		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			cycle_id: string;
			total: number;
			completed: number;
			errored: number;
			started_at: number;
			finished_at: number;
		};
		expect(typeof body.cycle_id).toBe('string');
		expect(body.cycle_id.length).toBeGreaterThan(0);
		expect(body.total).toBe(1);
		expect(body.completed + body.errored).toBe(1);
		expect(body.finished_at).toBeGreaterThanOrEqual(body.started_at);
	});

	it('writes an audit_events row for scan.start with the cycle_id as resourceId', async () => {
		const { mockTxtRecords } = await import('../helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const { customEnv, registryCalls } = buildEnvWithTenant();
		const before = registryCalls.length;
		const res = await sendRequest(makeReq({ cycle_id: 'cycle_audit_test', domains: ['example.com'] }), customEnv);
		expect(res.status).toBe(200);
		const auditCalls = registryCalls.slice(before).filter((c) => /insert\s+into\s+["`]?audit_events["`]?/i.test(c.sql));
		expect(auditCalls.length).toBe(1);
		expect(auditCalls[0].binds.some((b) => b === 'scan.start')).toBe(true);
		expect(auditCalls[0].binds.some((b) => b === 'cycle_audit_test')).toBe(true);
		expect(auditCalls[0].binds.some((b) => b === 'success')).toBe(true);
	});

	it('echoes a caller-provided cycle_id rather than minting a new UUID', async () => {
		const { mockTxtRecords } = await import('../helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const { customEnv } = buildEnvWithTenant();
		const res = await sendRequest(makeReq({ cycle_id: 'cycle_2026_05_09', domains: ['example.com'] }), customEnv);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { cycle_id: string };
		expect(body.cycle_id).toBe('cycle_2026_05_09');
	});

	it('returns 401 when bearer is missing under REQUIRE_INTERNAL_AUTH=true', async () => {
		const { customEnv } = buildEnvWithTenant();
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/scan', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'X-Tenant': TEST_TENANT_ID },
			body: JSON.stringify({ domains: ['example.com'] }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(401);
	});

	it('returns 400 when X-Tenant header is missing', async () => {
		const { customEnv } = buildEnvWithTenant();
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/scan', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TEST_INTERNAL_KEY}` },
			body: JSON.stringify({ domains: ['example.com'] }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(400);
	});

	it('returns 400 when concurrency is out of range (Zod validation)', async () => {
		const { customEnv } = buildEnvWithTenant();
		const res = await sendRequest(makeReq({ domains: ['example.com'], concurrency: 999 }), customEnv);
		expect(res.status).toBe(400);
	});

	it('returns 404 for an unknown sub-tenant', async () => {
		const registry = makeMockD1({ [REGISTRY_LOOKUP_SQL]: [] });
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
		} as TestEnv;
		const res = await sendRequest(makeReq({ domains: ['example.com'] }), customEnv);
		expect(res.status).toBe(404);
	});

	it('returns 413 when the body exceeds MAX_INTERNAL_BATCH_BODY_BYTES', async () => {
		const { customEnv } = buildEnvWithTenant();
		const big = 'x'.repeat(MAX_INTERNAL_BATCH_BODY_BYTES + 100);
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/scan', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
			},
			body: JSON.stringify({ domains: ['example.com'], _pad: big }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(413);
	});

	it('scans only enrolled domain_ids — unenrolled IDs are silently dropped', async () => {
		const { mockTxtRecords } = await import('../helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const tenant = makeMockD1({
			'SELECT domain FROM domains WHERE domain IN (?,?)': [{ domain: 'example.com' }],
		});
		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
		});
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		} as TestEnv;
		const res = await sendRequest(makeReq({ domain_ids: ['example.com', 'attacker-domain.com'] }), customEnv);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { total: number };
		expect(body.total).toBe(1);
	});

	it('returns 400 when no domain_ids are enrolled (prevents quota burn on arbitrary strings)', async () => {
		const tenant = makeMockD1({
			'SELECT domain FROM domains WHERE domain IN (?)': [],
		});
		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
		});
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		} as TestEnv;
		const res = await sendRequest(makeReq({ domain_ids: ['attacker-domain.com'] }), customEnv);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body.error).toMatch(/Invalid domain_ids/);
	});
});

describe('GET /internal/tenants/report/:cycle_id', () => {
	function makeReq(cycleId: string, headers: Record<string, string> = {}): Request {
		return new Request<unknown, IncomingRequestCfProperties>(
			`http://example.com/internal/tenants/report/${encodeURIComponent(cycleId)}`,
			{
				method: 'GET',
				headers: {
					Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
					'X-Tenant': TEST_TENANT_ID,
					...headers,
				},
			},
		);
	}

	it('returns 200 with summary + findings_by_category for a known cycle', async () => {
		const cycleId = 'cycle_test_001';
		const tenant = makeMockD1({
			'SELECT score, grade FROM scans WHERE cycle_id = ?': [
				{ score: 85, grade: 'B+' },
				{ score: 92, grade: 'A' },
			],
			'SELECT category, severity, COUNT(*) as count FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE cycle_id = ?) GROUP BY category, severity':
				[
					{ category: 'spf', severity: 'high', count: 1 },
					{ category: 'dmarc', severity: 'medium', count: 2 },
				],
		});
		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
		});
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		} as TestEnv;
		const res = await sendRequest(makeReq(cycleId), customEnv);
		expect(res.status).toBe(200);
		const body = (await res.json()) as {
			cycle_id: string;
			summary: {
				domains: number;
				mean_score: number;
				grade_dist: Record<string, number>;
				severity_counts: Record<string, number>;
			};
			findings_by_category: Array<{ category: string; severity: string; count: number }>;
		};
		expect(body.cycle_id).toBe(cycleId);
		expect(body.summary.domains).toBe(2);
		expect(body.summary.mean_score).toBeCloseTo((85 + 92) / 2, 5);
		expect(body.summary.grade_dist['B+']).toBe(1);
		expect(body.summary.grade_dist['A']).toBe(1);
		expect(body.summary.severity_counts.high).toBe(1);
		expect(body.summary.severity_counts.medium).toBe(2);
		expect(body.findings_by_category.length).toBe(2);
	});

	it('writes an audit_events row for report.read with the cycle_id as resourceId', async () => {
		const cycleId = 'cycle_audit_report';
		const tenant = makeMockD1({
			'SELECT score, grade FROM scans WHERE cycle_id = ?': [{ score: 85, grade: 'B+' }],
			'SELECT category, severity, COUNT(*) as count FROM findings WHERE scan_id IN (SELECT id FROM scans WHERE cycle_id = ?) GROUP BY category, severity':
				[],
		});
		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
		});
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		} as TestEnv;
		const before = registry.calls.length;
		const res = await sendRequest(makeReq(cycleId), customEnv);
		expect(res.status).toBe(200);
		const auditCalls = registry.calls.slice(before).filter((c) => /insert\s+into\s+["`]?audit_events["`]?/i.test(c.sql));
		expect(auditCalls.length).toBe(1);
		expect(auditCalls[0].binds.some((b) => b === 'report.read')).toBe(true);
		expect(auditCalls[0].binds.some((b) => b === cycleId)).toBe(true);
		expect(auditCalls[0].binds.some((b) => b === 'success')).toBe(true);
	});

	it('returns 401 when bearer is missing', async () => {
		const { customEnv } = buildEnvWithTenant();
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/report/cycle_x', {
			method: 'GET',
			headers: { 'X-Tenant': TEST_TENANT_ID },
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(401);
	});

	it('returns 400 when X-Tenant header is missing', async () => {
		const { customEnv } = buildEnvWithTenant();
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/report/cycle_x', {
			method: 'GET',
			headers: { Authorization: `Bearer ${TEST_INTERNAL_KEY}` },
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(400);
	});

	it('returns 400 for a malformed cycle_id (Zod param validation)', async () => {
		const { customEnv } = buildEnvWithTenant();
		const res = await sendRequest(makeReq('bad cycle id with spaces'), customEnv);
		expect(res.status).toBe(400);
	});

	it('returns 404 for an unknown sub-tenant', async () => {
		const registry = makeMockD1({ [REGISTRY_LOOKUP_SQL]: [] });
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
		} as TestEnv;
		const res = await sendRequest(makeReq('cycle_x'), customEnv);
		expect(res.status).toBe(404);
	});
});

// ─── Phase 6: audit-on-denial coverage ────────────────────────────────────
//
// Wave B (already on main) only audited success paths. Phase 6 extends audit
// coverage to every 4xx return: invalid headers, Zod failures, oversized
// bodies, unknown tenants. Each test asserts a single row was queued for the
// `audit_events` table with the expected outcome + reason.

const AUDIT_INSERT_RE = /insert\s+into\s+["`]?audit_events["`]?/i;

function auditRowsBetween(calls: { sql: string; binds: unknown[] }[], before: number) {
	return calls.slice(before).filter((c) => AUDIT_INSERT_RE.test(c.sql));
}

describe('Phase 6: audit on denied paths', () => {
	it('writes outcome=denied audit row when X-Tenant header is missing on /portfolio', async () => {
		const { customEnv, registryCalls } = buildEnvWithTenant();
		const before = registryCalls.length;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/portfolio', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TEST_INTERNAL_KEY}` },
			body: JSON.stringify({ domains: ['example.com'] }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(400);
		const audits = auditRowsBetween(registryCalls, before);
		expect(audits.length).toBe(1);
		expect(audits[0].binds.some((b) => b === 'portfolio.upsert')).toBe(true);
		expect(audits[0].binds.some((b) => b === 'denied')).toBe(true);
	});

	it('writes outcome=denied audit row when /portfolio body fails Zod validation', async () => {
		const { customEnv, registryCalls } = buildEnvWithTenant();
		const before = registryCalls.length;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/portfolio', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
			},
			body: JSON.stringify({}), // missing domains
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(400);
		const audits = auditRowsBetween(registryCalls, before);
		expect(audits.length).toBe(1);
		expect(audits[0].binds.some((b) => b === 'denied')).toBe(true);
		expect(audits[0].binds.some((b) => b === 'portfolio.upsert')).toBe(true);
	});

	it('writes outcome=denied audit row for an unknown sub-tenant on /portfolio (404 path)', async () => {
		const registry = makeMockD1({ [REGISTRY_LOOKUP_SQL]: [] });
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
		} as TestEnv;
		const before = registry.calls.length;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/portfolio', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
			},
			body: JSON.stringify({ domains: ['example.com'] }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(404);
		const audits = auditRowsBetween(registry.calls, before);
		expect(audits.length).toBe(1);
		expect(audits[0].binds.some((b) => b === 'denied')).toBe(true);
	});

	it('writes outcome=denied audit row when /scan body exceeds the 256KB cap', async () => {
		const { customEnv, registryCalls } = buildEnvWithTenant();
		const before = registryCalls.length;
		const big = 'x'.repeat(MAX_INTERNAL_BATCH_BODY_BYTES + 100);
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/scan', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
			},
			body: JSON.stringify({ domains: ['example.com'], _pad: big }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(413);
		const audits = auditRowsBetween(registryCalls, before);
		expect(audits.length).toBe(1);
		expect(audits[0].binds.some((b) => b === 'scan.start')).toBe(true);
		expect(audits[0].binds.some((b) => b === 'denied')).toBe(true);
	});

	it('writes outcome=denied audit row when /scan domain_ids are unenrolled (quota-burn guard)', async () => {
		const tenant = makeMockD1({
			'SELECT domain FROM domains WHERE domain IN (?)': [],
		});
		const registry = makeMockD1({
			[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
		});
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
			REQUIRE_INTERNAL_AUTH: 'true',
			TENANT_REGISTRY_DB: registry.db,
			[TEST_TENANT_BINDING]: tenant.db,
		} as TestEnv;
		const before = registry.calls.length;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/scan', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
			},
			body: JSON.stringify({ domain_ids: ['attacker-domain.com'] }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(400);
		const audits = auditRowsBetween(registry.calls, before);
		expect(audits.length).toBe(1);
		expect(audits[0].binds.some((b) => b === 'scan.start')).toBe(true);
		expect(audits[0].binds.some((b) => b === 'denied')).toBe(true);
	});

	it('writes outcome=denied audit row for malformed cycle_id on /report (Zod fail)', async () => {
		const { customEnv, registryCalls } = buildEnvWithTenant();
		const before = registryCalls.length;
		const req = new Request<unknown, IncomingRequestCfProperties>(
			`http://example.com/internal/tenants/report/${encodeURIComponent('bad cycle id with spaces')}`,
			{
				method: 'GET',
				headers: { Authorization: `Bearer ${TEST_INTERNAL_KEY}`, 'X-Tenant': TEST_TENANT_ID },
			},
		);
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(400);
		const audits = auditRowsBetween(registryCalls, before);
		expect(audits.length).toBe(1);
		expect(audits[0].binds.some((b) => b === 'report.read')).toBe(true);
		expect(audits[0].binds.some((b) => b === 'denied')).toBe(true);
	});
});

// ─── Phase 6: per-tenant rate limiter integration ─────────────────────────
//
// Wires checkAndRecord against an in-memory KV stub bound to RATE_LIMIT.
// One test confirms the limiter is transparent under default load; the
// other two test the rejection path: 429 status + Retry-After header +
// matching denied audit row.

function makeKvStub(): KVNamespace & { _store: Map<string, string> } {
	const store = new Map<string, string>();
	const kv = {
		_store: store,
		async get(key: string): Promise<string | null> {
			return store.get(key) ?? null;
		},
		async put(key: string, value: string): Promise<void> {
			store.set(key, value);
		},
		async delete(key: string): Promise<void> {
			store.delete(key);
		},
		async list(): Promise<KVNamespaceListResult<unknown, string>> {
			return { keys: [], list_complete: true, cacheStatus: null } as unknown as KVNamespaceListResult<unknown, string>;
		},
		async getWithMetadata(): Promise<unknown> {
			return { value: null, metadata: null };
		},
	};
	return kv as unknown as KVNamespace & { _store: Map<string, string> };
}

function buildEnvWithTenantAndKv(kv: KVNamespace) {
	const built = buildEnvWithTenant();
	built.customEnv.RATE_LIMIT = kv;
	return built;
}

describe('Phase 6: per-tenant rate limiter on /internal/tenants/*', () => {
	it('200 normal request passes through with rate limiter bound', async () => {
		const kv = makeKvStub();
		const { customEnv } = buildEnvWithTenantAndKv(kv);
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/portfolio', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
			},
			body: JSON.stringify({ domains: ['example.com'] }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(200);
	});

	it('returns 429 with Retry-After header after the bucket is pre-filled to quota', async () => {
		const kv = makeKvStub();
		// Pre-fill the portfolio:min bucket for this tenant to the default cap (30).
		const { PER_TENANT_QUOTAS } = await import('../../src/tenants/per-tenant-rate-limit');
		const now = new Date();
		const y = now.getUTCFullYear();
		const m = String(now.getUTCMonth() + 1).padStart(2, '0');
		const d = String(now.getUTCDate()).padStart(2, '0');
		const h = String(now.getUTCHours()).padStart(2, '0');
		const min = String(now.getUTCMinutes()).padStart(2, '0');
		const window = `${y}-${m}-${d}T${h}:${min}`;
		const key = `tenant-rl:${TEST_TENANT_ID}:portfolio:min:${window}`;
		kv._store.set(key, String(PER_TENANT_QUOTAS.default.portfolioPerMin));
		const { customEnv } = buildEnvWithTenantAndKv(kv);
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/portfolio', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
			},
			body: JSON.stringify({ domains: ['example.com'] }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(429);
		const retryAfter = res.headers.get('retry-after');
		expect(retryAfter).not.toBeNull();
		expect(Number(retryAfter)).toBeGreaterThanOrEqual(1);
		const body = (await res.json()) as { error: string; retry_after: number };
		expect(body.error).toBe('Rate limit exceeded');
	});

	it('rate-limit denial emits outcome=denied audit row with rate_limit_exceeded reason', async () => {
		const kv = makeKvStub();
		const { PER_TENANT_QUOTAS } = await import('../../src/tenants/per-tenant-rate-limit');
		const now = new Date();
		const y = now.getUTCFullYear();
		const m = String(now.getUTCMonth() + 1).padStart(2, '0');
		const d = String(now.getUTCDate()).padStart(2, '0');
		const h = String(now.getUTCHours()).padStart(2, '0');
		const min = String(now.getUTCMinutes()).padStart(2, '0');
		const window = `${y}-${m}-${d}T${h}:${min}`;
		const key = `tenant-rl:${TEST_TENANT_ID}:portfolio:min:${window}`;
		kv._store.set(key, String(PER_TENANT_QUOTAS.default.portfolioPerMin));
		const { customEnv, registryCalls } = buildEnvWithTenantAndKv(kv);
		const before = registryCalls.length;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/portfolio', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
			},
			body: JSON.stringify({ domains: ['example.com'] }),
		});
		const res = await sendRequest(req, customEnv);
		expect(res.status).toBe(429);
		const audits = auditRowsBetween(registryCalls, before);
		expect(audits.length).toBe(1);
		expect(audits[0].binds.some((b) => b === 'denied')).toBe(true);
		// blob is the last positional bind in audit's row builder; assert the
		// rate_limit_exceeded marker appears in the JSON-stringified blob.
		const blobBind = audits[0].binds.find((b) => typeof b === 'string' && (b as string).includes('rate_limit_exceeded'));
		expect(blobBind).toBeDefined();
	});
});
