// SPDX-License-Identifier: BUSL-1.1

/**
 * End-to-end regression tests for tenant scan persistence.
 *
 * These deliberately do NOT `vi.mock('../../src/handlers/tools')`. Every other
 * tenant suite mocks `handleToolsCall` and fires `resultCapture` itself, so they
 * all passed while production captured nothing: `resultCapture` was only invoked
 * on the `TOOL_REGISTRY` dispatch path, and `scan_domain` is dispatched from the
 * `switch` in `handlers/tools.ts` instead. Every tenant scan row therefore
 * persisted `score: null, grade: null` with zero findings, which made the
 * `/report/:cycle_id` `mean_score` and `grade_dist` aggregates meaningless.
 *
 * Driving the REAL `handleToolsCall` (with DNS mocked at the fetch layer) is the
 * only way to catch that wiring gap, so these tests assert on the values actually
 * bound to the `scans` INSERT.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from '../helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	resetTenantResolverCache();
});

const TEST_TENANT_ID = 'tenant-1';
const TEST_TENANT_BINDING = 'TENANT_DB_TENANT_1';
const TEST_INTERNAL_KEY = 'tenant-orchestrator-internal-key';
const TEST_DOMAIN = 'example.com';
const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';
const SCANS_INSERT_SQL =
	'INSERT INTO scans (id, domain, scan_at, score, grade, maturity_stage, finding_count, result_json, cycle_id) ' +
	'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';

/** Bind positions of the `scans` INSERT above. */
const DOMAIN_BIND = 1;
const SCORE_BIND = 3;
const GRADE_BIND = 4;
const FINDING_COUNT_BIND = 6;
const RESULT_JSON_BIND = 7;

/** A scan-wide DNS/HTTP mock: enough signal that the domain scores above zero. */
function mockScannableDomain() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) return Promise.resolve(txtResponse(`_dmarc.${TEST_DOMAIN}`, ['v=DMARC1; p=reject']));
				if (url.includes('_domainkey.')) return Promise.resolve(txtResponse(`default._domainkey.${TEST_DOMAIN}`, ['v=DKIM1; k=rsa; p=MIGf']));
				return Promise.resolve(txtResponse(TEST_DOMAIN, ['v=spf1 include:_spf.google.com -all']));
			}
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse(TEST_DOMAIN, ['ns1.example.com.', 'ns2.example.com.']));
			}
			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(caaResponse(TEST_DOMAIN, ['0 issue "letsencrypt.org"']));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse(TEST_DOMAIN, true));
			}
			return Promise.resolve(createDohResponse([], []));
		}

		if (url.startsWith('https://')) return Promise.resolve({ ...httpResponse('OK'), url });
		return Promise.resolve(httpResponse('OK'));
	});
}

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
					return ((rowsBySql[sql] ?? [])[0] as T | undefined) ?? null;
				},
				async all<T = unknown>() {
					calls.push({ sql, binds });
					return { results: (rowsBySql[sql] ?? []) as T[], success: true, meta: {} } as unknown as D1Result<T>;
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
			for (const s of stmts) out.push((await (s as unknown as { run: () => Promise<unknown> }).run()) as D1Result<T>);
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

function buildEnv(rowsBySql: Record<string, unknown[]> = {}) {
	const registry = makeMockD1({
		[REGISTRY_LOOKUP_SQL]: [{ id: TEST_TENANT_ID, super_tenant_id: 'super-tenant-1', d1_db_id: 'fake-d1-uuid', active: 1 }],
	});
	const tenant = makeMockD1(rowsBySql);
	const customEnv = {
		...env,
		BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
		REQUIRE_INTERNAL_AUTH: 'true',
		TENANT_REGISTRY_DB: registry.db,
		[TEST_TENANT_BINDING]: tenant.db,
	} as typeof env & Record<string, unknown>;
	return { customEnv, tenantCalls: tenant.calls };
}

/**
 * Assert a `scans` row carries a genuine score/grade rather than the nulls production wrote.
 *
 * `domain` is asserted on the COLUMN (bind 1), not inside `result_json`:
 * `TenantScanSnapshot` (`src/tenants/scan-snapshot.ts`) is a deliberate compact
 * projection of `score`/`grade`/`maturityStage`/`findings` and carries no
 * `domain` key, because the column already holds it. This test originally
 * asserted `parsed.domain` against a pre-`scanResultCapture` snapshot shape
 * that no longer exists.
 */
function expectRealScoreRow(binds: unknown[]) {
	expect(typeof binds[SCORE_BIND]).toBe('number');
	expect(binds[SCORE_BIND]).toBeGreaterThan(0);
	expect(typeof binds[GRADE_BIND]).toBe('string');
	expect(binds[GRADE_BIND]).not.toBe('');
	// result_json must round-trip the aggregate the fingerprint pre-flight re-reads.
	expect(typeof binds[RESULT_JSON_BIND]).toBe('string');
	const parsed = JSON.parse(binds[RESULT_JSON_BIND] as string) as { score?: unknown; grade?: unknown };
	expect(parsed.score).toBe(binds[SCORE_BIND]);
	expect(parsed.grade).toBe(binds[GRADE_BIND]);
	expect(binds[DOMAIN_BIND]).toBe(TEST_DOMAIN);
}

describe('tenant scan persistence (real handleToolsCall)', () => {
	it('persists a real score and grade via the queue consumer', async () => {
		mockScannableDomain();
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv, tenantCalls } = buildEnv();
		const ctx = createExecutionContext();

		const outcome = await processScanMessage(
			{ cycle_id: 'cycle_persist_q', sub_tenant_id: TEST_TENANT_ID, domain: TEST_DOMAIN },
			1,
			customEnv,
			{ waitUntil: (p: Promise<unknown>) => ctx.waitUntil(p) },
		);
		await waitOnExecutionContext(ctx);
		expect(outcome).toBe('ack');

		const scanInserts = tenantCalls.filter((c) => c.sql === SCANS_INSERT_SQL);
		expect(scanInserts.length).toBe(1);
		expectRealScoreRow(scanInserts[0]!.binds);
	});

	it('persists a real score and grade via the sync POST /internal/tenants/scan route', async () => {
		mockScannableDomain();
		const worker = (await import('../../src')).default;
		const { customEnv, tenantCalls } = buildEnv();

		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/scan', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'X-Tenant': TEST_TENANT_ID,
			},
			body: JSON.stringify({ domains: [TEST_DOMAIN] }),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, customEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(200);

		const scanInserts = tenantCalls.filter((c) => c.sql === SCANS_INSERT_SQL);
		expect(scanInserts.length).toBe(1);
		expectRealScoreRow(scanInserts[0]!.binds);
	});

	it('persists the scan findings so finding_count is not stuck at zero', async () => {
		mockScannableDomain();
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const { customEnv, tenantCalls } = buildEnv();
		const ctx = createExecutionContext();

		await processScanMessage(
			{ cycle_id: 'cycle_persist_findings', sub_tenant_id: TEST_TENANT_ID, domain: TEST_DOMAIN },
			1,
			customEnv,
			{ waitUntil: (p: Promise<unknown>) => ctx.waitUntil(p) },
		);
		await waitOnExecutionContext(ctx);

		const scanInsert = tenantCalls.find((c) => c.sql === SCANS_INSERT_SQL);
		const findingCount = scanInsert!.binds[FINDING_COUNT_BIND] as number;
		expect(findingCount).toBeGreaterThan(0);

		// A non-zero finding_count must be matched by actual findings rows, or the
		// cycle alert sweep (which reads the findings table) sees an empty scan.
		const findingInserts = tenantCalls.filter((c) => c.sql.startsWith('INSERT INTO findings'));
		expect(findingInserts.length).toBeGreaterThan(0);
		const persistedFindings = findingInserts.reduce((n, c) => n + c.binds.length / 8, 0);
		expect(persistedFindings).toBe(findingCount);
	});

	it('reports a non-zero mean_score once rows carry real scores', async () => {
		const worker = (await import('../../src')).default;
		// Rows shaped like the ones the fixed persistence path now writes.
		const { customEnv } = buildEnv({
			'SELECT score, grade FROM scans WHERE cycle_id = ?': [
				{ score: 80, grade: 'B' },
				{ score: 90, grade: 'A' },
			],
		});

		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants/report/cycle_persist_q', {
			method: 'GET',
			headers: { Authorization: `Bearer ${TEST_INTERNAL_KEY}`, 'X-Tenant': TEST_TENANT_ID },
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, customEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(200);

		const body = (await res.json()) as { summary: { mean_score: number; grade_dist: Record<string, number> } };
		expect(body.summary.mean_score).toBe(85);
		// Before the fix every row was null → grade_dist was always `{ unknown: N }`.
		expect(body.summary.grade_dist).toEqual({ B: 1, A: 1 });
		expect(body.summary.grade_dist.unknown).toBeUndefined();
	});
});
