// test/analytics-rollup-routing.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 1 — decision #2: rollup routing for internal-source access-log events.
//
// Contract (all DARK behind the ANALYTICS_ROLLUP_INTERNAL flag, surfaced on the
// recorder as `options.rollupInternal`):
//   - flag ON  + source 'internal' → UPSERT the `mcp_access_rollup` table; NO
//                                     per-event `INSERT INTO mcp_access_log`.
//   - flag ON  + source 'public'   → per-event `INSERT INTO mcp_access_log`
//                                     (external/authenticated traffic stays faithful).
//   - flag OFF (any source)        → per-event insert, byte-for-byte unchanged.
//
// These tests are written BEFORE the implementation and are expected to FAIL
// until the routing lands (today every path inserts `mcp_access_log`).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/** D1 fake recording every prepared SQL; bind() is chainable, run() resolves. */
function createFakeD1() {
	const run = vi.fn(async () => ({ success: true }));
	const stmt = { bind: vi.fn(() => stmt), run };
	const prepare = vi.fn(() => stmt);
	return { db: { prepare } as unknown as D1Database, prepare, stmt, run };
}

/** Drain whatever was deferred through waitUntil so the inline DB work settles. */
async function drain(promises: Promise<unknown>[]): Promise<void> {
	await Promise.all(promises);
	await new Promise((resolve) => setTimeout(resolve, 0));
}

function preparedSql(prepare: ReturnType<typeof vi.fn>): string[] {
	return prepare.mock.calls.map((call) => String(call[0]));
}

beforeEach(() => {
	vi.resetModules();
});

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('access-log rollup routing (decision #2)', () => {
	it('flag ON + internal source → UPSERTs mcp_access_rollup, no per-event insert', async () => {
		const mod = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const promises: Promise<unknown>[] = [];

		const options = {
			intelligenceDb: fake.db,
			analyticsPiiLevel: 'coarse' as const,
			ip: '192.0.2.9',
			ipHash: 'i_x',
			country: 'NZ',
			source: 'internal',
			rollupInternal: true,
			responseTransport: 'internal',
			startTime: Date.now(),
			waitUntil: (p: Promise<unknown>) => promises.push(p),
		};
		// @ts-expect-error — exercising the internal recorder with a partial options shape
		mod.__recordMcpAccessLogForTest(options, { toolName: 'check_spf', domain: 'example.com', rateLimited: false, method: 'tools/call', status: 'pass' });
		await drain(promises);

		const sqls = preparedSql(fake.prepare);
		expect(sqls.some((sql) => /mcp_access_rollup/i.test(sql))).toBe(true);
		expect(sqls.some((sql) => /on conflict/i.test(sql) && /do update/i.test(sql))).toBe(true);
		expect(sqls.some((sql) => /INSERT INTO mcp_access_log\b/.test(sql))).toBe(false);
	});

	it('rollup UPSERT carries the routing dimensions (source + tool)', async () => {
		const mod = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const promises: Promise<unknown>[] = [];

		const options = {
			intelligenceDb: fake.db,
			analyticsPiiLevel: 'coarse' as const,
			ip: '192.0.2.9',
			ipHash: 'i_x',
			source: 'internal',
			rollupInternal: true,
			responseTransport: 'internal',
			startTime: Date.now(),
			waitUntil: (p: Promise<unknown>) => promises.push(p),
		};
		// @ts-expect-error — partial options for the internal recorder
		mod.__recordMcpAccessLogForTest(options, { toolName: 'check_dmarc', domain: 'example.com', rateLimited: false, method: 'tools/call', status: 'pass' });
		await drain(promises);

		// Gate on the rollup path so this can't pass via the per-event insert's bindings.
		expect(preparedSql(fake.prepare).some((sql) => /mcp_access_rollup/i.test(sql))).toBe(true);
		const boundArgs = fake.stmt.bind.mock.calls.flat();
		expect(boundArgs).toContain('internal');
		expect(boundArgs).toContain('check_dmarc');
	});

	it('flag ON + public source → per-event insert (external traffic stays faithful)', async () => {
		const mod = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const promises: Promise<unknown>[] = [];

		const options = {
			intelligenceDb: fake.db,
			analyticsPiiLevel: 'coarse' as const,
			ip: '192.0.2.9',
			ipHash: 'i_x',
			country: 'NZ',
			source: 'public',
			rollupInternal: true,
			responseTransport: 'json',
			startTime: Date.now(),
			waitUntil: (p: Promise<unknown>) => promises.push(p),
		};
		// @ts-expect-error — partial options for the internal recorder
		mod.__recordMcpAccessLogForTest(options, { toolName: 'check_spf', domain: 'example.com', rateLimited: false, method: 'tools/call', status: 'pass' });
		await drain(promises);

		const sqls = preparedSql(fake.prepare);
		expect(sqls.some((sql) => /INSERT INTO mcp_access_log\b/.test(sql))).toBe(true);
		expect(sqls.some((sql) => /mcp_access_rollup/i.test(sql))).toBe(false);
	});

	it('flag OFF + internal source → per-event insert (unchanged dark default)', async () => {
		const mod = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const promises: Promise<unknown>[] = [];

		const options = {
			intelligenceDb: fake.db,
			analyticsPiiLevel: 'coarse' as const,
			ip: '192.0.2.9',
			ipHash: 'i_x',
			source: 'internal',
			rollupInternal: false,
			responseTransport: 'internal',
			startTime: Date.now(),
			waitUntil: (p: Promise<unknown>) => promises.push(p),
		};
		// @ts-expect-error — partial options for the internal recorder
		mod.__recordMcpAccessLogForTest(options, { toolName: 'check_spf', domain: 'example.com', rateLimited: false, method: 'tools/call', status: 'pass' });
		await drain(promises);

		const sqls = preparedSql(fake.prepare);
		expect(sqls.some((sql) => /INSERT INTO mcp_access_log\b/.test(sql))).toBe(true);
		expect(sqls.some((sql) => /mcp_access_rollup/i.test(sql))).toBe(false);
	});

	it('recordInternalAccessLog forwards rollupInternal so internal rows route to the rollup', async () => {
		const { recordInternalAccessLog } = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const promises: Promise<unknown>[] = [];

		recordInternalAccessLog({
			toolName: 'check_spf',
			domain: 'example.com',
			status: 'pass',
			clientType: 'admin-analytics',
			intelligenceDb: fake.db,
			analyticsPiiLevel: 'coarse',
			startTime: Date.now(),
			waitUntil: (p: Promise<unknown>) => promises.push(p),
			rollupInternal: true,
		} as Parameters<typeof recordInternalAccessLog>[0]);
		await drain(promises);

		const sqls = preparedSql(fake.prepare);
		expect(sqls.some((sql) => /mcp_access_rollup/i.test(sql))).toBe(true);
		expect(sqls.some((sql) => /INSERT INTO mcp_access_log\b/.test(sql))).toBe(false);
	});

	it('recordInternalAccessLog without the flag still inserts a per-event row (unchanged)', async () => {
		const { recordInternalAccessLog } = await import('../src/mcp/execute');
		const fake = createFakeD1();
		const promises: Promise<unknown>[] = [];

		recordInternalAccessLog({
			toolName: 'check_spf',
			domain: 'example.com',
			status: 'pass',
			clientType: 'admin-analytics',
			intelligenceDb: fake.db,
			analyticsPiiLevel: 'coarse',
			startTime: Date.now(),
			waitUntil: (p: Promise<unknown>) => promises.push(p),
		});
		await drain(promises);

		const sqls = preparedSql(fake.prepare);
		expect(sqls.some((sql) => /INSERT INTO mcp_access_log\b/.test(sql))).toBe(true);
		expect(sqls.some((sql) => /mcp_access_rollup/i.test(sql))).toBe(false);
	});
});
