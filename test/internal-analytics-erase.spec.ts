import { afterEach, describe, expect, it, vi } from 'vitest';
afterEach(() => vi.restoreAllMocks());

describe('POST /internal/analytics/erase', () => {
	it('503s when BV_WEB_INTERNAL_KEY unset; 401 on wrong bearer (strict gate ignores REQUIRE_INTERNAL_AUTH=false)', async () => {
		const { internalRoutes } = await import('../src/internal');
		const env = { REQUIRE_INTERNAL_AUTH: 'false', INTELLIGENCE_DB: {} as D1Database };
		const r503 = await internalRoutes.request('/analytics/erase', { method: 'POST' }, env);
		expect(r503.status).toBe(503);
		const r401 = await internalRoutes.request(
			'/analytics/erase',
			{ method: 'POST', headers: { authorization: 'Bearer wrong' } },
			{ ...env, BV_WEB_INTERNAL_KEY: 'right' },
		);
		expect(r401.status).toBe(401);
	});

	it('400s when neither key_hash nor ip_hash is given', async () => {
		const { internalRoutes } = await import('../src/internal');
		const env = { BV_WEB_INTERNAL_KEY: 'right', INTELLIGENCE_DB: {} as D1Database };
		const res = await internalRoutes.request('/analytics/erase', { method: 'POST', headers: { authorization: 'Bearer right' } }, env);
		expect(res.status).toBe(400);
	});

	it('deletes matching rows, returns the count, and writes a self-audit row', async () => {
		const { internalRoutes } = await import('../src/internal');
		const auditRun = vi.fn(async () => ({ success: true }));
		const deleteRun = vi.fn(async () => ({ success: true, meta: { changes: 7 } }));
		const bindArgs: unknown[][] = [];
		const prepare = vi.fn((sql: string) =>
			sql.includes('mcp_access_log_audit')
				? { bind: (...args: unknown[]) => (bindArgs.push(args), { run: auditRun }) }
				: { bind: (...args: unknown[]) => (bindArgs.push(args), { run: deleteRun }) },
		);
		const env = { BV_WEB_INTERNAL_KEY: 'right', INTELLIGENCE_DB: { prepare } as unknown as D1Database };
		const res = await internalRoutes.request(
			'/analytics/erase?key_hash=abc123',
			{ method: 'POST', headers: { authorization: 'Bearer right' } },
			env,
		);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { deleted: number };
		expect(body.deleted).toBe(7);
		expect(deleteRun).toHaveBeenCalledTimes(1);
		expect(auditRun).toHaveBeenCalledTimes(1);
		// The DELETE must be filtered — never an unfiltered table wipe.
		const deleteSql = (prepare.mock.calls.find(([sql]) => !String(sql).includes('mcp_access_log_audit')) ?? [''])[0];
		expect(String(deleteSql)).toContain('WHERE');
		expect(String(deleteSql)).toContain('key_hash = ?');
	});
});
