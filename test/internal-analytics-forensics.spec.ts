import { afterEach, describe, expect, it, vi } from 'vitest';
afterEach(() => vi.restoreAllMocks());

describe('GET /internal/analytics/forensics', () => {
	it('503s when BV_WEB_INTERNAL_KEY unset; 401 on wrong bearer (strict gate ignores REQUIRE_INTERNAL_AUTH=false)', async () => {
		const { internalRoutes } = await import('../src/internal');
		const env = { REQUIRE_INTERNAL_AUTH: 'false', INTELLIGENCE_DB: {} as D1Database };
		const r503 = await internalRoutes.request('/analytics/forensics', {}, env);
		expect(r503.status).toBe(503);
		const r401 = await internalRoutes.request(
			'/analytics/forensics',
			{ headers: { authorization: 'Bearer wrong' } },
			{ ...env, BV_WEB_INTERNAL_KEY: 'right' },
		);
		expect(r401.status).toBe(401);
	});

	it('with the strict bearer: returns decrypted IPs and writes an audit row', async () => {
		const { encryptIpEvidence } = await import('../src/mcp/execute');
		const key = btoa(String.fromCharCode(...new Uint8Array(32))); // 32 zero bytes
		const ct = await encryptIpEvidence('192.0.2.77', key);
		const { internalRoutes } = await import('../src/internal');
		const auditRun = vi.fn(async () => ({ success: true }));
		const all = vi.fn(async () => ({ results: [{ ip_ciphertext: ct, ip_key_version: 'v1', key_hash: 'abc', created_at: 1, ptr_hostname: 'h.example' }] }));
		const prepare = vi.fn((sql: string) => (sql.includes('audit_events') ? { bind: () => ({ run: auditRun }) } : { bind: () => ({ all }) }));
		const env = {
			BV_WEB_INTERNAL_KEY: 'right',
			MCP_ACCESS_LOG_IP_ENCRYPTION_KEY: key,
			INTELLIGENCE_DB: { prepare } as unknown as D1Database,
		};
		const res = await internalRoutes.request('/analytics/forensics?days=1', { headers: { authorization: 'Bearer right' } }, env);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { events: Array<{ ip: string }> };
		expect(body.events[0].ip).toBe('192.0.2.77'); // decrypted
		expect(auditRun).toHaveBeenCalledTimes(1); // self-audit written
	});
});
