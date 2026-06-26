// test/internal-analytics-usage.spec.ts
import { afterEach, describe, expect, it, vi } from 'vitest';
afterEach(() => vi.restoreAllMocks());

describe('GET /internal/analytics/usage', () => {
	it('queries mcp_access_log grouped by key_hash with a bounded window', async () => {
		const { internalRoutes } = await import('../src/internal');
		const all = vi.fn(async () => ({ results: [{ key_hash: 'abc', calls: 4 }] }));
		const bind = vi.fn(() => ({ all }));
		const prepare = vi.fn(() => ({ bind }));
		const env = { REQUIRE_INTERNAL_AUTH: 'false', INTELLIGENCE_DB: { prepare } as unknown as D1Database };
		const res = await internalRoutes.request('/analytics/usage?days=7', {}, env);
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.usage[0].key_hash).toBe('abc');
		// window clamped + passed as a bind param (days*86400 seconds)
		expect(bind).toHaveBeenCalledWith(7 * 86400);
	});
});
