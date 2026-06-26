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

	it('labels each row with source (public|internal) and groups by it', async () => {
		const { internalRoutes } = await import('../src/internal');
		const all = vi.fn(async () => ({
			results: [
				{ key_hash: 'abc', tool_name: 'check_spf', source: 'public', calls: 9 },
				{ key_hash: null, tool_name: 'check_spf', source: 'internal', calls: 3 },
			],
		}));
		let capturedSql = '';
		const bind = vi.fn(() => ({ all }));
		const prepare = vi.fn((sql: string) => {
			capturedSql = sql;
			return { bind };
		});
		const env = { REQUIRE_INTERNAL_AUTH: 'false', INTELLIGENCE_DB: { prepare } as unknown as D1Database };
		const res = await internalRoutes.request('/analytics/usage?days=7', {}, env);
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body.source).toBe('all');
		expect(body.usage.map((r: { source: string }) => r.source)).toEqual(['public', 'internal']);
		// legacy NULL rows surface as 'public'; grouped by the coalesced source
		expect(capturedSql).toMatch(/COALESCE\(source, 'public'\) AS source/);
		expect(capturedSql).toMatch(/GROUP BY[\s\S]*COALESCE\(source, 'public'\)/i);
		// no filter ⇒ only the window is bound (back-compat with the base case)
		expect(bind).toHaveBeenCalledWith(7 * 86400);
	});

	it('filters to a single source when ?source= is a known value', async () => {
		const { internalRoutes } = await import('../src/internal');
		const all = vi.fn(async () => ({ results: [] }));
		const bind = vi.fn(() => ({ all }));
		const prepare = vi.fn(() => ({ bind }));
		const env = { REQUIRE_INTERNAL_AUTH: 'false', INTELLIGENCE_DB: { prepare } as unknown as D1Database };
		const res = await internalRoutes.request('/analytics/usage?days=7&source=internal', {}, env);
		expect(res.status).toBe(200);
		expect((await res.json()).source).toBe('internal');
		expect(bind).toHaveBeenCalledWith(7 * 86400, 'internal');
	});

	it('ignores an unrecognized ?source= value (treats as all, no extra bind)', async () => {
		const { internalRoutes } = await import('../src/internal');
		const all = vi.fn(async () => ({ results: [] }));
		const bind = vi.fn(() => ({ all }));
		const prepare = vi.fn(() => ({ bind }));
		const env = { REQUIRE_INTERNAL_AUTH: 'false', INTELLIGENCE_DB: { prepare } as unknown as D1Database };
		const res = await internalRoutes.request('/analytics/usage?days=7&source=bogus', {}, env);
		expect(res.status).toBe(200);
		expect((await res.json()).source).toBe('all');
		expect(bind).toHaveBeenCalledWith(7 * 86400);
	});
});
