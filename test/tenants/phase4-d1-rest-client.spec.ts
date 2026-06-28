// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 4 (WFP routing) — TDD contract spec for `D1ByIdClient`, the D1 REST-by-id
 * operator fallback used only in `routing_mode='rest'`.
 *
 * Layer: Unit (Vitest, Workers pool). Asserts the REST transport contract:
 *   - builds `POST /accounts/{acct}/d1/database/{d1_db_id}/query` with the
 *     `Bearer` token + JSON `{ sql, params }` body.
 *   - parses the CF `result[0].results` envelope for `.all()` / `.first()`.
 *   - `.first(col)` extracts a column; `.first()` returns null on an empty set.
 *   - a non-2xx response throws `tenant_db_rest_failed:<status>`.
 *
 * `fetch` is injected (the client's test seam) so no network is touched.
 * Mock isolation: dynamic `import()` inside each test fn.
 */

import { describe, it, expect } from 'vitest';

/** Injectable fetch double that captures the request + returns a canned response. */
function fakeFetch(captured: { url?: string; init?: RequestInit }, payload: unknown, ok = true, status = 200) {
	return (async (url: string | URL | Request, init?: RequestInit) => {
		captured.url = String(url);
		captured.init = init;
		return {
			ok,
			status,
			json: async () => payload,
		} as unknown as Response;
	}) as unknown as typeof fetch;
}

describe('Phase 4 — D1ByIdClient REST transport', () => {
	it('builds the correct REST request and parses .all() results', async () => {
		const { D1ByIdClient } = await import('../../src/tenants/d1-rest-client');
		const captured: { url?: string; init?: RequestInit } = {};
		const payload = { success: true, result: [{ results: [{ id: 'a' }, { id: 'b' }] }] };
		const client = new D1ByIdClient('db-uuid', 'acct-123', 'tok-xyz', fakeFetch(captured, payload));

		const res = await client.prepare('SELECT id FROM t WHERE k = ?').bind('v1').all<{ id: string }>();

		expect(res.results).toEqual([{ id: 'a' }, { id: 'b' }]);
		expect(captured.url).toBe('https://api.cloudflare.com/client/v4/accounts/acct-123/d1/database/db-uuid/query');
		expect(captured.init?.method).toBe('POST');
		expect((captured.init?.headers as Record<string, string>).authorization).toBe('Bearer tok-xyz');
		expect((captured.init?.headers as Record<string, string>)['content-type']).toBe('application/json');
		expect(JSON.parse(captured.init?.body as string)).toEqual({ sql: 'SELECT id FROM t WHERE k = ?', params: ['v1'] });
	});

	it('.first() returns the first row and .first(col) extracts the named column', async () => {
		const { D1ByIdClient } = await import('../../src/tenants/d1-rest-client');
		const captured: { url?: string; init?: RequestInit } = {};
		const payload = { success: true, result: [{ results: [{ id: 'a', name: 'first' }] }] };
		const client = new D1ByIdClient('db-uuid', 'acct-123', 'tok-xyz', fakeFetch(captured, payload));

		expect(await client.prepare('SELECT * FROM t').first()).toEqual({ id: 'a', name: 'first' });
		expect(await client.prepare('SELECT * FROM t').first<string>('name')).toBe('first');
	});

	it('.first() returns null on an empty result set', async () => {
		const { D1ByIdClient } = await import('../../src/tenants/d1-rest-client');
		const captured: { url?: string; init?: RequestInit } = {};
		const payload = { success: true, result: [{ results: [] }] };
		const client = new D1ByIdClient('db-uuid', 'acct-123', 'tok-xyz', fakeFetch(captured, payload));

		expect(await client.prepare('SELECT * FROM t WHERE 0').first()).toBeNull();
	});

	it('throws tenant_db_rest_failed:<status> on a non-2xx response', async () => {
		const { D1ByIdClient } = await import('../../src/tenants/d1-rest-client');
		const captured: { url?: string; init?: RequestInit } = {};
		const client = new D1ByIdClient('db-uuid', 'acct-123', 'tok-xyz', fakeFetch(captured, { success: false }, false, 403));

		await expect(client.prepare('SELECT 1').run()).rejects.toThrow(/tenant_db_rest_failed:403/);
	});

	it('reports backend === "rest"', async () => {
		const { D1ByIdClient } = await import('../../src/tenants/d1-rest-client');
		const captured: { url?: string; init?: RequestInit } = {};
		const client = new D1ByIdClient('db-uuid', 'acct-123', 'tok-xyz', fakeFetch(captured, { success: true, result: [{ results: [] }] }));
		expect(client.backend).toBe('rest');
	});
});
