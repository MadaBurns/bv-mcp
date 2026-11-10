// SPDX-License-Identifier: BUSL-1.1
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it, vi } from 'vitest';

const credential = 'synthetic-access-context-owner';
const metadata = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'get_access_context', arguments: {} } };

describe('read-only access context HTTP boundary', () => {
	async function call(body: unknown, options: { token?: string; ip?: string; path?: string; rawBody?: string } = {}) {
		const touched = vi.fn(() => {
			throw new Error('Unexpected side effect');
		});
		const unavailable = new Proxy({}, { get: () => touched });
		const targetEnv = {
			...env,
			BV_API_KEY: credential,
			OWNER_ALLOW_IPS: '192.0.2.10',
			OAUTH_SIGNING_SECRET: undefined,
			REQUIRE_AUTH: 'true',
			RATE_LIMIT: unavailable,
			SESSION_STORE: unavailable,
			SCAN_CACHE: unavailable,
			QUOTA_COORDINATOR: unavailable,
			BRAND_AUDIT_DB: unavailable,
			MCP_ANALYTICS: unavailable,
		} as unknown as Env;
		const outbound = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => {
			throw new Error('Unexpected outbound request');
		});
		try {
			const { default: worker } = await import('../src');
			const ctx = createExecutionContext();
			const response = await worker.fetch(
				new Request(`https://example.test${options.path ?? '/mcp'}`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						'CF-Connecting-IP': options.ip ?? '192.0.2.10',
						...(options.token === '' ? {} : { Authorization: `Bearer ${options.token ?? credential}` }),
					},
					body: options.rawBody ?? JSON.stringify(body),
				}),
				targetEnv,
				ctx,
			);
			await waitOnExecutionContext(ctx);
			const text = await response.text();
			expect(touched).not.toHaveBeenCalled();
			expect(outbound).not.toHaveBeenCalled();
			expect(response.headers.get('cache-control')).toBe('no-store');
			expect(text).not.toContain(credential);
			expect(text).not.toContain('192.0.2.10');
			return { response, body: JSON.parse(text) };
		} finally {
			outbound.mockRestore();
		}
	}

	it('returns an owner receipt without a session or target dispatch', async () => {
		const result = await call(metadata);
		expect(result.response.status).toBe(200);
		expect(result.body.result.structuredContent).toMatchObject({ authenticated: true, ownerVerified: true });
	});
	it('honors the owner IP restriction', async () => {
		const result = await call(metadata, { ip: '192.0.2.11' });
		expect(result.response.status).toBe(200);
		expect(result.body.result.structuredContent).toMatchObject({ authenticated: true, ownerVerified: false });
	});
	it('does not treat unresolved credentials as free access', async () => {
		const result = await call(metadata, { token: 'synthetic-unresolved-token' });
		expect(result.response.status).toBe(503);
	});
	it('reports missing authentication without dispatching a free tool', async () => {
		const result = await call(metadata, { token: '' });
		expect(result.body.result.structuredContent).toMatchObject({ authenticated: false, ownerVerified: false });
	});
	it('rejects a mixed batch before authentication and execution', async () => {
		const result = await call([metadata, { ...metadata, id: 2, params: { name: 'check_spf', arguments: { domain: 'example.test' } } }]);
		expect(result.response.status).toBe(400);
	});
	it('rejects malformed arguments through the read-only boundary', async () => {
		const result = await call({ ...metadata, params: { name: ' GET_ACCESS_CONTEXT ', arguments: { domain: 'example.test' } } });
		expect(result.response.status).toBe(400);
	});
	it('rejects an oversized diagnostic before stateful opaque authentication', async () => {
		const result = await call(
			{ ...metadata, params: { name: 'get_access_context', arguments: { padding: 'x'.repeat(11 * 1024) } } },
			{ token: 'synthetic-unresolved-token' },
		);
		expect(result.response.status).toBe(413);
	});
	it('rejects truncated diagnostic JSON before stateful opaque authentication', async () => {
		const result = await call(undefined, {
			token: 'synthetic-unresolved-token',
			rawBody: '{"method":"tools/call","params":{"name":"get_access_context"}',
		});
		expect(result.response.status).toBe(400);
		expect(result.body.error.code).toBe(-32700);
	});
	it('limits repeated diagnostics per client address without touching storage or authentication', async () => {
		// 60 per minute is the control-plane budget; the address is unique to this case.
		const options = { token: 'synthetic-unresolved-token', ip: '192.0.2.77' };
		for (let i = 0; i < 60; i++) expect((await call(metadata, options)).response.status).toBe(503);
		const limited = await call(metadata, options);
		expect(limited.response.status).toBe(429);
		expect(limited.body.error).toMatchObject({ code: -32029, message: expect.stringMatching(/^Rate limit exceeded/) });
		expect(Number(limited.response.headers.get('retry-after'))).toBeGreaterThan(0);
		// Another address is unaffected.
		expect((await call(metadata, { token: 'synthetic-unresolved-token', ip: '192.0.2.78' })).response.status).toBe(503);
	});
	it('uses the same read-only boundary on the legacy POST path', async () => {
		const result = await call(metadata, { path: '/mcp/messages' });
		expect(result.response.status).toBe(200);
	});
});
