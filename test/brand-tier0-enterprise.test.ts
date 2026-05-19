// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for `tier0EnterpriseLookup` — the BV_ENTERPRISE service-binding
 * wrapper that surfaces tenant-declared domain ownership as Tier 0 observations.
 *
 * The wrapper is intentionally fail-soft: every error path returns
 * `{ observations: [], status: 'degraded' }` rather than throwing. Discovery
 * is best-effort; a flaky Tier 0 source must not break the broader pipeline.
 */

import { describe, expect, it, vi } from 'vitest';

const ENV_WITH_KEY = { BV_WEB_INTERNAL_KEY: 'test_internal_key' };

function mockResponse(status: number, body: unknown): Response {
	return {
		status,
		ok: status >= 200 && status < 300,
		json: () => Promise.resolve(body),
	} as unknown as Response;
}

describe('tier0EnterpriseLookup', () => {
	it('returns Tier 0 observation when binding reports isRegistered=true and !isOptedOut', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		const mockBinding = {
			fetch: vi.fn().mockResolvedValue(
				mockResponse(200, {
					isRegistered: true,
					tenantId: 't_abc',
					isOptedOut: false,
					registeredAt: 1779000000,
				}),
			),
		} as unknown as Fetcher;
		const result = await tier0EnterpriseLookup('example.com', mockBinding, ENV_WITH_KEY);
		expect(result.status).toBe('ok');
		expect(result.optedOut).toBe(false);
		expect(result.observations).toHaveLength(1);
		expect(result.observations[0]).toMatchObject({
			candidate: 'example.com',
			source: 'tenant_domains',
			tier: 0,
			confidence: 1.0,
			tenantId: 't_abc',
			registeredAt: 1779000000,
		});
	});

	it('returns empty observations + degraded status when binding throws', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		const mockBinding = {
			fetch: vi.fn().mockRejectedValue(new Error('binding unavailable')),
		} as unknown as Fetcher;
		const result = await tier0EnterpriseLookup('example.com', mockBinding, ENV_WITH_KEY);
		expect(result.observations).toHaveLength(0);
		expect(result.status).toBe('degraded');
		expect(result.optedOut).toBe(false);
	});

	it('returns NO observations when isOptedOut=true regardless of isRegistered', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		const mockBinding = {
			fetch: vi.fn().mockResolvedValue(
				mockResponse(200, { isRegistered: true, tenantId: 't_abc', isOptedOut: true }),
			),
		} as unknown as Fetcher;
		const result = await tier0EnterpriseLookup('example.com', mockBinding, ENV_WITH_KEY);
		expect(result.observations).toHaveLength(0);
		expect(result.optedOut).toBe(true);
		expect(result.status).toBe('ok');
	});

	it('returns empty observations when isRegistered=false (seed not in any portfolio)', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		const mockBinding = {
			fetch: vi.fn().mockResolvedValue(mockResponse(200, { isRegistered: false, isOptedOut: false })),
		} as unknown as Fetcher;
		const result = await tier0EnterpriseLookup('example.com', mockBinding, ENV_WITH_KEY);
		expect(result.observations).toHaveLength(0);
		expect(result.optedOut).toBe(false);
		expect(result.status).toBe('ok');
	});

	it('returns degraded status (no throw) when BV_WEB_INTERNAL_KEY is unset', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		// Binding must NOT be called when the key is unset — short-circuit, fail-soft.
		const mockBinding = { fetch: vi.fn() } as unknown as Fetcher;
		const result = await tier0EnterpriseLookup('example.com', mockBinding, {});
		expect(result.observations).toHaveLength(0);
		expect(result.status).toBe('degraded');
		expect(result.optedOut).toBe(false);
		expect((mockBinding.fetch as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
	});

	it('returns degraded status when response is non-2xx', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		const mockBinding = {
			fetch: vi.fn().mockResolvedValue(mockResponse(500, { error: 'internal' })),
		} as unknown as Fetcher;
		const result = await tier0EnterpriseLookup('example.com', mockBinding, ENV_WITH_KEY);
		expect(result.observations).toHaveLength(0);
		expect(result.status).toBe('degraded');
	});

	it('returns degraded status when response JSON fails Zod validation', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		const mockBinding = {
			fetch: vi.fn().mockResolvedValue(mockResponse(200, { wrong: 'shape' })),
		} as unknown as Fetcher;
		const result = await tier0EnterpriseLookup('example.com', mockBinding, ENV_WITH_KEY);
		expect(result.observations).toHaveLength(0);
		expect(result.status).toBe('degraded');
	});

	it('sends Authorization: Bearer header with the internal key', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		const fetchSpy = vi.fn().mockResolvedValue(
			mockResponse(200, { isRegistered: false, isOptedOut: false }),
		);
		const mockBinding = { fetch: fetchSpy } as unknown as Fetcher;
		await tier0EnterpriseLookup('example.com', mockBinding, { BV_WEB_INTERNAL_KEY: 'sekret' });

		expect(fetchSpy).toHaveBeenCalledTimes(1);
		const firstCall = fetchSpy.mock.calls[0];
		// First arg may be a string URL or a Request — accept either.
		const urlArg = firstCall[0];
		const url = typeof urlArg === 'string' ? urlArg : (urlArg as Request).url;
		expect(url).toContain('/internal/tenant-domains/example.com');

		// Auth header may be on the init bag or the Request — accept either.
		const init = firstCall[1] as RequestInit | undefined;
		const headersFromInit = init?.headers as Record<string, string> | Headers | undefined;
		const auth =
			(headersFromInit instanceof Headers ? headersFromInit.get('Authorization') : (headersFromInit ?? {})['Authorization']) ??
			(typeof urlArg === 'object' ? (urlArg as Request).headers.get('Authorization') : null);
		expect(auth).toBe('Bearer sekret');
	});

	it('URL-encodes the domain segment to defend against path-traversal-like inputs', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		const fetchSpy = vi.fn().mockResolvedValue(
			mockResponse(200, { isRegistered: false, isOptedOut: false }),
		);
		const mockBinding = { fetch: fetchSpy } as unknown as Fetcher;
		// Not a real domain — just verifies the segment is URL-encoded.
		await tier0EnterpriseLookup('foo bar/baz', mockBinding, ENV_WITH_KEY);
		const urlArg = fetchSpy.mock.calls[0][0];
		const url = typeof urlArg === 'string' ? urlArg : (urlArg as Request).url;
		expect(url).toContain(encodeURIComponent('foo bar/baz'));
		expect(url).not.toContain('foo bar/baz');
	});
});
