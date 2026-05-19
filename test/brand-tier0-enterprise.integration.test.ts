// SPDX-License-Identifier: BUSL-1.1

/**
 * Integration tests for `tier0EnterpriseLookup` against a stub `BV_ENTERPRISE`
 * service binding.
 *
 * These tests exercise the real Cloudflare `Fetcher` service-binding contract:
 * the wrapper builds a `Request`, the binding receives it, a stub Worker
 * returns a typed response, and the wrapper parses it through the shared Zod
 * schema. This is the "narrow integration" layer per testing-methodology.md —
 * one external dependency (the binding) is real-ish; everything else is unit.
 *
 * All three blocks are currently `it.skip`'d. They activate when bv-web /
 * bv-enterprise ships the `/internal/tenant-domains/:domain` contract surface
 * (see cross-worker contract doc §1.3 and the producer-side TODO in the
 * bv-enterprise Worker). Removing `.skip` is the single-line change required.
 *
 * The unit-test layer (`brand-tier0-enterprise.test.ts`) already covers the
 * branch logic in isolation. These integration tests guard the wire format
 * once the producer is real.
 */

import { describe, it, expect } from 'vitest';

describe.skip('tier0EnterpriseLookup integration (BV_ENTERPRISE service binding)', () => {
	// SKIP: unblocks when bv-web ships /internal/tenant-domains contract surface
	it('surfaces a Tier 0 observation for a domain registered to a real tenant', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		const stubBinding: Fetcher = {
			fetch: async (input: RequestInfo | URL) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
				expect(url).toContain('/internal/tenant-domains/');
				return new Response(
					JSON.stringify({ isRegistered: true, tenantId: 't_integration', isOptedOut: false }),
					{ status: 200, headers: { 'content-type': 'application/json' } },
				);
			},
		} as unknown as Fetcher;
		const result = await tier0EnterpriseLookup('example.com', stubBinding, {
			BV_WEB_INTERNAL_KEY: 'integration_key',
		});
		expect(result.status).toBe('ok');
		expect(result.observations).toHaveLength(1);
		expect(result.observations[0]).toMatchObject({ source: 'tenant_domains', tier: 0, confidence: 1.0 });
	});

	// SKIP: unblocks when bv-web ships /internal/tenant-domains contract surface
	it('returns optedOut=true and no observations for an opted-out domain', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		const stubBinding: Fetcher = {
			fetch: async () =>
				new Response(JSON.stringify({ isRegistered: true, tenantId: 't_x', isOptedOut: true }), {
					status: 200,
					headers: { 'content-type': 'application/json' },
				}),
		} as unknown as Fetcher;
		const result = await tier0EnterpriseLookup('opted-out.example', stubBinding, {
			BV_WEB_INTERNAL_KEY: 'integration_key',
		});
		expect(result.status).toBe('ok');
		expect(result.optedOut).toBe(true);
		expect(result.observations).toHaveLength(0);
	});

	// SKIP: unblocks when bv-web ships /internal/tenant-domains contract surface
	it('returns degraded status when the binding is unavailable (5xx)', async () => {
		const { tier0EnterpriseLookup } = await import('../src/lib/brand-tier0-enterprise');
		const stubBinding: Fetcher = {
			fetch: async () => new Response('internal error', { status: 500 }),
		} as unknown as Fetcher;
		const result = await tier0EnterpriseLookup('example.com', stubBinding, {
			BV_WEB_INTERNAL_KEY: 'integration_key',
		});
		expect(result.status).toBe('degraded');
		expect(result.observations).toHaveLength(0);
	});
});
