// SPDX-License-Identifier: BUSL-1.1
/**
 * Contract: bv-enterprise → bv-mcp tenant-domains lookup surface.
 *
 * Source of truth: docs/superpowers/plans/2026-05-20-brand-discovery-cross-worker-contract.md §1.3.
 *
 * bv-mcp consumes `GET /internal/tenant-domains/:domain` from the bv-enterprise
 * Worker via the `BV_ENTERPRISE` service binding. The Zod schema in
 * `src/schemas/cross-worker-tenant-domains.ts` IS the inter-Worker contract.
 * If bv-enterprise widens or narrows the payload, this test will catch it.
 */

import { describe, expect, it } from 'vitest';

describe('TenantDomainsLookupResponseSchema contract', () => {
	it('producer payload conforms to schema (registered, not opted out)', async () => {
		const { TenantDomainsLookupResponseSchema } = await import('../../src/schemas/cross-worker-tenant-domains');
		const payload = {
			isRegistered: true,
			tenantId: 't_abc',
			isOptedOut: false,
			registeredAt: 1779000000,
		};
		expect(() => TenantDomainsLookupResponseSchema.parse(payload)).not.toThrow();
	});

	it('producer payload conforms when domain is registered but opted out', async () => {
		const { TenantDomainsLookupResponseSchema } = await import('../../src/schemas/cross-worker-tenant-domains');
		const payload = {
			isRegistered: true,
			tenantId: 't_abc',
			isOptedOut: true,
		};
		expect(() => TenantDomainsLookupResponseSchema.parse(payload)).not.toThrow();
	});

	it('producer payload conforms when domain is not registered (minimal shape)', async () => {
		const { TenantDomainsLookupResponseSchema } = await import('../../src/schemas/cross-worker-tenant-domains');
		const payload = { isRegistered: false, isOptedOut: false };
		expect(() => TenantDomainsLookupResponseSchema.parse(payload)).not.toThrow();
	});

	it('accepts optional trancoRank as number or null', async () => {
		const { TenantDomainsLookupResponseSchema } = await import('../../src/schemas/cross-worker-tenant-domains');
		expect(() =>
			TenantDomainsLookupResponseSchema.parse({ isRegistered: true, isOptedOut: false, trancoRank: 12345 }),
		).not.toThrow();
		expect(() =>
			TenantDomainsLookupResponseSchema.parse({ isRegistered: true, isOptedOut: false, trancoRank: null }),
		).not.toThrow();
	});

	it('consumer rejects malformed payloads (isRegistered wrong type)', async () => {
		const { TenantDomainsLookupResponseSchema } = await import('../../src/schemas/cross-worker-tenant-domains');
		expect(() => TenantDomainsLookupResponseSchema.parse({ isRegistered: 'yes', isOptedOut: false })).toThrow();
	});

	it('consumer rejects payloads missing required isOptedOut boundary flag', async () => {
		const { TenantDomainsLookupResponseSchema } = await import('../../src/schemas/cross-worker-tenant-domains');
		// isOptedOut is a privacy-critical boundary flag. Missing it must FAIL closed,
		// not default to false.
		expect(() => TenantDomainsLookupResponseSchema.parse({ isRegistered: true })).toThrow();
	});
});
