// SPDX-License-Identifier: BUSL-1.1

/**
 * Cross-Worker contract: `bv-enterprise` → `bv-mcp` tenant-domains lookup.
 *
 * Source of truth:
 *   docs/superpowers/plans/2026-05-20-brand-discovery-cross-worker-contract.md §1.3.
 *
 * The producer is the `bv-enterprise` Worker exposing
 *   GET /internal/tenant-domains/:domain
 * over a Cloudflare service binding (`BV_ENTERPRISE`). The consumer is
 * `src/lib/brand-tier0-enterprise.ts`. This Zod schema IS the contract:
 * widening or narrowing the producer payload must be paired with a change here
 * and a failing entry in `test/contracts/bv-enterprise-tenant-domains.contract.test.ts`.
 *
 * Auth: callers attach `Authorization: Bearer ${BV_WEB_INTERNAL_KEY}` (the
 * shared cross-Worker key per the contract doc §"Versioning" decision).
 *
 * Privacy boundary: `isOptedOut` is the operator-approved suppression flag from
 * `gsi_domain_optouts`. It is REQUIRED on every payload — never default-false.
 * A missing field must fail closed (Zod rejects the parse), forcing the consumer
 * down its `degraded` branch rather than silently treating the seed as opted-in.
 *
 * BSL — do NOT import this schema from a bv-web npm package. The duplication is
 * deliberate: two independently-owned Workers, two copies, contract test is the
 * convergence pressure (testing-methodology.md principle 3).
 */

import { z } from 'zod';

/**
 * Response shape for `GET /internal/tenant-domains/:domain`.
 *
 * Fields:
 *   - `isRegistered` (required): the seed is present in `tenant_domains` for any tenant.
 *   - `tenantId` (optional): present iff `isRegistered === true`. Opaque string.
 *   - `isOptedOut` (required): the seed appears in `gsi_domain_optouts`. Privacy-critical.
 *   - `registeredAt` (optional): Unix-seconds timestamp; only meaningful when `isRegistered`.
 *   - `trancoRank` (optional, nullable): convenience pass-through from the registry row.
 */
export const TenantDomainsLookupResponseSchema = z.object({
	isRegistered: z.boolean(),
	tenantId: z.string().optional(),
	isOptedOut: z.boolean(),
	registeredAt: z.number().optional(),
	trancoRank: z.number().nullable().optional(),
});

export type TenantDomainsLookupResponse = z.infer<typeof TenantDomainsLookupResponseSchema>;
