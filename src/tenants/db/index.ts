// SPDX-License-Identifier: BUSL-1.1

/**
 * Barrel re-exports for the Tenant multi-tenant D1 schemas.
 *
 *   - `./schema/registry` — shared registry DB (super_tenants, sub_tenants, tenant_keys, billing_events)
 *   - `./schema/tenant`   — per-sub-tenant DB (domains, scans, findings, alerts)
 *
 * Use these imports from handler/adapter code; do not reach into the schema
 * sub-files directly — keeping the surface narrow lets us add scoped helpers
 * (e.g. `db.registry.activeKeys()`) here later without churn at call sites.
 *
 * Drizzle-kit configs for migration generation:
 *   - registry DB: `src/tenants/db/drizzle.registry.config.ts`
 *   - per-tenant DB: `src/tenants/db/drizzle.tenant.config.ts`
 * Run via `npm run drizzle:generate` / `npm run drizzle:check`.
 */

export * from './schema/registry';
export * from './schema/tenant';
