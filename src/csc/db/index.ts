// SPDX-License-Identifier: BUSL-1.1

/**
 * Barrel re-exports for the CSC multi-tenant D1 schemas.
 *
 *   - `./schema/registry` — shared registry DB (super_tenants, sub_tenants, tenant_keys, billing_events)
 *   - `./schema/tenant`   — per-sub-tenant DB (domains, scans, findings, alerts)
 *
 * Use these imports from handler/adapter code; do not reach into the schema
 * sub-files directly — keeping the surface narrow lets us add scoped helpers
 * (e.g. `db.registry.activeKeys()`) here later without churn at call sites.
 *
 * TODO(csc-d1-schemas): wire these into a `drizzle.config.ts` once the
 * registry / tenant migrations are introduced. No drizzle-kit config exists
 * yet, so migrations are not generated from this file.
 */

export * from './schema/registry';
export * from './schema/tenant';
