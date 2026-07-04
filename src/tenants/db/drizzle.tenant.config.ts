// SPDX-License-Identifier: BUSL-1.1

// Drizzle config for the PER-SUB-TENANT Tenant D1 schema.
// One database PER sub-tenant — holds their domains, scans, findings, alerts.
// Source schema: src/tenants/db/schema/tenant.ts.
//
// The generated migration is the same SQL applied to every per-tenant D1; the
// orchestrator's tenant-provisioning script applies it on each new sub-tenant.
//
// Usage:
//   npm run tenants:migrate:tenant
// (alias for: drizzle-kit generate --config=src/tenants/db/drizzle.tenant.config.ts)

import type { Config } from 'drizzle-kit';

const config: Config = {
	schema: './src/tenants/db/schema/tenant.ts',
	out: './src/tenants/db/migrations/tenant',
	dialect: 'sqlite',
	driver: 'd1-http',
};

export default config;
