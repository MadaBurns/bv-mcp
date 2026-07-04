// SPDX-License-Identifier: BUSL-1.1

// Drizzle config for the SHARED Tenant registry D1 database.
// One database across all super-tenants — holds tenant metadata, API keys,
// and billing events. Source schema: src/tenants/db/schema/registry.ts.
//
// Usage:
//   npm run tenants:migrate:registry
// (alias for: drizzle-kit generate --config=src/tenants/db/drizzle.registry.config.ts)

import type { Config } from 'drizzle-kit';

const config: Config = {
	schema: './src/tenants/db/schema/registry.ts',
	out: './src/tenants/db/migrations/registry',
	dialect: 'sqlite',
	driver: 'd1-http',
};

export default config;
