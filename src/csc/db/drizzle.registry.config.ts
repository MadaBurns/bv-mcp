// Drizzle config for the SHARED CSC registry D1 database.
// One database across all super-tenants — holds tenant metadata, API keys,
// and billing events. Source schema: src/csc/db/schema/registry.ts.
//
// Usage:
//   npm run csc:migrate:registry
// (alias for: drizzle-kit generate --config=src/csc/db/drizzle.registry.config.ts)

import type { Config } from 'drizzle-kit';

const config: Config = {
	schema: './src/csc/db/schema/registry.ts',
	out: './src/csc/db/migrations/registry',
	dialect: 'sqlite',
	driver: 'd1-http',
};

export default config;
