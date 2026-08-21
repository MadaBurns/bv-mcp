import { defineConfig } from 'vitest/config';
import { NODE_POOL_AUDIT_TESTS, NODE_POOL_EXTRA_TESTS } from './scripts/vitest-node-suites.mjs';

/**
 * Standalone Node-pool config used by dedicated CI jobs (`audit:oss-safety`,
 * "File hygiene check"). It is a superset of the `node` project in
 * vitest.config.mts: it adds the Playwright/real-filesystem suites that the
 * default `npm test` run deliberately does not collect.
 */
export default defineConfig({
	test: {
		testTimeout: 60_000, // Playwright can be slow
		include: [...NODE_POOL_AUDIT_TESTS, ...NODE_POOL_EXTRA_TESTS],
		environment: 'node',
		pool: 'forks',
	},
});
