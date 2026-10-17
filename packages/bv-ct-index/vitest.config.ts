import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-plugin';

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: './wrangler.jsonc' },
		}),
	],
	test: {
		// Stable project name: the root vitest.config.mts lists this package as a project, so
		// `vitest run --project bv-ct-index` selects it (the default would be the package.json name).
		name: 'bv-ct-index',
		testTimeout: 15_000,
		include: ['src/__tests__/**/*.test.ts'],
	},
});
