import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
	plugins: [
		cloudflareTest({
			isolatedStorage: false,
			wrangler: { configPath: './wrangler.jsonc' },
		}),
	],
	test: {
		testTimeout: 15_000,
		exclude: ['node_modules/**', '.claude/**'],
	},
});
