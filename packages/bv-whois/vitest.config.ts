import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-plugin';

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: './wrangler.jsonc' },
			miniflare: {
				kvNamespaces: ['WHOIS_CACHE'],
			},
		}),
	],
	test: {
		testTimeout: 15_000,
		include: ['src/__tests__/**/*.test.ts'],
		dangerouslyIgnoreUnhandledErrors: true,
	},
});
