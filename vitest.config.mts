import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config';

export default defineWorkersConfig({
	test: {
		poolOptions: {
			workers: {
				wrangler: { configPath: './wrangler.jsonc' },
			},
		},
		exclude: ['bv-dns-security-mcp/**', 'node_modules/**'],
		coverage: {
			provider: 'istanbul',
			reporter: ['text', 'json-summary'],
			include: ['src/**/*.ts'],
			exclude: ['src/**/*.d.ts'],
		},
	},
});
