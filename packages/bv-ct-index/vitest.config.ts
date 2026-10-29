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
		// Only active under `--coverage` (npm run test:coverage); the plain `test` script is unchanged.
		// Istanbul, not V8: @cloudflare/vitest-plugin only wires V8 coverage for Vitest >= 5
		// (its runner DO gates the node:inspector session on `vitestMajorVersion >= 5`), and this
		// package pins Vitest 4.1.12. Istanbul instruments the source at transform time, so it works
		// inside workerd. No thresholds on purpose: this reports, it does not gate.
		coverage: {
			provider: 'istanbul',
			include: ['src/**'],
			exclude: ['src/__tests__/**', 'src/**/*.d.ts'],
			reporter: ['text-summary', 'lcov'],
			reportsDirectory: './coverage',
		},
	},
});
