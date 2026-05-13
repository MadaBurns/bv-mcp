import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		testTimeout: 60_000, // Playwright can be slow
		include: [
			'test/pdf-engine.spec.ts',
			'test/generate-discovery-report.spec.ts'
		],
		environment: 'node',
		pool: 'forks',
	},
});
