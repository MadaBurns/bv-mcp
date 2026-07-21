import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		testTimeout: 60_000, // Playwright can be slow
		include: [
			'test/pdf-engine.spec.ts',
			'test/generate-discovery-report.spec.ts',
			'test/audits/brand-report-qa-script.node.test.ts',
			'test/audits/brand-report-quality-audit-script.node.test.ts',
			'test/audits/private-config-injection.node.test.ts',
			'test/audits/pretooluse-hook-scope.node.test.ts',
			'test/audits/repo-safety-push-range-scanner.audit.test.ts',
			'test/audits/license-headers.audit.test.ts',
			'test/audits/dependency-license.audit.test.ts',
			'test/audits/workflow-cost.audit.test.ts',
			'test/audits/vitest-workerd-stderr-filter.node.test.ts',
			'test/audits/score-stability-chaos-script.node.test.ts',
		],
		environment: 'node',
		pool: 'forks',
	},
});
