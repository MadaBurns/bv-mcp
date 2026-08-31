/**
 * Single source of truth for the test suites that must run in a **Node** pool
 * rather than the Cloudflare Workers pool.
 *
 * These suites shell out to repo scripts / walk the real filesystem via Node
 * built-ins (`node:child_process`, `node:fs`, `node:os`), which do not exist in
 * workerd unless `nodejs_compat` is enabled. Until @cloudflare/vitest-pool-workers
 * 0.21.2 the pool injected `nodejs_compat_v2` unconditionally, so these files
 * happened to load inside the Workers pool; 0.21.2+ resolves Node compatibility
 * from the Worker's own compatibility date/flags (wrangler.jsonc pins
 * 2026-07-29 with no `nodejs_compat`), so the built-ins are correctly gone.
 * They are therefore routed to a dedicated `node` project instead.
 */

/**
 * Node-pool audit suites that the default `npm test` run collects (via the
 * `node` project in vitest.config.ts). Governance gates — they must always run.
 */
export const NODE_POOL_AUDIT_TESTS = [
	'test/scheduled/brand-audit-cron-d1.node.test.ts',
	'test/audits/brand-audit-schema-preflight.node.test.ts',
	'test/audits/brand-report-qa-script.node.test.ts',
	'test/audits/brand-report-quality-audit-script.node.test.ts',
	'test/audits/dependency-license.audit.test.ts',
	'test/audits/license-headers.audit.test.ts',
	'test/audits/pretooluse-hook-scope.node.test.ts',
	'test/audits/private-config-injection.node.test.ts',
	'test/audits/repo-safety-push-range-scanner.audit.test.ts',
	'test/audits/score-stability-chaos-script.node.test.ts',
	'test/audits/scoring-version-gate.node.test.ts',
	'test/audits/security-capability-inventory.node.test.ts',
	'test/audits/vitest-workerd-stderr-filter.node.test.ts',
];

/**
 * Additional Node-pool suites that the default `npm test` run deliberately does
 * NOT collect: they need Playwright browsers or long real-filesystem walks and
 * are run by dedicated CI jobs (`audit:oss-safety` / "File hygiene check") via
 * `--config vitest.node.config.mts`.
 */
export const NODE_POOL_EXTRA_TESTS = [
	'test/pdf-engine.spec.ts',
	'test/generate-discovery-report.spec.ts',
	'test/audits/workflow-cost.audit.test.ts',
	'test/audits/dns-checks-runtime-agnostic.node.test.ts',
];
