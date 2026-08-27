import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import infraProbeWorker from './src/workers/infra-probe';
import { isKnownWorkerdPoolShutdownError } from './scripts/vitest-unhandled-error-filter.mjs';
import { NODE_POOL_AUDIT_TESTS } from './scripts/vitest-node-suites.mjs';

/**
 * Two projects, one command. `npm test` runs both:
 *
 * - `workers` — the product suite, inside workerd via @cloudflare/vitest-pool-workers.
 * - `node`    — audit suites that shell out to repo scripts with Node built-ins
 *               (`node:child_process`, `node:os`, real `node:fs`). workerd only has
 *               those under `nodejs_compat`, which this Worker deliberately does not
 *               enable, so they belong in a Node pool. See scripts/vitest-node-suites.mjs.
 */
export default defineConfig({
	test: {
		onUnhandledError(error) {
			if (isKnownWorkerdPoolShutdownError(error)) return false;
		},
		projects: [
			{
				plugins: [
					cloudflareTest({
						isolatedStorage: false,
						wrangler: { configPath: './wrangler.jsonc' },
						miniflare: {
							kvNamespaces: ['SESSION_STORE', 'RATE_LIMIT'],
							serviceBindings: {
								BV_WEB: async (_req: Request) => {
									return new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
								},
								// Stub: real shim is bv-whois Worker. Tests that exercise the fallback
								// inject their own Fetcher via checkRdapLookup options; this stub just
								// keeps the runtime startup green when the binding is unused.
								BV_WHOIS: async (_req: Request) => {
									return new Response(JSON.stringify({ registrar: null, source: 'error' }), { status: 200 });
								},
								BV_INFRA_PROBE: async (req: Request) => infraProbeWorker.fetch(req),
							},
							bindings: {
								ENABLE_OAUTH: 'true',
								ENABLE_OWNER_OAUTH: 'true',
								BV_MCP_TENANT_KEY: 'tenant-orchestrator-internal-key',
								// v2.10.9 route gate requires `OAUTH_SIGNING_SECRET >= 32 bytes` for OAuth
								// routes to serve (otherwise 503 service_unavailable). Tests that override
								// env (chaos/e2e/token specs) explicitly unset it. Without this binding,
								// CI ran without .dev.vars and SELF.fetch tests against OAuth routes 503'd
								// instead of hitting the handler — caught by publish.yml v2.10.9 run #25497389714.
								OAUTH_SIGNING_SECRET: 'a'.repeat(32),
							},
						},
					}),
				],
				test: {
					name: 'workers',
					testTimeout: 15_000,
					onUnhandledError(error) {
						if (isKnownWorkerdPoolShutdownError(error)) return false;
					},
					exclude: [
						'node_modules/**',
						'.claude/**',
						'.dev/**',
						'.firecrawl/**',
						'.worktrees/**',
						// BrandAudit audit calibration specs are run via vitest.calibration.config.mts
						// (node env, can read fs). Excluding from the default workers-pool run.
						'scripts/brand-audit-*.spec.ts',
						// Node built-ins / real filesystem — owned by the `node` project below.
						...NODE_POOL_AUDIT_TESTS,
						// Needs real node:fs directory/file reads against .github/workflows — the
						// Workers pool has no real filesystem (readdirSync ENOENTs against the
						// sandboxed /bundle path). Runs only under vitest.node.config.mts, wired
						// via the `audit:oss-safety` npm script (the "File hygiene check" CI job).
						'test/audits/workflow-cost.audit.test.ts',
						// Same reason: walks packages/dns-checks/src with real node:fs to prove the
						// package imports no Node built-in. The Workers pool has no real filesystem.
						'test/audits/dns-checks-runtime-agnostic.node.test.ts',
						// Playwright/report specs require the Node pool and are collected by
						// vitest.node.config.mts, not the Workers runtime.
						'test/pdf-engine.spec.ts',
						'test/generate-discovery-report.spec.ts',
						// scripts/ hosts standalone node:test scripts (e.g. dogfood-scan.test.mjs)
						// that are run directly via `node --test`, not collected by Vitest. Vitest's
						// default include glob (**/*.test.mjs) would otherwise sweep these into the
						// Workers pool, where node:test/node:child_process aren't real -- producing a
						// hard SIGSEGV, not the benign pool-teardown noise documented above.
						// Deliberately broad (all of scripts/) so it also covers future scripts
						// (e.g. scripts/ci/verify-deploy.test.mjs).
						'scripts/**',
					],
					// No coverage config: the @vitest/coverage-v8 provider can't run under the
					// @cloudflare/vitest-pool-workers runtime (workerd lacks `node:inspector`,
					// so instrumentation throws and reports a false 0%). Quality is gated by the
					// structural audit suite under test/audits/ (tool-count/scoring/contract
					// invariants), not by line-coverage numbers.
				},
			},
			{
				test: {
					name: 'node',
					include: NODE_POOL_AUDIT_TESTS,
					environment: 'node',
					pool: 'forks',
					testTimeout: 60_000,
				},
			},
		],
	},
});
