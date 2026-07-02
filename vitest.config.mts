import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import infraProbeWorker from './src/workers/infra-probe';

export default defineConfig({
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
		testTimeout: 15_000,
		exclude: [
			'node_modules/**',
			'.claude/**',
			'.dev/**',
			'.worktrees/**',
			// BrandAudit audit calibration specs are run via vitest.calibration.config.mts
			// (node env, can read fs). Excluding from the default workers-pool run.
			'scripts/brand-audit-*.spec.ts',
		],
		poolMatchGlobs: [
			['test/pdf-engine.spec.ts', 'forks'],
			['test/generate-discovery-report.spec.ts', 'forks'],
		],
		// Pool-teardown noise from @cloudflare/vitest-pool-workers: miniflare's
		// communication WebSocket emits `peer disconnected` events on workerd
		// shutdown that the pool's transport bridge reports as 2 file-level
		// unhandled errors, even though every test assertion passes (3103/3103).
		// The errors don't carry an exit code by themselves — they only flip the
		// suite to red when vitest's Errors count is non-zero.
		//
		// KNOWN TRADE-OFF (audit FIND-4, flagged for operator): this is GLOBAL —
		// it swallows *every* unhandled error in the ~3300-test suite, so a real
		// floating-promise rejection would no longer fail CI. It is NOT redundant
		// with scripts/vitest-filter-workerd.mjs: that wrapper is output-only (it
		// strips the matching raw stderr LINE from user-visible output) and does
		// NOT affect vitest's unhandled-error count or exit code. Removing this
		// flag and relying on the stderr filter alone WOULD re-red the full suite
		// on the teardown noise. Vitest exposes no per-message narrow for this at
		// config level, so tightening safely requires a pool-workers fix (or a
		// vitest onUnhandledError filter hook) — left as operator follow-up rather
		// than silently reintroducing a flaky-red full suite.
		dangerouslyIgnoreUnhandledErrors: true,
		// No coverage config: the @vitest/coverage-v8 provider can't run under the
		// @cloudflare/vitest-pool-workers runtime (workerd lacks `node:inspector`,
		// so instrumentation throws and reports a false 0%). Quality is gated by the
		// structural audit suite under test/audits/ (tool-count/scoring/contract
		// invariants), not by line-coverage numbers.
	},
});
