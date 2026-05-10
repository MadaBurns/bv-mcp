import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-pool-workers';

export default defineConfig({
	plugins: [
		cloudflareTest({
			isolatedStorage: false,
			wrangler: { configPath: './wrangler.jsonc' },
			miniflare: {
				kvNamespaces: ['SESSION_STORE', 'RATE_LIMIT'],
				serviceBindings: {
					BV_WEB: async (req: Request) => {
						return new Response(JSON.stringify({ status: 'ok' }), { status: 200 });
					},
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
		exclude: ['node_modules/**', '.claude/**', '.worktrees/**'],
	},
});
