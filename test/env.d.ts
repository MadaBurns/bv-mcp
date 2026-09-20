// Type shape of `import { env } from 'cloudflare:test'` for the test tree.
//
// `@cloudflare/vitest-pool-workers` 0.22 types that `env` as `Cloudflare.Env` — the
// interface `wrangler types` generates into the (gitignored) `worker-configuration.d.ts`
// from `wrangler.jsonc`. The older `ProvidedEnv` augmentation point this file used to
// declare no longer exists in the package's `cloudflare:test` declarations, so that
// augmentation was inert; do not reintroduce it.
//
// The test pool's env is a SUPERSET of the deployed one, so the generated interface is
// short three bindings. `Cloudflare.Env` is an interface, so declaration merging is the
// supported way to add them — and keeping them here rather than in the global `Env`
// confines them to the test pool, where `src/` cannot reach for a binding production
// does not have.
declare namespace Cloudflare {
	interface Env {
		/** Declared by `vitest.config.mts`'s miniflare `kvNamespaces`, not by `wrangler.jsonc`. */
		SESSION_STORE: KVNamespace;
		/** Declared by `vitest.config.mts`'s miniflare `kvNamespaces`, not by `wrangler.jsonc`. */
		RATE_LIMIT: KVNamespace;
		/**
		 * Private binding injected at deploy time (`src/index.ts` declares it as
		 * `SCAN_CACHE?: KVNamespace`). Unbound under the test pool, so it stays optional
		 * here too — specs pass it straight into `kv?: KVNamespace` options.
		 */
		SCAN_CACHE?: KVNamespace;
	}
}
