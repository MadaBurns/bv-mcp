import { defineConfig, type Options } from 'tsup';

/** esbuild plugin that shims cloudflare:workers for Node.js (stdio bundle) */
const cloudflareShimPlugin = {
	name: 'cloudflare-workers-shim',
	setup(build: { onResolve: (opts: { filter: RegExp }, callback: (args: { path: string }) => { path: string; namespace: string } | undefined) => void; onLoad: (opts: { filter: RegExp; namespace: string }, callback: () => { contents: string; loader: string }) => void }) {
		build.onResolve({ filter: /^cloudflare:workers$/ }, () => ({
			path: 'cloudflare:workers',
			namespace: 'cf-shim',
		}));
		build.onLoad({ filter: /.*/, namespace: 'cf-shim' }, () => ({
			contents: 'export class DurableObject {}',
			loader: 'js' as const,
		}));
	},
};

const shared: Partial<Options> = {
	format: ['esm'],
	target: 'es2022',
	platform: 'neutral',
	// No `.d.ts` emit: the `blackveil-dns` package ships only a `bin` CLI (no `types`/`exports`),
	// so nothing consumes declarations here. (Also avoids tsup's rollup-dts injecting a deprecated
	// `baseUrl`, a hard error under TypeScript 6.0 — TS5101.) Type safety is still covered by `npm run typecheck`.
	dts: false,
	sourcemap: true,
	splitting: false,
	treeshake: true,
};

export default defineConfig([
	{
		...shared,
		entry: { index: 'src/package.ts' },
		clean: true,
		external: ['punycode', 'cloudflare:workers'],
	},
	{
		...shared,
		entry: { stdio: 'src/stdio.ts' },
		clean: false,
		noExternal: ['punycode'],
		esbuildPlugins: [cloudflareShimPlugin],
	},
]);