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
	dts: true,
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