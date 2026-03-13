import { defineConfig } from 'tsup';

export default defineConfig({
	entry: {
		index: 'src/package.ts',
		stdio: 'src/stdio.ts',
	},
	format: ['esm'],
	target: 'es2022',
	platform: 'neutral',
	dts: true,
	clean: true,
	sourcemap: true,
	splitting: false,
	treeshake: true,
	external: ['punycode', 'cloudflare:workers'],
});