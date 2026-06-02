import { defineConfig } from 'tsup';

export default defineConfig({
	entry: {
		index: 'src/index.ts',
		'scoring/index': 'src/scoring/index.ts',
		'whois/index': 'src/whois/index.ts',
	},
	format: ['esm'],
	target: 'es2022',
	// Declarations are emitted by `tsc --emitDeclarationOnly` (see build script), not tsup:
	// tsup's rollup-dts path injects a deprecated `baseUrl`, a hard error under TypeScript 6.0 (TS5101).
	dts: false,
	sourcemap: true,
	clean: true,
	splitting: false,
});
