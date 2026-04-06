import { defineConfig } from 'tsup';

export default defineConfig({
	entry: {
		index: 'src/index.ts',
		'scoring/index': 'src/scoring/index.ts',
	},
	format: ['esm'],
	target: 'es2022',
	dts: true,
	sourcemap: true,
	clean: true,
	splitting: false,
});
