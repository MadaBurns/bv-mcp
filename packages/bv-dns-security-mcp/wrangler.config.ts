import { defineWranglerConfig } from 'wrangler/experimental-config';

export default defineWranglerConfig({
	minify: true,
	uploadSourceMaps: true,
	types: {
		generate: false,
	},
});
