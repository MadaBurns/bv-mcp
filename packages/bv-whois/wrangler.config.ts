import { defineWranglerConfig } from 'wrangler/experimental-config';

export default defineWranglerConfig({
	uploadSourceMaps: true,
	types: {
		generate: false,
	},
});
