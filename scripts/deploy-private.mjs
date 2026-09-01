import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const privateConfigPath = '.dev/wrangler.deploy.jsonc';
const generatedConfigPath = 'wrangler.production.jsonc';

if (!existsSync(privateConfigPath)) {
	console.error(`Missing ${privateConfigPath}.`);
	console.error(
		'Copy wrangler.private.example.jsonc to .dev/wrangler.deploy.jsonc and replace the placeholder bindings with real Cloudflare resource identifiers.',
	);
	process.exit(1);
}

const require = createRequire(import.meta.url);
const wranglerCliPath = require.resolve('wrangler');

/** Run one deploy step, streaming its output and aborting the deploy on any non-zero exit. */
function runStep(argv, description) {
	const step = spawnSync(process.execPath, argv, { stdio: 'inherit' });
	if (step.error) {
		console.error(`${description} failed: ${step.error.message}`);
		process.exit(1);
	}
	if (step.status !== 0) {
		process.exit(step.status ?? 1);
	}
}

// The overlay is an OVERLAY, not a standalone config. Deploying it directly skips the
// public wrangler.jsonc base — routes, cron triggers, limits, tail consumers — and every
// fail-closed gate in inject-private-config.cjs: the production security vars, the
// unknown-overlay-key guard, and the required-secrets declaration. Deploying the overlay
// as-is once meant shipping without PROFILE_ACCUMULATOR, because the example overlay
// carried its own stale `durable_objects` copy. Always deploy the injected config.
runStep(['scripts/inject-private-config.cjs'], 'Private config injection');

runStep(['scripts/brand-audit-schema-preflight.mjs', '--config', generatedConfigPath], 'Brand Audit schema preflight');

const result = spawnSync(process.execPath, [wranglerCliPath, 'deploy', '--config', generatedConfigPath, ...process.argv.slice(2)], {
	stdio: 'inherit',
});

if (result.error) {
	console.error(result.error.message);
	process.exit(1);
}

process.exit(result.status ?? 1);
