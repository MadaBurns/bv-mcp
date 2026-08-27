import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const privateConfigPath = '.dev/wrangler.deploy.jsonc';

if (!existsSync(privateConfigPath)) {
	console.error(`Missing ${privateConfigPath}.`);
	console.error(
		'Copy wrangler.private.example.jsonc to .dev/wrangler.deploy.jsonc and replace the placeholder bindings with real Cloudflare resource identifiers.',
	);
	process.exit(1);
}

const require = createRequire(import.meta.url);
const wranglerCliPath = require.resolve('wrangler');
const preflightResult = spawnSync(
	process.execPath,
	['scripts/brand-audit-schema-preflight.mjs', '--config', privateConfigPath],
	{ stdio: 'inherit' },
);
if (preflightResult.error || preflightResult.status !== 0) {
	if (preflightResult.error) console.error(preflightResult.error.message);
	process.exit(preflightResult.status ?? 1);
}

const result = spawnSync(process.execPath, [wranglerCliPath, 'deploy', '--config', privateConfigPath, ...process.argv.slice(2)], {
	stdio: 'inherit',
});

if (result.error) {
	console.error(result.error.message);
	process.exit(1);
}

process.exit(result.status ?? 1);
