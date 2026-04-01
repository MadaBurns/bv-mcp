import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const privateConfigPath = '.dev/wrangler.deploy.jsonc';

if (!existsSync(privateConfigPath)) {
	console.error(`Missing ${privateConfigPath}.`);
	console.error('Copy wrangler.private.example.jsonc to .dev/wrangler.deploy.jsonc and replace the placeholder bindings with real Cloudflare resource identifiers.');
	process.exit(1);
}

const result = spawnSync('npx', ['wrangler', 'deploy', '--config', privateConfigPath, ...process.argv.slice(2)], {
	stdio: 'inherit',
	shell: process.platform === 'win32',
});

if (result.error) {
	console.error(result.error.message);
	process.exit(1);
}

process.exit(result.status ?? 1);