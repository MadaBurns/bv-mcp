// SPDX-License-Identifier: BUSL-1.1

/**
 * bv-ct-index deploy preflight (US-12, SQ-354) — CLI shell.
 *
 * Wired at the FRONT of `npm run deploy:ct-index` (`check:ct-index-deploy-ready`) so a missing D1 id, a wrong Worker name or an
 * empty migrations directory stops the chain before anything is built or uploaded. All decision logic lives in the pure
 * `scripts/ct-index-deploy-ready.ts`; this file only turns the filesystem and the environment into its inputs. A file that cannot
 * be read becomes `null`, which the core treats as a failure, never a pass.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { assessCtIndexDeployReady, CT_INDEX_D1_ID_ENV } from '../ct-index-deploy-ready';

const PACKAGE_DIR = new URL('../../packages/bv-ct-index/', import.meta.url);

function readText(name: string): string | null {
	try {
		return readFileSync(new URL(name, PACKAGE_DIR), 'utf8');
	} catch {
		return null;
	}
}

function listDir(name: string): string[] | null {
	try {
		return readdirSync(new URL(name, PACKAGE_DIR));
	} catch {
		return null;
	}
}

export function main(env: NodeJS.ProcessEnv = process.env): number {
	const verdict = assessCtIndexDeployReady({
		d1Id: env[CT_INDEX_D1_ID_ENV],
		configSource: readText('cloudflare.config.ts'),
		wranglerSource: readText('wrangler.jsonc'),
		packageJsonSource: readText('package.json'),
		migrationFiles: listDir('migrations/'),
	});
	if (verdict.ok) {
		console.log('ct-index deploy preflight: OK (D1 id resolves, Worker name is bv-ct-index, migrations present)');
		return 0;
	}
	console.error('ct-index deploy preflight: BLOCKED');
	for (const failure of verdict.failures) console.error(`  - ${failure}`);
	return 1;
}

// Run only when executed directly, never on import.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
	process.exit(main());
}
