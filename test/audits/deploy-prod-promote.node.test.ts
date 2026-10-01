// SPDX-License-Identifier: BUSL-1.1
//
// Contract for scripts/deploy-prod-promote.mjs (SQ-256, Phase 5.3): `npm run deploy:prod:promote` routes production
// traffic to an uploaded Worker version and must FAIL CLOSED without an explicit version id. Node pool: it spawns the
// real script and reads the real cloudflare.config.ts with node:fs / node:child_process.

import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { PRODUCTION_WORKER_NAME, VERSION_ID_ENV, buildPromoteArgv, resolveVersionId } from '../../scripts/deploy-prod-promote.mjs';

const root = process.cwd();
const scriptPath = join(root, 'scripts/deploy-prod-promote.mjs');
const VERSION_ID = '023e105f-2a42-4f8b-a1c1-73f6a2a30c0f';

/** Run the script with a scrubbed environment so an ambient BV_PROMOTE_VERSION_ID cannot leak in. */
function runPromote(args: string[], env: Record<string, string> = {}) {
	return spawnSync(process.execPath, [scriptPath, ...args], {
		encoding: 'utf8',
		env: { PATH: process.env.PATH ?? '', ...env },
	});
}

describe('deploy-prod-promote: fail closed without an explicit version id', () => {
	it('exits non-zero, names the missing id, and never starts cf when no id is given', () => {
		const result = runPromote([]);
		expect(result.status, 'no version id must be a refusal, never a guess at "latest"').toBe(1);
		expect(result.stderr).toContain('Refusing to promote: no version id');
		expect(result.stdout).toBe('');
	});

	it('treats an empty argument and an empty env value as absent', () => {
		expect(runPromote(['']).status).toBe(1);
		expect(runPromote([], { [VERSION_ID_ENV]: '' }).status).toBe(1);
	});

	it.each(['latest', '--help', '023e105f', `${VERSION_ID}; echo pwned`, `[{"version_id":"${VERSION_ID}","percentage":100}]`])(
		'rejects %j: anything that is not a version UUID',
		(bad) => {
			const result = runPromote([bad]);
			expect(result.status).toBe(1);
			expect(result.stderr).toContain('not a Worker version id');
		},
	);

	it('rejects a bad id supplied through the environment too', () => {
		const result = runPromote([], { [VERSION_ID_ENV]: 'latest' });
		expect(result.status).toBe(1);
		expect(result.stderr).toContain('not a Worker version id');
	});
});

describe('deploy-prod-promote: the cf argv', () => {
	it('promotes exactly the named version to 100% with the strategy cf requires live', () => {
		expect(buildPromoteArgv(VERSION_ID)).toEqual([
			'workers',
			'deployments',
			'create',
			'--worker',
			'bv-dns-security-mcp',
			'--strategy',
			'percentage',
			'--versions',
			`[{"version_id":"${VERSION_ID}","percentage":100}]`,
		]);
	});

	it('never carries the bypass flag and lower-cases the id into the JSON payload', () => {
		const argv = buildPromoteArgv(VERSION_ID.toUpperCase());
		expect(argv).not.toContain('--bypass-deployment-checks');
		expect(argv).not.toContain('--force');
		expect(argv.at(-1)).toContain(VERSION_ID);
	});

	it('prefers an argument over the environment, and falls back to the environment', () => {
		const other = '11111111-2222-4333-8444-555555555555';
		expect(resolveVersionId([VERSION_ID], { [VERSION_ID_ENV]: other })).toBe(VERSION_ID);
		expect(resolveVersionId([], { [VERSION_ID_ENV]: other })).toBe(other);
		expect(resolveVersionId([], {})).toBeNull();
	});

	it('targets the production Worker name that cloudflare.config.ts deploys', () => {
		const configSource = readFileSync(join(root, 'packages/bv-dns-security-mcp/cloudflare.config.ts'), 'utf8');
		expect(configSource).toContain(`export const PRODUCTION_WORKER_NAME = '${PRODUCTION_WORKER_NAME}';`);
	});
});

describe('deploy-prod-promote: end to end through a stand-in cf', () => {
	it('spawns the config package\'s own cf with the built argv from that package as the cwd', () => {
		// Copy the script into a temp tree shaped like the repo so its import.meta.url-relative cf path resolves to a
		// recording stand-in, never the real cf (this test must not touch the network or the production Worker).
		const tree = mkdtempSync(join(tmpdir(), 'bv-promote-'));
		try {
			mkdirSync(join(tree, 'scripts'), { recursive: true });
			mkdirSync(join(tree, 'packages/bv-dns-security-mcp/node_modules/.bin'), { recursive: true });
			writeFileSync(join(tree, 'scripts/deploy-prod-promote.mjs'), readFileSync(scriptPath, 'utf8'));
			const record = join(tree, 'record.json');
			const standIn = join(tree, 'packages/bv-dns-security-mcp/node_modules/.bin/cf');
			writeFileSync(
				standIn,
				`require('node:fs').writeFileSync(${JSON.stringify(record)}, JSON.stringify({ argv: process.argv.slice(2), cwd: process.cwd() }));`,
			);
			chmodSync(standIn, 0o755);
			const result = spawnSync(process.execPath, [join(tree, 'scripts/deploy-prod-promote.mjs'), VERSION_ID], {
				encoding: 'utf8',
				env: { PATH: process.env.PATH ?? '' },
			});
			expect(result.status, result.stderr).toBe(0);
			const seen = JSON.parse(readFileSync(record, 'utf8')) as { argv: string[]; cwd: string };
			expect(seen.argv).toEqual(buildPromoteArgv(VERSION_ID));
			// The temp tree sits behind macOS's /var -> /private/var symlink, which also pins that main() runs when argv[1] is a symlinked path.
			expect(seen.cwd.endsWith('packages/bv-dns-security-mcp')).toBe(true);
		} finally {
			rmSync(tree, { recursive: true, force: true });
		}
	});
});
