// SPDX-License-Identifier: BUSL-1.1

/**
 * Node-pool audit for the sidecar deploy-drift gate (#945).
 *
 * Two jobs:
 *
 * 1. Pin the CLI shell's process contract — it must issue a READ-ONLY
 *    `wrangler deployments list --json --config <path>` and nothing else, and a
 *    failed probe must block. The gate's value is entirely in what it refuses,
 *    so an argv drift that turned it into a no-op would be invisible otherwise.
 * 2. Prove `SIDECAR_TARGETS` is a true SSOT against the filesystem — every
 *    config exists, its `name` matches, and no tracked Wrangler config naming a
 *    non-main Worker is missing from the list. #945 happened because two
 *    Workers had deploy commands nothing invoked; a THIRD one added later must
 *    not be able to repeat that silently.
 *
 * Runs in the **Node** pool (registered in `scripts/vitest-node-suites.mjs`)
 * because it imports `scripts/ci/sidecar-deploy-drift-check.ts`, which imports
 * `node:child_process` — a hard SIGSEGV in the Workers pool. Importing it is
 * safe only because that file guards its `main()` behind an argv check.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';

import { parseJsonc } from '../../scripts/brand-audit-schema-preflight.mjs';
import { MAIN_WORKER_NAME, SIDECAR_TARGETS } from '../../scripts/sidecar-deploy-drift';
import { probeSidecar, runSidecarDriftCheck, WRANGLER_DEPLOYMENTS_ARGV } from '../../scripts/ci/sidecar-deploy-drift-check';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

const WHOIS = SIDECAR_TARGETS[0]!;

type SpawnCall = [string, string[], { encoding: 'utf8' }];

function fakeSpawn(handler: (command: string, args: string[]) => { status: number | null; stdout?: string; stderr?: string }) {
	return vi.fn((command: string, args: string[], _options: { encoding: 'utf8' }) => handler(command, args)) as unknown as ((
		...call: SpawnCall
	) => { status: number | null; stdout?: string; stderr?: string }) & { mock: { calls: SpawnCall[] } };
}

const OK_DEPLOYMENTS = JSON.stringify([{ id: 'v1', created_on: '2026-05-20T22:01:09.022895Z' }]);

describe('sidecar drift CLI — process contract', () => {
	it('issues exactly the read-only `wrangler deployments list --json --config <path>`', () => {
		const spawn = fakeSpawn((command) => ({
			status: 0,
			stdout: command === 'npx' ? OK_DEPLOYMENTS : '',
			stderr: '',
		}));

		probeSidecar(WHOIS, spawn);

		const [command, args] = spawn.mock.calls[0]!;
		expect(command).toBe('npx');
		expect(args).toEqual(['wrangler', 'deployments', 'list', '--json', '--config', WHOIS.configPath]);
		// Explicitly: nothing that mutates, and no name guessing. The Worker name
		// comes from the config, which is also what the deploy command uses, so
		// the read and the write can never disagree about which Worker this is.
		expect(args).not.toContain('deploy');
		expect(args).not.toContain('upload');
		expect(args).not.toContain('versions');
		expect(args).not.toContain('--name');
	});

	it('exports the argv prefix as data so it cannot drift silently', () => {
		expect([...WRANGLER_DEPLOYMENTS_ARGV]).toEqual(['wrangler', 'deployments', 'list', '--json', '--config']);
	});

	it('reads git history for the watched paths against HEAD, not origin/main', () => {
		// `deploy:prod` uploads the WORKING TREE, and check:deploy-freshness has
		// already proven HEAD ⊇ origin/main by the time this gate runs.
		const spawn = fakeSpawn((command) => ({ status: 0, stdout: command === 'npx' ? OK_DEPLOYMENTS : '', stderr: '' }));
		probeSidecar(WHOIS, spawn);

		const [command, args] = spawn.mock.calls[1]!;
		expect(command).toBe('git');
		expect(args[0]).toBe('log');
		expect(args).toContain('HEAD');
		expect(args).not.toContain('origin/main');
		expect(args.slice(args.indexOf('--') + 1)).toEqual(WHOIS.watchPaths);
	});

	it('a non-zero wrangler status BLOCKS — stdout is never parsed without it', () => {
		// With a bad token wrangler exits 1 but still prints ~199 bytes of auth
		// banner on STDOUT. Status is the only reliable signal.
		const spawn = fakeSpawn((command) =>
			command === 'npx'
				? {
						status: 1,
						stdout: '📎 It looks like you are authenticating Wrangler via a custom API token.',
						stderr: 'Authentication error [code: 10000]',
					}
				: { status: 0, stdout: '', stderr: '' },
		);

		const probe = probeSidecar(WHOIS, spawn);
		expect(probe.deployedAtMs).toBeNull();
		expect(probe.unverifiedReason).toMatch(/exited 1/);

		const verdict = runSidecarDriftCheck(spawn, {});
		expect(verdict.ok).toBe(false);
		expect(verdict.code).toBe('unverified');
	});

	it('a wrangler that will not launch BLOCKS', () => {
		const spawn = vi.fn((command: string) =>
			command === 'npx'
				? { status: null, stdout: '', stderr: '', error: new Error('spawn npx ENOENT') }
				: { status: 0, stdout: '', stderr: '' },
		) as never;
		const verdict = runSidecarDriftCheck(spawn, {});
		expect(verdict.ok).toBe(false);
		expect(verdict.code).toBe('unverified');
	});

	it('a failed `git log` BLOCKS rather than degrading to an empty commit list', () => {
		const spawn = fakeSpawn((command) =>
			command === 'npx'
				? { status: 0, stdout: OK_DEPLOYMENTS, stderr: '' }
				: { status: 128, stdout: '', stderr: 'fatal: not a git repository' },
		);
		const verdict = runSidecarDriftCheck(spawn, {});
		expect(verdict.ok).toBe(false);
		expect(verdict.code).toBe('unverified');
	});

	it('passes only when every sidecar probes clean, and honours the override env', () => {
		const clean = fakeSpawn((command) => ({ status: 0, stdout: command === 'npx' ? OK_DEPLOYMENTS : '', stderr: '' }));
		expect(runSidecarDriftCheck(clean, {}).code).toBe('fresh');

		const broken = fakeSpawn(() => ({ status: 1, stdout: '', stderr: 'nope' }));
		expect(runSidecarDriftCheck(broken, {}).ok).toBe(false);
		expect(runSidecarDriftCheck(broken, { BV_ALLOW_STALE_SIDECARS: '1' }).code).toBe('override');
		// The git-freshness override must NOT release this gate.
		expect(runSidecarDriftCheck(broken, { BV_ALLOW_STALE_DEPLOY: '1' }).ok).toBe(false);
	});
});

describe('SIDECAR_TARGETS is an SSOT against the filesystem', () => {
	function wranglerName(configPath: string): string | undefined {
		const config = parseJsonc(readFileSync(resolve(REPO_ROOT, configPath), 'utf8')) as { name?: unknown };
		return typeof config.name === 'string' ? config.name : undefined;
	}

	it('every target config exists and its `name` matches the declared worker', () => {
		for (const target of SIDECAR_TARGETS) {
			expect(existsSync(resolve(REPO_ROOT, target.configPath)), `${target.configPath} must exist`).toBe(true);
			expect(wranglerName(target.configPath), `${target.configPath} name must match ${target.worker}`).toBe(target.worker);
			for (const watched of target.watchPaths) {
				expect(existsSync(resolve(REPO_ROOT, watched)), `${target.worker} watches a path that does not exist: ${watched}`).toBe(true);
			}
		}
	});

	it('the main Worker name matches wrangler.jsonc and is NOT a sidecar', () => {
		expect(wranglerName('wrangler.jsonc')).toBe(MAIN_WORKER_NAME);
		expect(SIDECAR_TARGETS.map((t) => t.worker)).not.toContain(MAIN_WORKER_NAME);
	});

	it('covers EVERY tracked Wrangler config that names a non-main Worker', () => {
		// The whole defect class: a Worker with a deploy command that nothing
		// invokes. A third sidecar added later must fail here rather than quietly
		// rotting for three months like bv-whois did.
		const tracked = execFileSync('git', ['ls-files'], { cwd: REPO_ROOT, encoding: 'utf8' })
			.split('\n')
			.map((line) => line.trim())
			.filter((line) => /(^|\/)wrangler[\w.-]*\.jsonc$/.test(line));

		expect(tracked.length, 'git ls-files found no Wrangler configs — the filter is broken').toBeGreaterThan(1);

		const unmanaged = tracked.filter((path) => {
			const name = wranglerName(path);
			// Overlay/example fragments carry no `name` and are not deployable alone.
			if (name === undefined || name === MAIN_WORKER_NAME) return false;
			return !SIDECAR_TARGETS.some((target) => target.configPath === path);
		});

		expect(unmanaged, `add these Workers to SIDECAR_TARGETS in scripts/sidecar-deploy-drift.ts: ${unmanaged.join(', ')}`).toEqual([]);
	});
});
