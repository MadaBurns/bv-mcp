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
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';

import { parseJsonc } from '../../scripts/brand-audit-schema-preflight.mjs';
import { MAIN_WORKER_NAME, SIDECAR_TARGETS, type SidecarTarget } from '../../scripts/sidecar-deploy-drift';
import {
	isInvokedDirectly,
	probeSidecar,
	runSidecarDriftCheck,
	verifyHeadContainsUpstream,
	WRANGLER_DEPLOYMENTS_ARGV,
} from '../../scripts/ci/sidecar-deploy-drift-check';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

const WHOIS = SIDECAR_TARGETS[0]!;

type SpawnCall = [string, string[], { encoding: 'utf8' }];
type SpawnResult = { status: number | null; stdout?: string; stderr?: string; error?: Error; signal?: string };

function fakeSpawn(handler: (command: string, args: string[]) => SpawnResult) {
	return vi.fn((command: string, args: string[], _options: { encoding: 'utf8' }) => handler(command, args)) as unknown as ((
		...call: SpawnCall
	) => SpawnResult) & { mock: { calls: SpawnCall[] } };
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

	it('a wrangler call that times out BLOCKS and names the timeout (#SQ-25)', () => {
		const timeoutError = Object.assign(new Error('spawnSync npx ETIMEDOUT'), { code: 'ETIMEDOUT' });
		const spawn = fakeSpawn((command) =>
			command === 'npx' ? { status: null, stdout: '', stderr: '', error: timeoutError } : { status: 0, stdout: '', stderr: '' },
		);

		const probe = probeSidecar(WHOIS, spawn);
		expect(probe.deployedAtMs).toBeNull();
		expect(probe.unverifiedReason).toMatch(/timed out/);

		const verdict = runSidecarDriftCheck(spawn, {});
		expect(verdict.ok).toBe(false);
		expect(verdict.code).toBe('unverified');
	});

	it('a wrangler call killed with SIGTERM (timeout, no ETIMEDOUT error) still BLOCKS (#SQ-25)', () => {
		const spawn = fakeSpawn((command) =>
			command === 'npx' ? { status: null, stdout: '', stderr: '', signal: 'SIGTERM' } : { status: 0, stdout: '', stderr: '' },
		);

		const probe = probeSidecar(WHOIS, spawn);
		expect(probe.unverifiedReason).toMatch(/timed out/);
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

	it('reads git history with --first-parent, not a plain history-simplified log (#981 item 2)', () => {
		// This repo merges via merge commits. A plain `git log -- <path>` surfaces
		// the ORIGINAL side-branch commit (and its side-branch committer date), not
		// the merge that landed it on main — `--first-parent` is what fixes that
		// (see the real temp-repo reproduction below).
		const spawn = fakeSpawn((command) => ({ status: 0, stdout: command === 'npx' ? OK_DEPLOYMENTS : '', stderr: '' }));
		probeSidecar(WHOIS, spawn);

		const [command, args] = spawn.mock.calls[1]!;
		expect(command).toBe('git');
		expect(args[0]).toBe('log');
		expect(args).toContain('--first-parent');
	});
});

describe('verifyHeadContainsUpstream — HEAD ⊇ origin/main proof (#981 item 1)', () => {
	function fixedSpawn(overrides: { fetch?: SpawnResult; mergeBase?: SpawnResult } = {}) {
		return fakeSpawn((command, args) => {
			if (command === 'git' && args[0] === 'fetch') return overrides.fetch ?? { status: 0, stdout: '', stderr: '' };
			if (command === 'git' && args[0] === 'merge-base') return overrides.mergeBase ?? { status: 0, stdout: '', stderr: '' };
			return { status: 0, stdout: '', stderr: '' };
		});
	}

	it('proves HEAD ⊇ origin/main via `git merge-base --is-ancestor origin/main HEAD`', () => {
		const spawn = fixedSpawn();
		expect(verifyHeadContainsUpstream(spawn)).toBeNull();

		const mergeBaseCall = spawn.mock.calls.find(([command, args]) => command === 'git' && args[0] === 'merge-base');
		expect(mergeBaseCall?.[1]).toEqual(['merge-base', '--is-ancestor', 'origin/main', 'HEAD']);
	});

	it('BLOCKS when HEAD does not contain origin/main (exit 1 from --is-ancestor)', () => {
		const spawn = fixedSpawn({ mergeBase: { status: 1, stdout: '', stderr: '' } });
		expect(verifyHeadContainsUpstream(spawn)).toMatch(/does not contain origin\/main/);
	});

	it('BLOCKS when the upstream fetch fails', () => {
		const spawn = fixedSpawn({ fetch: { status: 128, stdout: '', stderr: 'could not resolve host' } });
		expect(verifyHeadContainsUpstream(spawn)).toMatch(/could not fetch origin\/main/);
	});

	it('BLOCKS and names the timeout when `git fetch` times out (#SQ-25)', () => {
		const timeoutError = Object.assign(new Error('spawnSync git ETIMEDOUT'), { code: 'ETIMEDOUT' });
		const spawn = fixedSpawn({ fetch: { status: null, stdout: '', stderr: '', error: timeoutError } });
		expect(verifyHeadContainsUpstream(spawn)).toMatch(/git fetch origin\/main.*timed out/);
	});

	it('BLOCKS and names the timeout when `git merge-base` times out, even with no error object (#SQ-25)', () => {
		const spawn = fixedSpawn({ mergeBase: { status: null, stdout: '', stderr: '', signal: 'SIGTERM' } });
		expect(verifyHeadContainsUpstream(spawn)).toMatch(/merge-base.*timed out/);
	});

	it('BLOCKS on an unexpected merge-base exit status rather than guessing', () => {
		const spawn = fixedSpawn({ mergeBase: { status: 128, stdout: '', stderr: 'fatal: not a valid object name' } });
		expect(verifyHeadContainsUpstream(spawn)).toMatch(/exited 128/);
	});

	// The exact fail-open path #981 item 1 reports: BV_ALLOW_STALE_DEPLOY=1 makes
	// `assessDeployFreshness` return ok:true WITHOUT proving HEAD ⊇ origin/main
	// (scripts/deploy-freshness.ts). This sidecar gate must not inherit that hole
	// by trusting the freshness gate ran (or ran honestly) — it proves the same
	// precondition itself, and BV_ALLOW_STALE_DEPLOY must have no effect on it.
	it('a checkout behind origin/main BLOCKS the sidecar gate even under BV_ALLOW_STALE_DEPLOY=1', () => {
		const spawn = fakeSpawn((command, args) => {
			if (command === 'git' && args[0] === 'fetch') return { status: 0, stdout: '', stderr: '' };
			if (command === 'git' && args[0] === 'merge-base') return { status: 1, stdout: '', stderr: '' }; // HEAD behind
			if (command === 'npx') return { status: 0, stdout: OK_DEPLOYMENTS, stderr: '' };
			return { status: 0, stdout: '', stderr: '' }; // git log: no drift visible from a stale HEAD
		});

		const verdict = runSidecarDriftCheck(spawn, { BV_ALLOW_STALE_DEPLOY: '1' });
		expect(verdict.ok).toBe(false);
		expect(verdict.code).toBe('unverified');
	});

	it('BV_ALLOW_STALE_SIDECARS still releases the gate even when HEAD is unproven', () => {
		// The one sanctioned bypass for THIS gate stays effective — only the
		// git-freshness override (BV_ALLOW_STALE_DEPLOY) must not reach it.
		const spawn = fakeSpawn((command, args) => {
			if (command === 'git' && args[0] === 'merge-base') return { status: 1, stdout: '', stderr: '' };
			if (command === 'npx') return { status: 0, stdout: OK_DEPLOYMENTS, stderr: '' };
			return { status: 0, stdout: '', stderr: '' };
		});
		expect(runSidecarDriftCheck(spawn, { BV_ALLOW_STALE_SIDECARS: '1' }).code).toBe('override');
	});

	it("a probe's own failure reason is reported over the shared HEAD-ancestry reason", () => {
		const spawn = fakeSpawn((command, args) => {
			if (command === 'git' && args[0] === 'merge-base') return { status: 1, stdout: '', stderr: '' };
			if (command === 'npx') return { status: 1, stdout: '', stderr: 'Authentication error [code: 10000]' };
			return { status: 0, stdout: '', stderr: '' };
		});
		const verdict = runSidecarDriftCheck(spawn, {});
		expect(verdict.ok).toBe(false);
		expect(verdict.message).toMatch(/exited 1/);
	});
});

describe('probeSidecar uses the merge date, not the side-branch committer date (#981 item 2 — real git repo)', () => {
	// Reproduces the exact shape measured in the issue: 9c170b0d (#526) carries a
	// side-branch committer date of 2026-07-20, four days before it actually
	// merged on 2026-07-24. A sidecar deployed in that four-day window must see
	// this as drift — the change reached main AFTER the deployment — even though
	// the original commit predates it.
	it('flags drift when the MERGE landed after the deployment, even though the side-branch commit predates it', () => {
		const repo = mkdtempSync(join(tmpdir(), 'sq981-first-parent-'));
		const prevCwd = process.cwd();
		const run = (args: string[], env?: Record<string, string>) =>
			execFileSync('git', args, { cwd: repo, encoding: 'utf8', env: { ...process.env, ...env } });

		try {
			run(['init', '-q']);
			run(['config', 'user.email', 'test@example.com']);
			run(['config', 'user.name', 'Test']);
			run(['checkout', '-q', '-b', 'main']);
			writeFileSync(join(repo, 'watched.txt'), 'base\n');
			run(['add', 'watched.txt']);
			run(['commit', '-q', '-m', 'base'], { GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z' });

			run(['checkout', '-q', '-b', 'feature']);
			writeFileSync(join(repo, 'watched.txt'), 'feature-change\n');
			run(['add', 'watched.txt']);
			// Side-branch date: BEFORE the sidecar's deployment.
			run(['commit', '-q', '-m', 'fix(rdap): surface WHOIS dates (#526)'], {
				GIT_AUTHOR_DATE: '2026-07-20T15:17:39+12:00',
				GIT_COMMITTER_DATE: '2026-07-20T15:17:39+12:00',
			});

			run(['checkout', '-q', 'main']);
			// Merge date: AFTER the sidecar's deployment — when the change actually
			// reached main and became eligible to ship.
			run(['merge', '--no-ff', '-q', '-m', 'Merge feature', 'feature'], {
				GIT_AUTHOR_DATE: '2026-07-24T09:00:00+12:00',
				GIT_COMMITTER_DATE: '2026-07-24T09:00:00+12:00',
			});

			process.chdir(repo);

			const target: SidecarTarget = {
				worker: 'fixture-sidecar',
				configPath: 'fixture.jsonc',
				watchPaths: ['watched.txt'],
				deployCommand: 'npm run deploy:fixture',
			};
			// Deployed BETWEEN the two dates — the exact #526 shape.
			const deployedAt = '2026-07-22T00:00:00+12:00';
			const spawn = fakeSpawn((command, args) => {
				if (command === 'npx') return { status: 0, stdout: JSON.stringify([{ created_on: deployedAt }]), stderr: '' };
				try {
					return { status: 0, stdout: execFileSync(command, args, { cwd: repo, encoding: 'utf8' }), stderr: '' };
				} catch (error) {
					const e = error as { status?: number | null; stdout?: string; stderr?: string };
					return { status: e.status ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
				}
			});

			const probe = probeSidecar(target, spawn);
			expect(probe.unverifiedReason).toBeNull();
			// This is the regression: on current main (no `--first-parent`), `git log`
			// surfaces the side-branch commit dated 2026-07-20 — BEFORE the 07-22
			// deployment — so `selectCommitsAfter` would drop it and report `fresh`,
			// exactly the false-clean signal #981 item 2 describes.
			expect(probe.driftCommits).toHaveLength(1);
			expect(probe.driftCommits[0]).toContain('Merge feature');
		} finally {
			process.chdir(prevCwd);
			rmSync(repo, { recursive: true, force: true });
		}
	});
});

describe('isInvokedDirectly — argv guard resists a symlinked invocation path (#981 item 4)', () => {
	const MODULE_URL = 'file:///repo/scripts/ci/sidecar-deploy-drift-check.ts';
	const REAL_PATH = fileURLToPath(MODULE_URL);

	it('treats a symlinked argv[1] as the entrypoint once realpathed to the module path', () => {
		const symlinkArgv = '/repo/.worktrees/agent-x/scripts/ci/sidecar-deploy-drift-check.ts';
		const fakeRealpath = (p: string) => (p === symlinkArgv ? REAL_PATH : p);
		expect(isInvokedDirectly(symlinkArgv, MODULE_URL, fakeRealpath)).toBe(true);
	});

	it('a plain resolve() would NOT have caught this — the exact #981 item 4 bug', () => {
		// `resolve()` normalizes but never follows symlinks, so a checkout reached
		// through a symlinked path component left it disagreeing with
		// `fileURLToPath(import.meta.url)` forever, and the guard silently no-op'd.
		const symlinkArgv = '/repo/.worktrees/agent-x/scripts/ci/sidecar-deploy-drift-check.ts';
		expect(resolve(symlinkArgv)).not.toBe(REAL_PATH);
	});

	it('returns false when argv1 is absent', () => {
		expect(isInvokedDirectly(undefined, MODULE_URL, () => REAL_PATH)).toBe(false);
	});

	it('returns false for a genuine non-entrypoint import', () => {
		const otherArgv = '/repo/test/audits/sidecar-deploy-drift-check.node.test.ts';
		const fakeRealpath = (p: string) => p;
		expect(isInvokedDirectly(otherArgv, MODULE_URL, fakeRealpath)).toBe(false);
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
