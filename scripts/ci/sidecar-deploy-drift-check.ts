// SPDX-License-Identifier: BUSL-1.1

/**
 * Sidecar deploy-drift gate — CLI shell (#945).
 *
 * Runs immediately after `check:deploy-freshness` in `deploy:prod` /
 * `deploy:prod:staged` and exits non-zero when a sidecar Worker's live
 * deployment predates its source. Placed early on purpose: it costs ~2 s per
 * target and must fail BEFORE the dns-checks build, not after it.
 *
 * All decision logic lives in the pure `scripts/sidecar-deploy-drift.ts` so it
 * can be unit-tested in the Workers pool; this file is the untestable half on
 * purpose — it exists only to turn wrangler and git into that module's inputs.
 * `node:child_process` is imported here and MUST NOT become reachable from any
 * WORKERS-pool test (it is a hard SIGSEGV there). The one test that imports
 * this file, `test/audits/sidecar-deploy-drift-check.node.test.ts`, is
 * registered in `scripts/vitest-node-suites.mjs` and therefore runs in the Node
 * pool; nothing calls `main()` on import, which is what keeps that safe.
 */

import { spawnSync as nodeSpawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import {
	assessSidecarDrift,
	parseNewestDeployment,
	selectCommitsAfter,
	SIDECAR_OVERRIDE_ENV,
	SIDECAR_TARGETS,
	type SidecarDriftVerdict,
	type SidecarProbe,
	type SidecarTarget,
} from '../sidecar-deploy-drift';

/**
 * The read-only wrangler invocation, as data so the audit can assert it
 * verbatim. It must stay a `deployments list` — no `deploy`, no `versions`,
 * and no `--name` guessing (the Worker name comes from the config, which is
 * also what the deploy commands use, so the two can never disagree).
 */
export const WRANGLER_DEPLOYMENTS_ARGV = ['wrangler', 'deployments', 'list', '--json', '--config'] as const;

/** `git log` format: `<sha>\t<committer date ISO>\t<subject>`; `%x09` is a literal tab. */
export const GIT_LOG_FORMAT = '--format=%H%x09%cI%x09%s';

type SpawnSyncLike = (
	command: string,
	args: string[],
	options: { encoding: 'utf8' },
) => { status: number | null; stdout?: string | null; stderr?: string | null; error?: Error };

function firstStderrLine(stderr: string | null | undefined): string {
	return (stderr ?? '').trim().split('\n')[0]?.trim() || 'no stderr';
}

/**
 * Measure one sidecar. Never throws: every failure is folded into
 * `unverifiedReason`, which `assessSidecarDrift` maps to a BLOCK.
 */
export function probeSidecar(target: SidecarTarget, spawnSync: SpawnSyncLike = nodeSpawnSync as SpawnSyncLike): SidecarProbe {
	let deployedAtMs: number | null = null;
	let unverifiedReason: string | null = null;

	const listed = spawnSync('npx', [...WRANGLER_DEPLOYMENTS_ARGV, target.configPath], { encoding: 'utf8' });
	if (listed.error) {
		unverifiedReason = `could not launch wrangler: ${listed.error.message}`;
	} else if (listed.status !== 0) {
		// Exit status is the reliable signal — stdout carries an auth banner even
		// on failure, so it must never be parsed without this check.
		unverifiedReason = `\`wrangler deployments list\` exited ${listed.status ?? 'with no status'}: ${firstStderrLine(listed.stderr)}`;
	} else {
		try {
			deployedAtMs = parseNewestDeployment(listed.stdout ?? '');
		} catch (error) {
			unverifiedReason = error instanceof Error ? error.message : String(error);
		}
	}

	// Compare against HEAD, not origin/main. `deploy:prod` uploads the WORKING
	// TREE, and `check:deploy-freshness` has already proven HEAD ⊇ origin/main by
	// the time this runs — so HEAD is both the thing being shipped and the
	// stricter comparison.
	let driftCommits: string[] = [];
	const log = spawnSync('git', ['log', GIT_LOG_FORMAT, 'HEAD', '--', ...target.watchPaths], { encoding: 'utf8' });
	if (log.error || log.status !== 0) {
		// A failed `git log` is not evidence of freshness — degrade to unverified
		// rather than to an empty commit list.
		unverifiedReason ??= `\`git log\` failed for ${target.watchPaths.join(', ')}: ${log.error ? log.error.message : firstStderrLine(log.stderr)}`;
	} else if (deployedAtMs !== null) {
		try {
			driftCommits = selectCommitsAfter((log.stdout ?? '').split('\n'), deployedAtMs);
		} catch (error) {
			unverifiedReason ??= error instanceof Error ? error.message : String(error);
		}
	}

	return { target, deployedAtMs, driftCommits, unverifiedReason };
}

export function runSidecarDriftCheck(
	spawnSync: SpawnSyncLike = nodeSpawnSync as SpawnSyncLike,
	env: NodeJS.ProcessEnv = process.env,
): SidecarDriftVerdict {
	const probes = SIDECAR_TARGETS.map((target) => probeSidecar(target, spawnSync));
	return assessSidecarDrift(probes, env[SIDECAR_OVERRIDE_ENV] === '1');
}

function main(): void {
	const verdict = runSidecarDriftCheck();
	if (!verdict.ok) {
		console.error(`\n${verdict.message}\n`);
		process.exit(1);
	}
	console.log(verdict.message);
}

// Guarded so the Node-pool audit can import `probeSidecar` without running the
// real gate (and without shelling out to wrangler) as an import side effect.
const invoked = process.argv[1] ? resolve(process.argv[1]) : '';
if (invoked === fileURLToPath(import.meta.url)) main();
