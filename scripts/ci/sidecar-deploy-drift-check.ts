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
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
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

const UPSTREAM = 'origin/main';

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
	// TREE, so HEAD is the thing being shipped. `runSidecarDriftCheck` proves
	// HEAD ⊇ origin/main itself (`verifyHeadContainsUpstream`, #981 item 1) —
	// `git log HEAD` can only see commits that are ANCESTORS of HEAD, so on a
	// checkout behind origin/main a sidecar commit that landed upstream but not
	// locally would otherwise be invisible: the drift list comes back empty and
	// this gate reports `fresh`, a false green in a gate that exists to be
	// fail-closed. `check:deploy-freshness` running first on all three doors
	// (`test/audits/deploy-pipeline.audit.test.ts`) is belt-and-suspenders, not
	// the only proof — `BV_ALLOW_STALE_DEPLOY=1` deliberately skips that gate's
	// own proof, so this probe cannot depend on a caller having run it.
	//
	// `--first-parent` matters as much as `HEAD` does (#981 item 2): this repo
	// merges via merge commits, so a plain `git log -- <path>` history
	// simplification surfaces the ORIGINAL side-branch commit — keeping its
	// side-branch committer date — not the merge that landed it on main.
	// Measured in-repo: 9c170b0d (#526) carries a committer date four days
	// before it actually merged. A sidecar deployed in that four-day window
	// would filter #526 out as "already deployed" and the drift would be
	// permanently invisible. `--first-parent` walks the mainline only, so a
	// squashed commit keeps its own (correct) date and a merged branch is
	// represented by the merge commit, whose committer date is when it reached
	// main — which is what "deployed after this" must be measured against.
	let driftCommits: string[] = [];
	const log = spawnSync('git', ['log', '--first-parent', GIT_LOG_FORMAT, 'HEAD', '--', ...target.watchPaths], { encoding: 'utf8' });
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

/**
 * Prove HEAD ⊇ origin/main before trusting `git log HEAD -- <watchPaths>` as
 * evidence of "no drift" (#981 item 1).
 *
 * `probeSidecar`'s `git log HEAD` can only see commits that are ANCESTORS of
 * HEAD, so on a checkout behind origin/main a sidecar commit that landed
 * upstream but not locally is invisible — the drift list comes back empty and
 * the gate reports `fresh`. `check:deploy-freshness` proves this precondition
 * on every real deploy door, EXCEPT that `BV_ALLOW_STALE_DEPLOY=1` makes that
 * gate return `ok: true` without ever proving it, for a deliberate rollback.
 * That override does not — and must not — apply here: a rollback that skips
 * the freshness proof still needs this gate to notice a stale sidecar. So this
 * gate proves the precondition itself rather than trusting a caller to have
 * run something else first.
 *
 * Returns `null` when proven; a reason string means the git evidence below is
 * unverified and every probe must BLOCK.
 */
export function verifyHeadContainsUpstream(spawnSync: SpawnSyncLike = nodeSpawnSync as SpawnSyncLike): string | null {
	const fetched = spawnSync('git', ['fetch', 'origin', 'main', '--quiet'], { encoding: 'utf8' });
	if (fetched.error || fetched.status !== 0) {
		return `could not fetch ${UPSTREAM}: ${fetched.error ? fetched.error.message : firstStderrLine(fetched.stderr)}`;
	}

	const mergeBase = spawnSync('git', ['merge-base', '--is-ancestor', UPSTREAM, 'HEAD'], { encoding: 'utf8' });
	if (mergeBase.error) {
		return `could not verify HEAD contains ${UPSTREAM}: ${mergeBase.error.message}`;
	}
	// `--is-ancestor` uses its exit code as the answer: 0 = yes, 1 = no. Any
	// other status (128 = no such ref, detached weirdness) is not evidence
	// either way.
	if (mergeBase.status === 1) {
		return `HEAD does not contain ${UPSTREAM} — the git-log drift evidence above is unreliable on a checkout behind the remote`;
	}
	if (mergeBase.status !== 0) {
		return `\`git merge-base --is-ancestor\` exited ${mergeBase.status ?? 'with no status'}: ${firstStderrLine(mergeBase.stderr)}`;
	}
	return null;
}

export function runSidecarDriftCheck(
	spawnSync: SpawnSyncLike = nodeSpawnSync as SpawnSyncLike,
	env: NodeJS.ProcessEnv = process.env,
): SidecarDriftVerdict {
	// Checked ONCE, before probing any sidecar, rather than inside
	// `probeSidecar` per target — the proof is the same for every target and
	// probing it twice would double the `git fetch` cost for no added signal.
	const headReason = verifyHeadContainsUpstream(spawnSync);
	const probes = SIDECAR_TARGETS.map((target) => {
		const probe = probeSidecar(target, spawnSync);
		// A probe's own unverifiedReason (bad wrangler token, failed git log)
		// always wins over the shared precondition failure — it is more specific.
		return headReason ? { ...probe, unverifiedReason: probe.unverifiedReason ?? headReason } : probe;
	});
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

/**
 * True when this file was invoked as the CLI entrypoint, not merely imported
 * (the Node-pool audit test imports `probeSidecar`/`runSidecarDriftCheck`
 * without running the real gate, which depends on this staying accurate).
 *
 * `resolve()` does NOT resolve symlinks, but the ESM loader realpaths
 * `import.meta.url` before handing it to the module (#981 item 4) — so a
 * checkout reached through a symlinked path component made
 * `resolve(process.argv[1])` disagree with `fileURLToPath(import.meta.url)`
 * and this guard silently no-op'd, exiting 0 without ever probing a sidecar.
 * `realpathSync` matches what the loader already did to `import.meta.url`.
 */
export function isInvokedDirectly(
	argv1: string | undefined,
	moduleUrl: string,
	realpath: (path: string) => string = realpathSync,
): boolean {
	if (!argv1) return false;
	return realpath(argv1) === fileURLToPath(moduleUrl);
}

// Guarded so the Node-pool audit can import `probeSidecar` without running the
// real gate (and without shelling out to wrangler) as an import side effect.
if (isInvokedDirectly(process.argv[1], import.meta.url)) main();
