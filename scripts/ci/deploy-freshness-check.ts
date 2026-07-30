// SPDX-License-Identifier: BUSL-1.1

/**
 * Deploy-freshness gate — CLI shell.
 *
 * Runs as the FIRST step of `npm run deploy:prod` and exits non-zero when this
 * checkout is behind `origin/main`, because `deploy:prod` uploads the working
 * tree and nothing otherwise connects a merged PR to a deployed Worker.
 *
 * All decision logic lives in the pure `scripts/deploy-freshness.ts` so it can
 * be unit-tested in the Workers pool; this file is the untestable half on
 * purpose — it exists only to turn git into that module's inputs. Keep it thin.
 * `node:child_process` is imported here and MUST NOT become reachable from
 * anything under `test/` (it is a hard SIGSEGV in the Workers pool).
 */

import { spawnSync } from 'node:child_process';
import { assessDeployFreshness, parseMissingCommits } from '../deploy-freshness';

const UPSTREAM = 'origin/main';

function git(args: string[]): { ok: boolean; stdout: string } {
	const res = spawnSync('git', args, { encoding: 'utf8' });
	return { ok: res.status === 0, stdout: res.stdout ?? '' };
}

function main(): void {
	// Refresh the upstream ref before comparing. Skipping this is what made the
	// 2026-07-27 incident invisible: the local `origin/main` was itself three
	// commits stale, so a comparison against it would have reported "fresh".
	const fetched = git(['fetch', 'origin', 'main', '--quiet']);

	let missingCommits: string[] = [];
	let upstreamUnverified = !fetched.ok;

	if (!upstreamUnverified) {
		const log = git(['log', '--oneline', `HEAD..${UPSTREAM}`]);
		// A failed `git log` (no such ref, not a repo, detached weirdness) is not
		// evidence of freshness — degrade to unverified rather than to empty.
		if (log.ok) missingCommits = parseMissingCommits(log.stdout);
		else upstreamUnverified = true;
	}

	const verdict = assessDeployFreshness({
		missingCommits,
		upstreamUnverified,
		allowStale: process.env.BV_ALLOW_STALE_DEPLOY === '1',
	});

	if (!verdict.ok) {
		console.error(`\n${verdict.message}\n`);
		process.exit(1);
	}

	console.log(verdict.message);
}

main();
