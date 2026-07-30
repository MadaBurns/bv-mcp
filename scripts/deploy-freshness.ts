// SPDX-License-Identifier: BUSL-1.1

/**
 * Deploy-freshness decision core.
 *
 * `npm run deploy:prod` uploads whatever is in the WORKING TREE. Nothing ties
 * that to the remote: `gh pr merge` moves a ref on GitHub and never touches
 * this checkout, so "merged" and "deployed" share no machinery at all. A deploy
 * run from a checkout that is behind `origin/main` therefore ships code that
 * predates the merge — and every local signal still reports success (exit 0, a
 * fresh version id, a full binding table). The only thing that contradicts it is
 * querying the live endpoint afterwards.
 *
 * That happened on 2026-07-27: #579, #580 and #583 were merged, `deploy:prod`
 * ran green and minted version cf9c5834, and the live tool kept serving the
 * exact payload #583 was written to remove. Nothing was lost only because the
 * stale tree happened to match what was already deployed; had the previous
 * deploy been newer, this would have silently REVERTED production.
 *
 * This module is deliberately PURE — no `node:*` imports, not even a lazy one.
 * The verdict logic is unit-tested from `test/deploy-freshness.spec.ts`, which
 * runs in the default Workers pool where `node:child_process` is not real and
 * importing it is a hard SIGSEGV rather than a catchable error (see the exclude
 * block in `vitest.config.mts`). All git I/O lives in the sibling CLI,
 * `scripts/ci/deploy-freshness-check.ts`, which nothing under `test/` imports.
 */

export interface FreshnessInput {
	/** Commit subjects present on the upstream ref but missing from HEAD, newest first. */
	missingCommits: string[];
	/**
	 * True when the upstream ref could not be refreshed (offline, auth failure,
	 * no `origin` remote). A stale local `origin/main` makes the comparison
	 * meaningless — it was itself out of date during the 2026-07-27 incident —
	 * so an unrefreshable upstream is treated as UNPROVEN, never as fresh.
	 */
	upstreamUnverified: boolean;
	/** Operator override for a deliberate rollback or older-commit hotfix. */
	allowStale: boolean;
}

export type FreshnessCode = 'fresh' | 'stale' | 'unverified' | 'override';

export interface FreshnessVerdict {
	/** False means: do not deploy. The CLI exits non-zero. */
	ok: boolean;
	code: FreshnessCode;
	message: string;
}

const OVERRIDE_ENV = 'BV_ALLOW_STALE_DEPLOY';

/**
 * Decide whether this checkout may be deployed.
 *
 * Fail-CLOSED by construction: the only paths that return `ok: true` are a
 * proven-fresh tree and an explicit operator override. Anything we cannot
 * verify blocks, because the failure this gate exists to catch is invisible
 * downstream — a stale deploy looks identical to a good one until someone
 * queries production.
 */
export function assessDeployFreshness(input: FreshnessInput): FreshnessVerdict {
	const { missingCommits, upstreamUnverified, allowStale } = input;

	// Checked FIRST so the escape hatch also covers an unverifiable upstream —
	// an operator deploying offline, or rolling back deliberately, must not be
	// stranded by a gate that cannot reach the remote.
	if (allowStale) {
		const reason = upstreamUnverified
			? 'upstream could not be verified'
			: missingCommits.length > 0
				? `${missingCommits.length} commit(s) missing from HEAD`
				: 'tree is already fresh';
		return {
			ok: true,
			code: 'override',
			message: `${OVERRIDE_ENV}=1 — freshness check bypassed (${reason}). Deploying this working tree as-is.`,
		};
	}

	if (upstreamUnverified) {
		return {
			ok: false,
			code: 'unverified',
			message: [
				'DEPLOY BLOCKED — could not verify this checkout against the remote.',
				'',
				'`git fetch` failed, so `origin/main` here may be out of date and the',
				'freshness comparison would be meaningless. This gate does not guess:',
				'an unprovable tree is treated as stale.',
				'',
				'Fix: restore network/auth access and retry.',
				`Deliberate offline deploy: ${OVERRIDE_ENV}=1 npm run deploy:prod`,
			].join('\n'),
		};
	}

	if (missingCommits.length > 0) {
		const listed = missingCommits.map((line) => `  ${line}`).join('\n');
		return {
			ok: false,
			code: 'stale',
			message: [
				`DEPLOY BLOCKED — this checkout is ${missingCommits.length} commit(s) behind origin/main.`,
				'',
				'`deploy:prod` uploads the WORKING TREE, not origin/main. Merging a PR',
				'with `gh` does not update this checkout, so deploying now would ship',
				'code that predates those merges — and would REVERT them on the live',
				'Worker if a newer version is already deployed.',
				'',
				'Missing from HEAD:',
				listed,
				'',
				'Fix: git pull --ff-only',
				`Deliberate rollback to an older commit: ${OVERRIDE_ENV}=1 npm run deploy:prod`,
			].join('\n'),
		};
	}

	return {
		ok: true,
		code: 'fresh',
		message: 'Deploy freshness OK — HEAD contains every commit on origin/main.',
	};
}

/**
 * Parse `git log --oneline HEAD..<upstream>` output into commit subjects.
 *
 * Split out so the CLI stays a thin shell and this stays testable: an empty or
 * whitespace-only body means "nothing missing", which is the single most
 * important case to get right — misreading it as one blank entry would block
 * every deploy from a perfectly fresh tree.
 */
export function parseMissingCommits(gitLogStdout: string): string[] {
	return gitLogStdout
		.split('\n')
		.map((line) => line.trim())
		.filter((line) => line.length > 0);
}
