// SPDX-License-Identifier: BUSL-1.1

/**
 * Release-integrity decision core (issue #720).
 *
 * Both shipping commands take their input from the WORKING TREE and neither
 * validates it against the tag being released:
 *
 *   - `npm run deploy:prod` compiles the tree (`npm -w packages/dns-checks run build`).
 *   - `mcp-publisher publish` reads `./server.json` from the CURRENT DIRECTORY.
 *
 * Run from a long-lived or shared checkout, either ships whatever that tree
 * happens to hold. That has already produced a wrong-version publish attempt,
 * which failed only because the version already existed on the registry — a
 * tree holding an UNPUBLISHED version would have succeeded, silently and
 * publicly. CLAUDE.md documents running both from a worktree pinned to the
 * release commit, but that is convention; this module is the enforcement.
 *
 * Relationship to `publish.yml`'s `version-bump` job: that gate checks the SAME
 * four version surfaces against the tag, but it runs on GitHub after a tag
 * push, over a checkout that IS the tag by construction. It therefore cannot
 * see either failure this module exists to catch — a dirty tree, and a HEAD
 * that is not the tag — because neither can exist in its environment. This is
 * the local counterpart, deliberately mirroring the workflow's surface list and
 * its CHANGELOG heading test so the two cannot drift into disagreeing about
 * what "version 3.55.0" means. `expectVersion` + `skipGit` exist so the
 * workflow could later call this script instead of keeping its own copy.
 *
 * This module is deliberately PURE — no `node:*` imports, not even a lazy one.
 * It is unit-tested from `test/release-integrity.spec.ts`, which runs in the
 * default Workers pool where importing `node:child_process` is a hard SIGSEGV
 * rather than a catchable error. All git/fs I/O lives in the sibling CLI,
 * `scripts/ci/release-integrity-check.ts`, which nothing under `test/` imports.
 */

/** The four version surfaces CLAUDE.md and `publish.yml` both treat as the release contract. */
export interface VersionSurfaces {
	/** `version` in the root package.json — the source of truth. */
	packageJson: string | null;
	/** `version` in package-lock.json. */
	packageLock: string | null;
	/** Top-level `version` in server.json. */
	serverJson: string | null;
	/**
	 * `packages[0].version` in server.json. `server.json` is currently
	 * remotes-only so this is normally null; if an npm `packages` stanza is ever
	 * re-added it carries its own version that must match too — the same
	 * conditional check `publish.yml` performs.
	 */
	serverJsonPackage: string | null;
	/** Every `## [X.Y.Z]` heading token found in CHANGELOG.md, in file order. */
	changelogHeadings: string[];
}

export type ReleaseMode = 'deploy' | 'publish';

export interface ReleaseIntegrityInput {
	/**
	 * `deploy` gates `npm run deploy:prod`; `publish` gates the registry/npm
	 * publish. The mode changes ONLY whether the override is honoured — see
	 * `allowUnpinned`.
	 */
	mode: ReleaseMode;
	/** Trimmed `git describe --tags --exact-match`; null when HEAD is not exactly at a tag. */
	exactTag: string | null;
	/** Repo-wide `git status --porcelain`; '' when clean. */
	porcelain: string;
	/** True when git could not be consulted at all (not a repo, git missing, command failed). */
	gitUnavailable: boolean;
	versions: VersionSurfaces;
	/** Operator override, from the environment. Honoured in `deploy` mode only. */
	allowUnpinned: boolean;
	/**
	 * Expected version supplied explicitly instead of derived from the tag.
	 * Used by `skipGit` callers (CI, where the tag is already known).
	 */
	expectVersion?: string | null;
	/**
	 * Skip the git-derived checks (tag + cleanliness) and verify only that the
	 * version surfaces agree with `expectVersion`. This is the shape
	 * `publish.yml`'s `version-bump` job needs; it is NOT a bypass, because
	 * `expectVersion` becomes mandatory when it is set.
	 */
	skipGit?: boolean;
}

export type ReleaseIntegrityCode =
	| 'ok'
	| 'override'
	| 'blocked'
	| 'misconfigured';

export interface ReleaseIntegrityVerdict {
	/** False means: do not deploy, do not publish. The CLI exits non-zero. */
	ok: boolean;
	code: ReleaseIntegrityCode;
	/** The version this release was judged against; null when it could not be established. */
	version: string | null;
	/** One human-readable line per failed condition. Empty when everything passed. */
	violations: string[];
	message: string;
}

const OVERRIDE_ENV = 'BV_ALLOW_UNPINNED_DEPLOY';

/** `v3.55.0`, `v3.55.0-rc.1`. Anything else is not a release tag we can derive a version from. */
const RELEASE_TAG_RE = /^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/;

/**
 * Strip a leading `v` from a release tag.
 *
 * Exported for the CLI and for tests: getting this wrong in either direction
 * (leaving the `v` on, or stripping a leading character from a bare version)
 * would make every surface comparison fail and block every legitimate release.
 */
export function versionFromTag(tag: string): string | null {
	const m = RELEASE_TAG_RE.exec(tag.trim());
	return m ? m[1] : null;
}

/**
 * Parse `## [X.Y.Z]` headings out of a CHANGELOG body.
 *
 * Mirrors `publish.yml`'s `grep -q "^## \[$VERSION\]"`. Kept as a parser rather
 * than a per-version predicate so the pure core stays data-in/data-out.
 */
export function parseChangelogHeadings(changelog: string): string[] {
	const out: string[] = [];
	const re = /^## \[([^\]]+)\]/gm;
	let m: RegExpExecArray | null;
	while ((m = re.exec(changelog)) !== null) out.push(m[1]);
	return out;
}

function collectSurfaceViolations(versions: VersionSurfaces, version: string): string[] {
	const violations: string[] = [];
	const named: Array<[string, string | null]> = [
		['package.json', versions.packageJson],
		['package-lock.json', versions.packageLock],
		['server.json', versions.serverJson],
	];
	for (const [label, actual] of named) {
		if (actual === null) violations.push(`${label}: version could not be read`);
		else if (actual !== version) violations.push(`${label}: is ${actual}, expected ${version}`);
	}
	// Conditional, exactly as in publish.yml: only enforced when the stanza exists.
	if (versions.serverJsonPackage !== null && versions.serverJsonPackage !== version) {
		violations.push(`server.json packages[0].version: is ${versions.serverJsonPackage}, expected ${version}`);
	}
	if (!versions.changelogHeadings.includes(version)) {
		violations.push(`CHANGELOG.md: no "## [${version}]" heading`);
	}
	return violations;
}

function renderBlocked(mode: ReleaseMode, violations: string[], overrideRequested: boolean): string {
	const what = mode === 'deploy' ? 'DEPLOY' : 'PUBLISH';
	const lines = [
		`${what} BLOCKED — this working tree does not match a released version.`,
		'',
		`${mode === 'deploy' ? '`deploy:prod` compiles the WORKING TREE' : '`mcp-publisher` reads ./server.json from the WORKING TREE'}`,
		'and nothing else connects it to the tag being released. Shipping from a',
		'stale or dirty checkout ships whatever this tree happens to hold.',
		'',
		'Failed checks:',
		...violations.map((v) => `  - ${v}`),
		'',
		'Fix: run this from a worktree pinned to the release commit —',
		'  git worktree add .worktrees/release v<X.Y.Z> && cd .worktrees/release && npm ci',
	];
	if (mode === 'deploy') {
		lines.push(
			'',
			`Deliberate hotfix deploy from an untagged commit: ${OVERRIDE_ENV}=1 npm run deploy:prod`,
		);
	} else if (overrideRequested) {
		// Loud, because the operator explicitly asked for a bypass and is not getting one.
		lines.push(
			'',
			`NOTE: ${OVERRIDE_ENV} is set but is IGNORED for publish. A registry or npm`,
			'publish is public and permanent — there is no "hotfix publish from an',
			'untagged commit" need it could serve, only the wrong-version publish this',
			'gate exists to prevent. Tag the commit and publish from that tag.',
		);
	} else {
		lines.push('', 'There is no override for publish. Tag the commit and publish from that tag.');
	}
	return lines.join('\n');
}

/**
 * Decide whether this checkout may be deployed or published.
 *
 * Fail-CLOSED by construction: the only paths returning `ok: true` are a tree
 * proven to be a clean checkout of a release tag whose four version surfaces
 * agree, and an explicit deploy-mode operator override. Anything unverifiable
 * blocks, because a stale ship looks identical to a good one until someone
 * queries production or the registry.
 *
 * Every failed condition is collected and reported together — an operator who
 * fixes one and re-runs only to hit the next has been told half the truth.
 */
export function assessReleaseIntegrity(input: ReleaseIntegrityInput): ReleaseIntegrityVerdict {
	const { mode, exactTag, porcelain, gitUnavailable, versions, allowUnpinned } = input;
	const skipGit = input.skipGit === true;
	const expectVersion = input.expectVersion ?? null;

	// CI-reuse shape: caller already knows the version, wants surfaces only.
	// `expectVersion` is mandatory here — silently falling back to the tree's own
	// package.json would make every surface agree with itself and pass always.
	if (skipGit) {
		if (!expectVersion) {
			return {
				ok: false,
				code: 'misconfigured',
				version: null,
				violations: ['--skip-git requires --expect-version'],
				message: 'RELEASE CHECK MISCONFIGURED — --skip-git requires an explicit --expect-version.',
			};
		}
		const violations = collectSurfaceViolations(versions, expectVersion);
		if (violations.length === 0) {
			return {
				ok: true,
				code: 'ok',
				version: expectVersion,
				violations: [],
				message: `All version surfaces match ${expectVersion}.`,
			};
		}
		return {
			ok: false,
			code: 'blocked',
			version: expectVersion,
			violations,
			message: renderBlocked(mode, violations, false),
		};
	}

	const violations: string[] = [];
	let version: string | null = expectVersion;

	if (gitUnavailable) {
		// Not evidence of a good tree. An unprovable checkout is treated as unpinned.
		violations.push('git could not be consulted, so this tree cannot be verified against a tag');
	} else {
		if (porcelain.trim().length > 0) {
			const entries = porcelain
				.split('\n')
				.map((l) => l.trim())
				.filter((l) => l.length > 0);
			violations.push(`working tree is dirty (${entries.length} uncommitted or untracked path(s))`);
			for (const e of entries.slice(0, 10)) violations.push(`    ${e}`);
			if (entries.length > 10) violations.push(`    ... and ${entries.length - 10} more`);
		}

		if (exactTag === null) {
			violations.push('HEAD is not at a tag (`git describe --tags --exact-match` found none)');
		} else {
			const fromTag = versionFromTag(exactTag);
			if (fromTag === null) {
				violations.push(`HEAD tag "${exactTag}" is not a vX.Y.Z release tag`);
			} else if (version === null) {
				version = fromTag;
			} else if (version !== fromTag) {
				violations.push(`--expect-version ${version} disagrees with HEAD tag ${exactTag}`);
			}
		}
	}

	if (version === null) {
		violations.push('no release version could be established, so the version surfaces were not checked');
	} else {
		violations.push(...collectSurfaceViolations(versions, version));
	}

	if (violations.length === 0) {
		return {
			ok: true,
			code: 'ok',
			version,
			violations: [],
			message: `Release integrity OK — clean checkout of ${exactTag}, all version surfaces at ${version}.`,
		};
	}

	// The override is deploy-only, and it is loud: it names every condition it is
	// waiving rather than printing a single generic "bypassed" line, so an
	// operator who reaches for it during an incident still sees what is wrong.
	if (allowUnpinned && mode === 'deploy') {
		return {
			ok: true,
			code: 'override',
			version,
			violations,
			message: [
				`${OVERRIDE_ENV}=1 — RELEASE INTEGRITY CHECK BYPASSED.`,
				'',
				'Deploying this working tree as-is. Waived:',
				...violations.map((v) => `  - ${v}`),
				'',
				'This deploy is NOT reproducible from a tag. Record what was shipped.',
			].join('\n'),
		};
	}

	return {
		ok: false,
		code: 'blocked',
		version,
		violations,
		message: renderBlocked(mode, violations, allowUnpinned),
	};
}

export { OVERRIDE_ENV as RELEASE_INTEGRITY_OVERRIDE_ENV };
