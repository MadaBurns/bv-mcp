// SPDX-License-Identifier: BUSL-1.1

/**
 * Pack-integrity decision core + provenance stamp (issue #702).
 *
 * `@blackveil/dns-checks@1.18.0` was built, packed and vendored into bv-web-prod
 * from a bv-mcp working tree that was NEVER committed. Nothing in either repo
 * prevented it and nothing flagged it afterwards; the source proved recoverable
 * only from the vendored tarball's `.js.map` `sourcesContent`. Per operator
 * decision 1.18.0 was SKIPPED rather than reconstructed — the version number
 * stays orphaned. This module exists so it cannot happen again.
 *
 * The vendoring seam is tarball-based and sha256-pinned with a contract test, so
 * the CONTENT is already verified — but the pin proves only that bv-web-prod got
 * the bytes bv-mcp handed it. It says nothing about whether those bytes
 * correspond to a commit. That is the exact gap here, and it is closed twice:
 *
 *   1. PACK-TIME GATE (`assessPackIntegrity`) — refuse to pack or publish when
 *      `packages/dns-checks` is dirty, or when the version in its package.json
 *      does not resolve to a commit.
 *   2. PROVENANCE STAMP (`buildBuildInfo`) — write the build commit into
 *      `dist/BUILD_INFO.json` so any vendored tarball SELF-IDENTIFIES its source
 *      commit, making "what code is bv-web-prod actually running?" answerable
 *      without spelunking in sourcemaps.
 *
 * Scope note: the dirty check is scoped to `packages/dns-checks` on purpose. The
 * repo root routinely carries unrelated dirty files from concurrent work, and a
 * repo-wide check here would block every legitimate release. (The repo-wide
 * cleanliness requirement belongs to the DEPLOY path and lives in
 * `scripts/release-integrity.ts`, which is a different gate with a different
 * blast radius.)
 *
 * CI note: a detached-HEAD, clean-tree checkout is normal and legitimate for a
 * tagged release, so nothing here consults branches or upstreams — `HEAD`
 * resolves fine when detached, and that is all this gate needs.
 *
 * This module is deliberately PURE — no `node:*` imports. It is unit-tested from
 * `test/pack-integrity.spec.ts`; all git/fs I/O lives in the sibling CLI,
 * `scripts/ci/dns-checks-prepack.ts`.
 */

export interface PackIntegrityInput {
	/**
	 * `git status --porcelain -- packages/dns-checks`; '' when clean.
	 * Includes untracked files by default, which is what caught 1.18.0's novel
	 * `packages/dns-checks/src/rating.ts`.
	 */
	scopedPorcelain: string;
	/** `version` from the working `packages/dns-checks/package.json`. */
	workingVersion: string | null;
	/** `version` parsed from `git show HEAD:packages/dns-checks/package.json`; null when unreadable. */
	headVersion: string | null;
	/** Full `git rev-parse HEAD`; null when unavailable. */
	headCommit: string | null;
	/** True when git could not be consulted at all. */
	gitUnavailable: boolean;
	/** Operator override, from the environment. Never silent — see `provenance`. */
	allowUncommitted: boolean;
}

export type PackIntegrityCode = 'ok' | 'override' | 'blocked';

/** How trustworthy the resulting tarball's provenance is. Recorded IN the tarball. */
export type Provenance = 'committed' | 'uncommitted-override';

export interface PackIntegrityVerdict {
	/** False means: do not pack, do not publish. The CLI exits non-zero. */
	ok: boolean;
	code: PackIntegrityCode;
	/** The commit these bytes correspond to; null when that could not be established. */
	commit: string | null;
	provenance: Provenance;
	violations: string[];
	message: string;
}

const OVERRIDE_ENV = 'BV_ALLOW_UNCOMMITTED_PACK';

/** Current shape of `dist/BUILD_INFO.json`. Bump when fields change meaning. */
export const BUILD_INFO_SCHEMA = 1;

export interface BuildInfo {
	schema: number;
	name: string;
	version: string;
	/** Full 40-hex commit these bytes were packed from, or null under an override. */
	commit: string | null;
	provenance: Provenance;
}

/**
 * Build the provenance stamp written to `dist/BUILD_INFO.json`.
 *
 * Deliberately DETERMINISTIC — no timestamps, no hostnames, no packer identity.
 * bv-web-prod pins the vendored tarball by sha256, so a clock reading baked into
 * the payload would change that hash on every re-pack of the same commit and
 * destroy the one property the pin is there to provide. Everything here is a
 * function of the source commit, so re-packing a commit reproduces the bytes.
 *
 * `provenance: 'uncommitted-override'` (with a null commit) is how a forced pack
 * announces itself. That is the whole point of keeping the escape hatch: a
 * tarball produced under duress still says so, in the tarball, forever — which
 * is precisely what 1.18.0 could not do.
 */
export function buildBuildInfo(input: { name: string; version: string; commit: string | null; provenance: Provenance }): BuildInfo {
	return {
		schema: BUILD_INFO_SCHEMA,
		name: input.name,
		version: input.version,
		commit: input.provenance === 'committed' ? input.commit : null,
		provenance: input.provenance,
	};
}

/**
 * Decide whether `packages/dns-checks` may be packed or published.
 *
 * Fail-CLOSED: the only unforced path to `ok: true` is a clean scoped tree whose
 * package.json version is the one recorded at HEAD — i.e. these bytes provably
 * correspond to a commit.
 */
export function assessPackIntegrity(input: PackIntegrityInput): PackIntegrityVerdict {
	const { scopedPorcelain, workingVersion, headVersion, headCommit, gitUnavailable, allowUncommitted } = input;
	const violations: string[] = [];

	if (workingVersion === null) {
		violations.push('packages/dns-checks/package.json: version could not be read');
	}

	if (gitUnavailable) {
		violations.push('git could not be consulted, so these bytes cannot be tied to a commit');
	} else {
		const entries = scopedPorcelain
			.split('\n')
			.map((l) => l.trim())
			.filter((l) => l.length > 0);
		if (entries.length > 0) {
			violations.push(`packages/dns-checks is dirty (${entries.length} uncommitted or untracked path(s))`);
			for (const e of entries.slice(0, 10)) violations.push(`    ${e}`);
			if (entries.length > 10) violations.push(`    ... and ${entries.length - 10} more`);
		}

		if (headCommit === null) {
			violations.push('HEAD could not be resolved to a commit');
		}

		// "Resolves to a commit" in the concrete sense that matters: the version
		// about to be published is the version recorded at HEAD. Checked against
		// HEAD rather than by searching all refs so a shallow, detached CI
		// checkout — the normal shape of a tagged release build — still passes.
		if (headVersion === null) {
			violations.push('packages/dns-checks/package.json could not be read at HEAD');
		} else if (workingVersion !== null && headVersion !== workingVersion) {
			violations.push(`version ${workingVersion} is not the version committed at HEAD (${headVersion}) — it resolves to no commit`);
		}
	}

	if (violations.length === 0) {
		return {
			ok: true,
			code: 'ok',
			commit: headCommit,
			provenance: 'committed',
			violations: [],
			message: `Pack integrity OK — @blackveil/dns-checks ${workingVersion} matches commit ${(headCommit ?? '').slice(0, 12)}.`,
		};
	}

	if (allowUncommitted) {
		return {
			ok: true,
			code: 'override',
			commit: null,
			provenance: 'uncommitted-override',
			violations,
			message: [
				`${OVERRIDE_ENV}=1 — PACK INTEGRITY CHECK BYPASSED.`,
				'',
				'Packing anyway. Waived:',
				...violations.map((v) => `  - ${v}`),
				'',
				'This tarball will be stamped provenance="uncommitted-override" with a',
				'null commit in dist/BUILD_INFO.json. Do NOT vendor it into bv-web-prod:',
				'that is exactly how 1.18.0 happened.',
			].join('\n'),
		};
	}

	return {
		ok: false,
		code: 'blocked',
		commit: null,
		provenance: 'committed',
		violations,
		message: [
			'PACK BLOCKED — these bytes do not correspond to a commit.',
			'',
			'@blackveil/dns-checks 1.18.0 was packed and vendored into bv-web-prod from',
			'an uncommitted tree; the source survived only inside the tarball sourcemaps.',
			'A sha256 pin proves bv-web-prod got the bytes bv-mcp handed it — it cannot',
			'prove those bytes came from anywhere reviewable.',
			'',
			'Failed checks:',
			...violations.map((v) => `  - ${v}`),
			'',
			'Fix: commit packages/dns-checks (including any new files) and re-pack.',
			`Deliberate local experiment: ${OVERRIDE_ENV}=1 npm pack -w packages/dns-checks`,
		].join('\n'),
	};
}

export { OVERRIDE_ENV as PACK_INTEGRITY_OVERRIDE_ENV };
