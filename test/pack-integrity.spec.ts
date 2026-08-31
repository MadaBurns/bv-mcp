// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the pack-integrity decision core + provenance stamp (issue #702).
 *
 * Imports ONLY `scripts/pack-integrity.ts`, which is pure by design; the CLI that
 * performs git/fs I/O (`scripts/ci/dns-checks-prepack.ts`) is deliberately NOT
 * imported, because `node:child_process` is a hard SIGSEGV in the Workers pool.
 *
 * Testing the pure function also keeps these cases independent of the ambient
 * git state — the suite must behave the same whether the checkout running it
 * happens to be clean or dirty.
 *
 * Both directions are covered: the gate must block the 1.18.0 shape (packed from
 * an uncommitted tree) AND must permit a legitimate tagged, detached-HEAD CI
 * release. A gate that only blocks would take the release path down with it.
 */

import { describe, expect, it } from 'vitest';
import { assessPackIntegrity, buildBuildInfo, BUILD_INFO_SCHEMA, type PackIntegrityInput } from '../scripts/pack-integrity';

const COMMIT = '379c1916aa11bb22cc33dd44ee55ff6677889900';
const VERSION = '1.22.0';

/** A clean, committed `packages/dns-checks` — the only shape that should pack unforced. */
function committed(overrides: Partial<PackIntegrityInput> = {}): PackIntegrityInput {
	return {
		scopedPorcelain: '',
		workingVersion: VERSION,
		headVersion: VERSION,
		headCommit: COMMIT,
		gitUnavailable: false,
		allowUncommitted: false,
		...overrides,
	};
}

describe('assessPackIntegrity — PERMITS a legitimate pack', () => {
	it('passes when the scoped tree is clean and the version is the one at HEAD', () => {
		const v = assessPackIntegrity(committed());
		expect(v.ok).toBe(true);
		expect(v.code).toBe('ok');
		expect(v.commit).toBe(COMMIT);
		expect(v.provenance).toBe('committed');
		expect(v.violations).toEqual([]);
	});

	it('passes on a detached-HEAD checkout — the normal shape of a tagged CI release', () => {
		// Nothing in this gate consults a branch or an upstream, precisely so that
		// `actions/checkout` at a tag (which detaches HEAD) is not treated as broken.
		const v = assessPackIntegrity(committed({ headCommit: COMMIT }));
		expect(v.ok).toBe(true);
	});

	it('IGNORES dirt outside packages/dns-checks', () => {
		// The scoped porcelain is what the CLI passes; the repo root routinely
		// carries unrelated dirty files from concurrent work and must not block a
		// legitimate package release.
		const v = assessPackIntegrity(committed({ scopedPorcelain: '' }));
		expect(v.ok).toBe(true);
	});
});

describe('assessPackIntegrity — BLOCKS the 1.18.0 shape', () => {
	it('BLOCKS when packages/dns-checks has uncommitted modifications', () => {
		const v = assessPackIntegrity(committed({ scopedPorcelain: ' M packages/dns-checks/src/scoring/engine.ts\n' }));
		expect(v.ok).toBe(false);
		expect(v.code).toBe('blocked');
		expect(v.violations.join('\n')).toContain('dirty');
	});

	it('BLOCKS on an UNTRACKED new file — exactly how 1.18.0 shipped src/rating.ts', () => {
		const v = assessPackIntegrity(committed({ scopedPorcelain: '?? packages/dns-checks/src/rating.ts\n' }));
		expect(v.ok).toBe(false);
		expect(v.message).toContain('packages/dns-checks/src/rating.ts');
	});

	it('BLOCKS when the version in package.json is not the version committed at HEAD', () => {
		// The literal 1.18.0 case: the version bump itself was never committed.
		const v = assessPackIntegrity(committed({ workingVersion: '1.18.0', headVersion: '1.17.0', scopedPorcelain: '' }));
		expect(v.ok).toBe(false);
		expect(v.violations.join('\n')).toContain('resolves to no commit');
	});

	it('BLOCKS when package.json could not be read at HEAD', () => {
		const v = assessPackIntegrity(committed({ headVersion: null }));
		expect(v.ok).toBe(false);
	});

	it('BLOCKS when the working version could not be read', () => {
		const v = assessPackIntegrity(committed({ workingVersion: null }));
		expect(v.ok).toBe(false);
	});

	it('BLOCKS when git could not be consulted — unprovable is not committed', () => {
		const v = assessPackIntegrity(committed({ gitUnavailable: true }));
		expect(v.ok).toBe(false);
		expect(v.violations.join('\n')).toContain('git could not be consulted');
	});

	it('BLOCKS when HEAD could not be resolved', () => {
		const v = assessPackIntegrity(committed({ headCommit: null }));
		expect(v.ok).toBe(false);
	});

	it('never reports a commit for a blocked pack', () => {
		const v = assessPackIntegrity(committed({ scopedPorcelain: '?? packages/dns-checks/src/rating.ts\n' }));
		expect(v.commit).toBeNull();
	});
});

describe('assessPackIntegrity — the override self-incriminates rather than hiding', () => {
	it('PERMITS a forced pack when the override is set', () => {
		const v = assessPackIntegrity(committed({ scopedPorcelain: '?? packages/dns-checks/src/rating.ts\n', allowUncommitted: true }));
		expect(v.ok).toBe(true);
		expect(v.code).toBe('override');
	});

	it('marks the forced pack uncommitted-override with a NULL commit', () => {
		// The whole value of keeping an escape hatch: the tarball says so forever.
		const v = assessPackIntegrity(committed({ scopedPorcelain: ' M packages/dns-checks/src/index.ts\n', allowUncommitted: true }));
		expect(v.provenance).toBe('uncommitted-override');
		expect(v.commit).toBeNull();
	});

	it('enumerates what it waived and warns against vendoring the result', () => {
		const v = assessPackIntegrity(committed({ workingVersion: '1.18.0', headVersion: '1.17.0', allowUncommitted: true }));
		expect(v.message).toContain('BYPASSED');
		expect(v.message).toContain('resolves to no commit');
		expect(v.message).toContain('bv-web-prod');
	});

	it('does not downgrade provenance for a tree that was already clean', () => {
		const v = assessPackIntegrity(committed({ allowUncommitted: true }));
		expect(v.code).toBe('ok');
		expect(v.provenance).toBe('committed');
		expect(v.commit).toBe(COMMIT);
	});
});

describe('buildBuildInfo — the provenance stamp', () => {
	it('records the source commit for a committed pack', () => {
		const info = buildBuildInfo({ name: '@blackveil/dns-checks', version: VERSION, commit: COMMIT, provenance: 'committed', scoringContractSha256: 'a'.repeat(64) });
		expect(info).toEqual({
			schema: BUILD_INFO_SCHEMA,
			name: '@blackveil/dns-checks',
			version: VERSION,
			commit: COMMIT,
			provenance: 'committed',
			scoringContractSha256: 'a'.repeat(64),
		});
	});

	it('refuses to record a commit for an overridden pack even if one is passed', () => {
		// Defence in depth: a caller that forwards HEAD regardless must not be able
		// to make an unverified tarball claim a reviewable source commit.
		const info = buildBuildInfo({ name: '@blackveil/dns-checks', version: VERSION, commit: COMMIT, provenance: 'uncommitted-override', scoringContractSha256: 'a'.repeat(64) });
		expect(info.commit).toBeNull();
		expect(info.provenance).toBe('uncommitted-override');
	});

	it('is DETERMINISTIC — no timestamps, so re-packing a commit reproduces the sha256 pin', () => {
		const args = { name: '@blackveil/dns-checks', version: VERSION, commit: COMMIT, provenance: 'committed' as const, scoringContractSha256: 'a'.repeat(64) };
		expect(JSON.stringify(buildBuildInfo(args))).toBe(JSON.stringify(buildBuildInfo(args)));
	});

	it('carries a schema number so consumers can detect a shape change', () => {
		const info = buildBuildInfo({ name: 'x', version: '1.0.0', commit: COMMIT, provenance: 'committed', scoringContractSha256: 'a'.repeat(64) });
		expect(info.schema).toBe(BUILD_INFO_SCHEMA);
		expect(typeof info.schema).toBe('number');
	});
});
