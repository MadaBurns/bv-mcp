// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the release-integrity decision core (issue #720).
 *
 * Imports ONLY `scripts/release-integrity.ts`, which is pure by design. The CLI
 * that performs git/fs I/O lives in `scripts/ci/release-integrity-check.ts` and
 * is deliberately NOT imported here: this spec runs in the default Workers pool,
 * where `node:child_process` is not real and importing it is a hard SIGSEGV
 * rather than a catchable failure.
 *
 * Testing the pure function rather than shelling out also means these cases do
 * not depend on the ambient git state of whatever checkout they run in — the
 * suite must behave identically on a tagged release worktree and on a dirty
 * feature branch.
 *
 * The issue is explicit that BOTH directions must be covered: "a guard only
 * proven to block is not proven to work." So every blocking case below has a
 * permitting counterpart, and the happy path is asserted first.
 */

import { describe, expect, it } from 'vitest';
import {
	assessReleaseIntegrity,
	parseChangelogHeadings,
	versionFromTag,
	type ReleaseIntegrityInput,
	type VersionSurfaces,
} from '../scripts/release-integrity';

const VERSION = '3.55.0';

function surfaces(overrides: Partial<VersionSurfaces> = {}): VersionSurfaces {
	return {
		packageJson: VERSION,
		packageLock: VERSION,
		serverJson: VERSION,
		serverJsonPackage: null,
		changelogHeadings: ['Unreleased', VERSION, '3.54.0'],
		...overrides,
	};
}

/** A clean checkout sitting exactly on tag v3.55.0 with all four surfaces in sync. */
function pinned(overrides: Partial<ReleaseIntegrityInput> = {}): ReleaseIntegrityInput {
	return {
		mode: 'deploy',
		exactTag: `v${VERSION}`,
		porcelain: '',
		gitUnavailable: false,
		versions: surfaces(),
		allowUnpinned: false,
		...overrides,
	};
}

describe('assessReleaseIntegrity — PERMITS a correct release', () => {
	it('passes a clean checkout of a tag whose version surfaces all agree (deploy)', () => {
		const v = assessReleaseIntegrity(pinned());
		expect(v.ok).toBe(true);
		expect(v.code).toBe('ok');
		expect(v.version).toBe(VERSION);
		expect(v.violations).toEqual([]);
	});

	it('passes the same tree for publish — the stricter mode must not block a correct release', () => {
		const v = assessReleaseIntegrity(pinned({ mode: 'publish' }));
		expect(v.ok).toBe(true);
		expect(v.code).toBe('ok');
	});

	it('passes a prerelease tag', () => {
		const v = assessReleaseIntegrity(
			pinned({
				exactTag: 'v3.56.0-rc.1',
				versions: surfaces({
					packageJson: '3.56.0-rc.1',
					packageLock: '3.56.0-rc.1',
					serverJson: '3.56.0-rc.1',
					changelogHeadings: ['3.56.0-rc.1'],
				}),
			}),
		);
		expect(v.ok).toBe(true);
		expect(v.version).toBe('3.56.0-rc.1');
	});

	it('passes when a server.json packages[] stanza exists and also matches', () => {
		// The stanza is currently absent, but if it is ever re-added it must be
		// enforced rather than silently ignored — and must not block when correct.
		const v = assessReleaseIntegrity(pinned({ versions: surfaces({ serverJsonPackage: VERSION }) }));
		expect(v.ok).toBe(true);
	});

	it('ignores an unrelated CHANGELOG heading set as long as this version is present', () => {
		const v = assessReleaseIntegrity(pinned({ versions: surfaces({ changelogHeadings: ['9.9.9', VERSION] }) }));
		expect(v.ok).toBe(true);
	});
});

describe('assessReleaseIntegrity — BLOCKS a stale or dirty checkout', () => {
	it('BLOCKS when the working tree is dirty', () => {
		const v = assessReleaseIntegrity(pinned({ porcelain: ' M src/tools/check-spf.ts\n?? scratch.ts\n' }));
		expect(v.ok).toBe(false);
		expect(v.code).toBe('blocked');
		expect(v.violations.join('\n')).toContain('dirty');
	});

	it('names the dirty paths so the operator can see what would ship', () => {
		const v = assessReleaseIntegrity(pinned({ porcelain: ' M src/lib/dns.ts\n?? packages/dns-checks/src/rating.ts\n' }));
		expect(v.message).toContain('src/lib/dns.ts');
		expect(v.message).toContain('packages/dns-checks/src/rating.ts');
	});

	it('BLOCKS when HEAD is not at a tag', () => {
		const v = assessReleaseIntegrity(pinned({ exactTag: null }));
		expect(v.ok).toBe(false);
		expect(v.violations.join('\n')).toContain('HEAD is not at a tag');
	});

	it('BLOCKS when HEAD is at a non-release tag', () => {
		const v = assessReleaseIntegrity(pinned({ exactTag: 'nightly-2026-08-20' }));
		expect(v.ok).toBe(false);
		expect(v.violations.join('\n')).toContain('not a vX.Y.Z release tag');
	});

	it.each([
		['package.json', { packageJson: '3.54.0' }],
		['package-lock.json', { packageLock: '3.54.0' }],
		['server.json', { serverJson: '3.54.0' }],
	] as Array<[string, Partial<VersionSurfaces>]>)('BLOCKS when %s disagrees with the tag', (label, override) => {
		const v = assessReleaseIntegrity(pinned({ versions: surfaces(override) }));
		expect(v.ok).toBe(false);
		expect(v.violations.join('\n')).toContain(label);
	});

	it('BLOCKS when a re-added server.json packages[0].version disagrees', () => {
		const v = assessReleaseIntegrity(pinned({ versions: surfaces({ serverJsonPackage: '3.54.0' }) }));
		expect(v.ok).toBe(false);
		expect(v.violations.join('\n')).toContain('packages[0].version');
	});

	it('BLOCKS when CHANGELOG.md has no heading for this version', () => {
		const v = assessReleaseIntegrity(pinned({ versions: surfaces({ changelogHeadings: ['Unreleased', '3.54.0'] }) }));
		expect(v.ok).toBe(false);
		expect(v.violations.join('\n')).toContain('CHANGELOG.md');
	});

	it('BLOCKS when a version surface could not be read at all', () => {
		// A missing file must not read as "nothing to compare, therefore fine".
		const v = assessReleaseIntegrity(pinned({ versions: surfaces({ serverJson: null }) }));
		expect(v.ok).toBe(false);
		expect(v.violations.join('\n')).toContain('could not be read');
	});

	it('BLOCKS when git could not be consulted — unprovable is not fresh', () => {
		const v = assessReleaseIntegrity(pinned({ gitUnavailable: true, exactTag: null }));
		expect(v.ok).toBe(false);
		expect(v.violations.join('\n')).toContain('git could not be consulted');
	});

	it('reports every violation at once rather than stopping at the first', () => {
		const v = assessReleaseIntegrity(
			pinned({ exactTag: null, porcelain: ' M a.ts\n', versions: surfaces({ packageJson: null }) }),
		);
		expect(v.ok).toBe(false);
		const joined = v.violations.join('\n');
		expect(joined).toContain('dirty');
		expect(joined).toContain('HEAD is not at a tag');
	});

	it('does not check version surfaces against a version it could not establish', () => {
		// Guards against a null/undefined version being coerced and "matching".
		const v = assessReleaseIntegrity(pinned({ exactTag: null }));
		expect(v.version).toBeNull();
		expect(v.violations.join('\n')).toContain('no release version could be established');
	});
});

describe('assessReleaseIntegrity — the escape hatch is explicit, loud, and deploy-only', () => {
	it('PERMITS an untagged hotfix deploy when the override is set', () => {
		const v = assessReleaseIntegrity(pinned({ mode: 'deploy', exactTag: null, allowUnpinned: true }));
		expect(v.ok).toBe(true);
		expect(v.code).toBe('override');
	});

	it('still enumerates everything it waived — the override is never silent', () => {
		const v = assessReleaseIntegrity(
			pinned({ mode: 'deploy', exactTag: null, porcelain: ' M src/index.ts\n', allowUnpinned: true }),
		);
		expect(v.message).toContain('BYPASSED');
		expect(v.message).toContain('dirty');
		expect(v.message).toContain('HEAD is not at a tag');
		expect(v.violations.length).toBeGreaterThan(1);
	});

	it('REFUSES to honour the override for publish — a wrong-version publish is public and permanent', () => {
		const v = assessReleaseIntegrity(pinned({ mode: 'publish', exactTag: null, allowUnpinned: true }));
		expect(v.ok).toBe(false);
		expect(v.code).toBe('blocked');
	});

	it('says loudly that the override was ignored, rather than failing as if it were unset', () => {
		const v = assessReleaseIntegrity(pinned({ mode: 'publish', exactTag: null, allowUnpinned: true }));
		expect(v.message).toContain('IGNORED for publish');
	});

	it('the override is opt-in: an unset override leaves a bad tree blocked', () => {
		const v = assessReleaseIntegrity(pinned({ exactTag: null, allowUnpinned: false }));
		expect(v.ok).toBe(false);
	});

	it('the override does not weaken a tree that is already correct', () => {
		const v = assessReleaseIntegrity(pinned({ allowUnpinned: true }));
		expect(v.ok).toBe(true);
		expect(v.code).toBe('ok');
	});
});

describe('assessReleaseIntegrity — --skip-git reuse shape (publish.yml parity)', () => {
	it('PERMITS surfaces that match an explicitly supplied version, ignoring git state', () => {
		const v = assessReleaseIntegrity(
			pinned({ skipGit: true, expectVersion: VERSION, exactTag: null, porcelain: ' M whatever.ts\n' }),
		);
		expect(v.ok).toBe(true);
		expect(v.code).toBe('ok');
	});

	it('BLOCKS surfaces that disagree with the supplied version', () => {
		const v = assessReleaseIntegrity(
			pinned({ skipGit: true, expectVersion: '3.56.0', exactTag: null }),
		);
		expect(v.ok).toBe(false);
	});

	it('BLOCKS as misconfigured when --skip-git is used without a version', () => {
		// Falling back to the tree's own package.json would make every surface
		// agree with itself and pass unconditionally.
		const v = assessReleaseIntegrity(pinned({ skipGit: true, expectVersion: null }));
		expect(v.ok).toBe(false);
		expect(v.code).toBe('misconfigured');
	});

	it('BLOCKS when an explicit --expect-version contradicts the HEAD tag', () => {
		const v = assessReleaseIntegrity(pinned({ expectVersion: '3.56.0' }));
		expect(v.ok).toBe(false);
		expect(v.violations.join('\n')).toContain('disagrees with HEAD tag');
	});
});

describe('versionFromTag', () => {
	it('strips the leading v from a release tag', () => {
		expect(versionFromTag('v3.55.0')).toBe('3.55.0');
		expect(versionFromTag('v3.55.0-rc.1')).toBe('3.55.0-rc.1');
	});

	it('rejects anything that is not a vX.Y.Z release tag', () => {
		for (const tag of ['3.55.0', 'nightly', 'v3.55', 'release-v3.55.0', '']) {
			expect(versionFromTag(tag)).toBeNull();
		}
	});
});

describe('parseChangelogHeadings', () => {
	it('extracts every bracketed heading token', () => {
		const md = ['# Changelog', '', '## [Unreleased]', 'text', '## [3.55.0] - 2026-08-20', 'text', '## [3.54.0]', ''].join('\n');
		expect(parseChangelogHeadings(md)).toEqual(['Unreleased', '3.55.0', '3.54.0']);
	});

	it('does not match a heading that is not at the start of a line', () => {
		// Mirrors publish.yml's anchored `grep -q "^## \[$VERSION\]"`.
		expect(parseChangelogHeadings('see ## [3.55.0] inline')).toEqual([]);
	});

	it('returns an empty list for an empty or unreadable changelog', () => {
		expect(parseChangelogHeadings('')).toEqual([]);
	});
});
