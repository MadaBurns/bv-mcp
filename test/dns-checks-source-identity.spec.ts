// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it } from 'vitest';
import { assessReleaseIntegrity, dnsChecksIdentityViolations, dnsChecksVersionBumpViolations, isDnsChecksIdentityPath, type DnsChecksIdentityInput, type DnsChecksVersionBumpInput } from '../scripts/release-integrity';

function identity(overrides: Partial<DnsChecksIdentityInput> = {}): DnsChecksIdentityInput {
	return { version: '1.59.0', tagVersion: '1.59.0', tagCommit: 'fixture-commit', changedPaths: [], gitUnavailable: false, ...overrides };
}

describe('dns-checks version-to-source identity (#1187)', () => {
	it('permits identical shipping inputs and test-only changes', () => {
		expect(dnsChecksIdentityViolations(identity())).toEqual([]);
		expect(dnsChecksIdentityViolations(identity({ changedPaths: [
			'packages/dns-checks/src/__tests__/scoring.spec.ts',
			'packages/dns-checks/test/check.test.ts',
			'packages/dns-checks/tsconfig.test.json',
			'test/check-spf.spec.ts',
		] }))).toEqual([]);
	});

	it('blocks absent tags, unreadable git and mismatched tag manifest versions', () => {
		expect(dnsChecksIdentityViolations(identity({ tagCommit: null }))[0]).toContain('local tag dns-checks-v1.59.0');
		expect(dnsChecksIdentityViolations(identity({ gitUnavailable: true }))).not.toEqual([]);
		expect(dnsChecksIdentityViolations(undefined)).not.toEqual([]);
		expect(dnsChecksIdentityViolations(identity({ tagVersion: '1.58.0' }))[0]).toContain('expected 1.59.0');
	});

	it.each([
		'packages/dns-checks/src/checks/spf.ts',
		'packages/dns-checks/src/scoring/classifiers/dmarc.test.ts',
		'packages/dns-checks/package.json',
		'packages/dns-checks/tsup.config.ts',
		'packages/dns-checks/tsconfig.json',
		'packages/dns-checks/assets/schema.json',
		'scripts/ci/dns-checks-prepack.ts',
		'scripts/pack-integrity.ts',
	])('blocks unchanged package version with changed shipping input %s', (path) => {
		expect(isDnsChecksIdentityPath(path)).toBe(true);
		expect(dnsChecksIdentityViolations(identity({ changedPaths: [path] })).join('\n')).toContain(path);
	});

	describe('PR-time version-bump gate (SQ-454)', () => {
		const shipping = 'packages/dns-checks/src/checks/spf.ts';
		const bump = (overrides: Partial<DnsChecksVersionBumpInput> = {}): DnsChecksVersionBumpInput => ({
			prChangedPaths: [shipping],
			tagState: 'present',
			identity: identity({ changedPaths: [shipping] }),
			...overrides,
		});

		it('passes without comparing when the PR touches no shipping input, even if main drifted from the tag', () => {
			expect(dnsChecksVersionBumpViolations(bump({ prChangedPaths: ['docs/readme.md', 'packages/dns-checks/test/x.test.ts'] }))).toEqual([]);
		});

		it('passes when the version has no tag yet (bumped PR)', () => {
			expect(dnsChecksVersionBumpViolations(bump({ tagState: 'absent', identity: identity({ tagCommit: null, changedPaths: [] }) }))).toEqual([]);
		});

		it('fails, listing paths and the remediation, when the tag exists and shipping inputs differ', () => {
			const out = dnsChecksVersionBumpViolations(bump()).join('\n');
			expect(out).toContain(shipping);
			expect(out).toContain('PARITY_CORPUS_VERSION');
			expect(out).toContain('packages/dns-checks/package.json');
		});

		it('passes when the tag exists and nothing differs', () => {
			expect(dnsChecksVersionBumpViolations(bump({ identity: identity({ changedPaths: [] }) }))).toEqual([]);
		});

		it('fails closed on an undiffable base, unreadable tags, or an unestablished version', () => {
			expect(dnsChecksVersionBumpViolations(bump({ prChangedPaths: null }))).not.toEqual([]);
			expect(dnsChecksVersionBumpViolations(bump({ tagState: 'unreadable' }))).not.toEqual([]);
			expect(dnsChecksVersionBumpViolations(bump({ tagState: 'absent', identity: identity({ version: null }) }))).not.toEqual([]);
			expect(dnsChecksVersionBumpViolations(bump({ identity: identity({ gitUnavailable: true }) }))).not.toEqual([]);
		});
	});

	it('cannot bypass identity by the unpinned deploy override or --skip-git', () => {
		for (const skipGit of [false, true]) {
			const verdict = assessReleaseIntegrity({
				mode: 'deploy', exactTag: null, porcelain: '', gitUnavailable: false, allowUnpinned: true,
				expectVersion: '3.97.0', skipGit,
				versions: { packageJson: '3.97.0', packageLock: '3.97.0', serverJson: '3.97.0', serverJsonPackage: null, changelogHeadings: ['3.97.0'] },
				dnsChecksIdentity: identity({ changedPaths: ['packages/dns-checks/src/types.ts'] }),
			});
			expect(verdict.ok).toBe(false);
			expect(verdict.code).toBe('blocked');
		}
	});
});
