// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it } from 'vitest';
import { assessReleaseIntegrity, dnsChecksIdentityViolations, isDnsChecksIdentityPath, type DnsChecksIdentityInput } from '../scripts/release-integrity';

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
