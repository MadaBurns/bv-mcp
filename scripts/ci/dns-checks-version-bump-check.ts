// SPDX-License-Identifier: BUSL-1.1

/**
 * PR-time dns-checks version-bump gate — CLI shell.
 *
 * Fails a PR that changes dns-checks shipping inputs while
 * `packages/dns-checks/package.json` still names an existing
 * `dns-checks-v<version>` tag whose tree differs on those inputs. All decisions
 * live in the pure `dnsChecksVersionBumpViolations` (scripts/release-integrity.ts);
 * this file only turns git into its input. `node:child_process` MUST NOT become
 * reachable from anything under `test/` (hard SIGSEGV in the Workers pool).
 *
 * Base ref: `DNS_CHECKS_BASE_REF`, else `origin/$GITHUB_BASE_REF`. A missing or
 * undiffable base fails closed. Requires tags (`actions/checkout` fetch-depth 0).
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dnsChecksVersionBumpViolations, type DnsChecksIdentityInput, type DnsChecksVersionBumpInput } from '../release-integrity';

const PACKAGE_PATH = 'packages/dns-checks/package.json';
const IDENTITY_PATHS = ['packages/dns-checks', 'scripts/ci/dns-checks-prepack.ts', 'scripts/pack-integrity.ts'];

function git(args: string[]): { ok: boolean; stdout: string } {
	const res = spawnSync('git', args, { encoding: 'utf8' });
	return { ok: res.status === 0, stdout: res.stdout ?? '' };
}

function versionFromJson(text: string): string | null {
	try {
		const value = (JSON.parse(text) as { version?: unknown }).version;
		return typeof value === 'string' ? value : null;
	} catch {
		return null;
	}
}

function splitZ(stdout: string): string[] {
	return stdout.split('\0').filter(Boolean);
}

function readPackageVersion(): string | null {
	try {
		return versionFromJson(readFileSync(PACKAGE_PATH, 'utf8'));
	} catch {
		return null; // unreadable → null → core reports it
	}
}

function readPrChangedPaths(baseRef: string): string[] | null {
	const diff = git(['diff', '--no-ext-diff', '--no-renames', '--name-only', '-z', `${baseRef}...HEAD`]);
	return diff.ok ? splitZ(diff.stdout) : null;
}

type TagRead = Pick<DnsChecksVersionBumpInput, 'tagState' | 'identity'>;

function readTag(version: string, fallback: DnsChecksIdentityInput): TagRead {
	const tag = `dns-checks-v${version}`;
	const listed = git(['tag', '--list', tag]);
	if (!listed.ok) return { tagState: 'unreadable', identity: fallback };
	if (listed.stdout.trim() !== tag) return { tagState: 'absent', identity: fallback };
	return compareWithTag(`refs/tags/${tag}`, version, fallback);
}

function compareWithTag(ref: string, version: string, fallback: DnsChecksIdentityInput): TagRead {
	const commit = git(['rev-parse', '--verify', `${ref}^{commit}`]);
	const manifest = git(['show', `${ref}:${PACKAGE_PATH}`]);
	// Both paths of a rename are reported: moving code into an excluded test dir is still a shipping deletion.
	const changed = git(['diff', '--no-ext-diff', '--no-renames', '--name-only', '-z', ref, 'HEAD', '--', ...IDENTITY_PATHS]);
	if (!commit.ok || !manifest.ok || !changed.ok) return { tagState: 'unreadable', identity: fallback };
	return {
		tagState: 'present',
		identity: {
			version,
			tagCommit: commit.stdout.trim(),
			tagVersion: versionFromJson(manifest.stdout),
			changedPaths: splitZ(changed.stdout),
			gitUnavailable: false,
		},
	};
}

function readInput(baseRef: string): DnsChecksVersionBumpInput {
	const version = readPackageVersion();
	const identity: DnsChecksIdentityInput = { version, tagCommit: null, tagVersion: null, changedPaths: [], gitUnavailable: false };
	const prChangedPaths = readPrChangedPaths(baseRef);
	if (!version) return { prChangedPaths, tagState: 'absent', identity };
	return { prChangedPaths, ...readTag(version, identity) };
}

function main(): void {
	const baseRef = process.env.DNS_CHECKS_BASE_REF || (process.env.GITHUB_BASE_REF ? `origin/${process.env.GITHUB_BASE_REF}` : undefined);
	const violations = baseRef
		? dnsChecksVersionBumpViolations(readInput(baseRef))
		: ['dns-checks version-bump gate has no base ref (set DNS_CHECKS_BASE_REF to a commit or ref to diff against)'];
	if (violations.length > 0) {
		console.error(`dns-checks version-bump gate: BLOCKED\n${violations.join('\n')}`);
		process.exit(1);
	}
	console.log('dns-checks version-bump gate: OK');
}

main();
