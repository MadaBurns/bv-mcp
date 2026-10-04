// SPDX-License-Identifier: BUSL-1.1

/**
 * Release-integrity gate (issue #720) — CLI shell.
 *
 * Wired into the two local shipping paths, which are the ones CI never sees:
 *   - `npm run deploy:prod` (via `check:release-integrity`)
 *   - `npm run publish:registry` → `mcp-publisher publish`
 *   - the root package's `prepack`, which npm runs for `npm publish` / `npm pack`
 *
 * All decision logic lives in the pure `scripts/release-integrity.ts` so it can
 * be unit-tested in the Workers pool; this file is the untestable half on
 * purpose — it exists only to turn git and the version files into that module's
 * inputs. Keep it thin. `node:child_process` is imported here and MUST NOT
 * become reachable from anything under `test/` (a hard SIGSEGV in that pool).
 *
 * Flags:
 *   --mode deploy|publish|sidecar   Which surface is being gated (default: deploy).
 *                           `publish` refuses to honour the override; `sidecar`
 *                           checks tree cleanliness only (no tag requirement).
 *   --expect-version X.Y.Z  Verify against this version instead of HEAD's tag.
 *   --skip-git              Skip app-tag/cleanliness checks. Requires
 *                           --expect-version. This is the shape publish.yml's
 *                           `version-bump` job needs if it ever swaps its inline
 *                           bash for this script. Deploy mode still verifies
 *                           dns-checks source identity with git, without an override.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { assessReleaseIntegrity, parseChangelogHeadings, type DnsChecksIdentityInput, type ReleaseMode, type VersionSurfaces } from '../release-integrity';

function git(args: string[]): { ok: boolean; stdout: string } {
	const res = spawnSync('git', args, { encoding: 'utf8' });
	return { ok: res.status === 0, stdout: res.stdout ?? '' };
}

/** Read one JSON file and pluck a value. Any failure degrades to null, never to a guess. */
function readJson(path: string): Record<string, unknown> | null {
	try {
		return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
	} catch {
		return null;
	}
}

function versionOf(obj: Record<string, unknown> | null): string | null {
	const v = obj?.version;
	return typeof v === 'string' ? v : null;
}

function readVersionSurfaces(): VersionSurfaces {
	const server = readJson('server.json');
	// server.json is currently remotes-only; a `packages` stanza is the foot-gun
	// that returns only if one is re-added. Absent → null → not enforced.
	const packages = server?.packages;
	const firstPackage = Array.isArray(packages) && packages.length > 0 ? (packages[0] as Record<string, unknown>) : null;

	let changelog = '';
	try {
		changelog = readFileSync('CHANGELOG.md', 'utf8');
	} catch {
		changelog = '';
	}

	return {
		packageJson: versionOf(readJson('package.json')),
		packageLock: versionOf(readJson('package-lock.json')),
		serverJson: versionOf(server),
		serverJsonPackage: versionOf(firstPackage),
		changelogHeadings: parseChangelogHeadings(changelog),
	};
}

function flagValue(argv: string[], name: string): string | null {
	const i = argv.indexOf(name);
	if (i === -1) return null;
	const v = argv[i + 1];
	return typeof v === 'string' && !v.startsWith('--') ? v : null;
}

/** Compare the working shipping inputs (including untracked additions) with the version's exact local tag. No network. */
function readDnsChecksIdentity(): DnsChecksIdentityInput {
	const version = versionOf(readJson('packages/dns-checks/package.json'));
	const empty: DnsChecksIdentityInput = { version, tagCommit: null, tagVersion: null, changedPaths: [], gitUnavailable: false };
	if (!git(['rev-parse', '--is-inside-work-tree']).ok) return { ...empty, gitUnavailable: true };
	if (!version || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) return empty;
	const ref = `refs/tags/dns-checks-v${version}`;
	const commit = git(['rev-parse', '--verify', `${ref}^{commit}`]);
	if (!commit.ok) return empty;
	const manifest = git(['show', `${ref}:packages/dns-checks/package.json`]);
	let tagVersion: string | null = null;
	try { tagVersion = versionOf(JSON.parse(manifest.stdout)); } catch { /* unreadable fails closed in the core */ }
	const paths = ['packages/dns-checks', 'scripts/ci/dns-checks-prepack.ts', 'scripts/pack-integrity.ts'];
	// Renames must report BOTH paths: moving runtime code into an excluded test
	// directory is still a shipping deletion, never a test-only change.
	const diff = git(['diff', '--no-ext-diff', '--no-renames', '--name-only', '-z', ref, '--', ...paths]);
	const untracked = git(['ls-files', '--others', '--exclude-standard', '-z', '--', ...paths]);
	return {
		version,
		tagCommit: commit.stdout.trim(),
		tagVersion,
		changedPaths: [...diff.stdout.split('\0'), ...untracked.stdout.split('\0')].filter(Boolean),
		gitUnavailable: !manifest.ok || !diff.ok || !untracked.ok,
	};
}

function main(): void {
	const argv = process.argv.slice(2);
	const rawMode = flagValue(argv, '--mode') ?? 'deploy';
	if (rawMode !== 'deploy' && rawMode !== 'publish' && rawMode !== 'sidecar') {
		console.error(`Unknown --mode "${rawMode}" (expected deploy, publish or sidecar)`);
		process.exit(1);
	}
	const mode: ReleaseMode = rawMode;
	const skipGit = argv.includes('--skip-git');
	const expectVersion = flagValue(argv, '--expect-version');

	let exactTag: string | null = null;
	let porcelain = '';
	let gitUnavailable = false;

	if (!skipGit) {
		const status = git(['status', '--porcelain']);
		if (!status.ok) gitUnavailable = true;
		else porcelain = status.stdout;

		// Non-zero simply means "HEAD is not at a tag", which is a verdict, not an
		// error — so it must not be folded into `gitUnavailable`.
		const described = git(['describe', '--tags', '--exact-match']);
		if (described.ok) {
			const tag = described.stdout.trim();
			if (tag.length > 0) exactTag = tag;
		}
	}

	const verdict = assessReleaseIntegrity({
		mode,
		exactTag,
		porcelain,
		gitUnavailable,
		versions: readVersionSurfaces(),
		allowUnpinned: process.env.BV_ALLOW_UNPINNED_DEPLOY === '1',
		expectVersion,
		skipGit,
		...(mode === 'deploy' ? { dnsChecksIdentity: readDnsChecksIdentity() } : {}),
	});

	if (!verdict.ok) {
		console.error(`\n${verdict.message}\n`);
		process.exit(1);
	}

	// An override is a pass, but it is not good news — send it to stderr so it
	// survives a pipeline that only surfaces error output.
	if (verdict.code === 'override') console.error(`\n${verdict.message}\n`);
	else console.log(verdict.message);
}

main();
