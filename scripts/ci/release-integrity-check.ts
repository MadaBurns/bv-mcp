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
 *   --mode deploy|publish   Which surface is being gated (default: deploy).
 *                           `publish` refuses to honour the override.
 *   --expect-version X.Y.Z  Verify against this version instead of HEAD's tag.
 *   --skip-git              Verify version surfaces only. Requires
 *                           --expect-version. This is the shape publish.yml's
 *                           `version-bump` job needs if it ever swaps its inline
 *                           bash for this script.
 */

import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { assessReleaseIntegrity, parseChangelogHeadings, type ReleaseMode, type VersionSurfaces } from '../release-integrity';

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

function main(): void {
	const argv = process.argv.slice(2);
	const rawMode = flagValue(argv, '--mode') ?? 'deploy';
	if (rawMode !== 'deploy' && rawMode !== 'publish') {
		console.error(`Unknown --mode "${rawMode}" (expected deploy or publish)`);
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
