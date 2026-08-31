// SPDX-License-Identifier: BUSL-1.1

/**
 * `@blackveil/dns-checks` pack-time gate + provenance stamp (issue #702) — CLI shell.
 *
 * Runs from `packages/dns-checks`'s `prepack`. Verified empirically on npm
 * 11.8.0 rather than assumed: `prepack` fires for `npm pack`, `npm pack -w
 * packages/dns-checks` from the repo root, `npm pack --dry-run`, and `npm
 * publish` — with cwd set to the package directory in every case — and does NOT
 * fire for `npm install` / `npm ci` (that is `prepare`, which would otherwise
 * make this gate block routine installs in a dirty dev tree). It also runs
 * BEFORE the tarball is assembled, so the `dist/BUILD_INFO.json` written here is
 * included in the pack.
 *
 * Two jobs, one hook:
 *   1. Refuse to pack when `packages/dns-checks` is dirty or its version does not
 *      resolve to a commit.
 *   2. Stamp the source commit into `dist/BUILD_INFO.json` so a vendored tarball
 *      self-identifies where it came from.
 *
 * Additive by construction: it writes ONE new file into an existing `dist`
 * (already covered by the package's `files` array) and touches neither
 * `package.json` nor the `exports` map — bv-web-prod consumes this tarball and a
 * changed `exports` map has broken its app bundle before.
 *
 * Decision logic lives in the pure `scripts/pack-integrity.ts`; this file only
 * turns git and the filesystem into that module's inputs. `node:child_process`
 * is imported here and MUST NOT become reachable from anything under `test/`.
 */

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assessPackIntegrity, buildBuildInfo } from '../pack-integrity';
import { canonicalScoringContractJson } from '../../packages/dns-checks/src/scoring/contract';

/**
 * Resolve the repo root from this file's own location rather than from cwd.
 * npm sets cwd to the package directory for `prepack`, but this script is also
 * runnable by hand from the repo root, and the two must agree.
 */
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PKG_DIR = join(REPO_ROOT, 'packages', 'dns-checks');
const PKG_REL = 'packages/dns-checks';

function git(args: string[]): { ok: boolean; stdout: string } {
	const res = spawnSync('git', args, { cwd: REPO_ROOT, encoding: 'utf8' });
	return { ok: res.status === 0, stdout: res.stdout ?? '' };
}

function versionFromPackageJsonText(text: string): string | null {
	try {
		const v = (JSON.parse(text) as { version?: unknown }).version;
		return typeof v === 'string' ? v : null;
	} catch {
		return null;
	}
}

function main(): void {
	const pkgPath = join(PKG_DIR, 'package.json');
	let workingVersion: string | null = null;
	let pkgName = '@blackveil/dns-checks';
	try {
		const text = readFileSync(pkgPath, 'utf8');
		workingVersion = versionFromPackageJsonText(text);
		const parsed = JSON.parse(text) as { name?: unknown };
		if (typeof parsed.name === 'string') pkgName = parsed.name;
	} catch {
		workingVersion = null;
	}

	// `git status --porcelain -- <path>` returns 0 with empty output on a clean
	// path, so a non-zero exit means git itself failed, not that the tree is dirty.
	const status = git(['status', '--porcelain', '--', PKG_REL]);
	const rev = git(['rev-parse', 'HEAD']);
	const headPkg = git(['show', `HEAD:${PKG_REL}/package.json`]);

	const gitUnavailable = !status.ok;
	const headCommit = rev.ok ? rev.stdout.trim() || null : null;
	const headVersion = headPkg.ok ? versionFromPackageJsonText(headPkg.stdout) : null;

	const verdict = assessPackIntegrity({
		scopedPorcelain: status.ok ? status.stdout : '',
		workingVersion,
		headVersion,
		headCommit,
		gitUnavailable,
		allowUncommitted: process.env.BV_ALLOW_UNCOMMITTED_PACK === '1',
	});

	if (!verdict.ok) {
		console.error(`\n${verdict.message}\n`);
		process.exit(1);
	}

	if (verdict.code === 'override') console.error(`\n${verdict.message}\n`);

	const contractJson = canonicalScoringContractJson();
	const scoringContractSha256 = createHash('sha256').update(contractJson).digest('hex');
	const buildInfo = buildBuildInfo({
		name: pkgName,
		version: workingVersion ?? '0.0.0',
		commit: verdict.commit,
		provenance: verdict.provenance,
		scoringContractSha256,
	});

	const distDir = join(PKG_DIR, 'dist');
	if (!existsSync(distDir)) mkdirSync(distDir, { recursive: true });
	// Trailing newline, 2-space indent: a stable serialization, so re-packing the
	// same commit reproduces byte-identical output and the downstream sha256 pin
	// stays meaningful.
	writeFileSync(join(distDir, 'BUILD_INFO.json'), `${JSON.stringify(buildInfo, null, 2)}\n`, 'utf8');
	writeFileSync(join(distDir, 'SCORING_CONTRACT.json'), contractJson, 'utf8');

	console.log(
		`${verdict.message}\nStamped dist/BUILD_INFO.json and dist/SCORING_CONTRACT.json ` +
			`(contract sha256=${scoringContractSha256}).`,
	);
}

main();
