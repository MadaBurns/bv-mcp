#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

/**
 * Version-bump automation — npm `version` lifecycle hook.
 *
 * Wired as the `version` script in package.json, so it runs automatically
 * inside `npm version <X.Y.Z> --no-git-tag-version` AFTER npm has already
 * rewritten package.json (and package-lock.json). This script reads the
 * already-bumped version back out of package.json and applies it to the
 * other two hand-edited release surfaces CLAUDE.md documents:
 *
 *   - server.json's top-level `"version"` field
 *   - a `## [X.Y.Z] - YYYY-MM-DD` CHANGELOG.md heading (idempotent — a
 *     developer who already wrote the real release notes under that
 *     heading is left untouched; otherwise a stub is inserted)
 *
 * `git add server.json CHANGELOG.md` at the end is ESSENTIAL, not cosmetic:
 * npm's `version` lifecycle auto-stages only package.json and
 * package-lock.json. Anything else this script edits would otherwise be
 * silently omitted from the release commit npm creates next (or, with
 * `--no-git-tag-version`, simply left as unstaged working-tree changes the
 * next `git commit -am` picks up incidentally — either way, staging it here
 * explicitly makes the intent visible rather than accidental).
 *
 * Deliberately does NOT touch packages/dns-checks/package.json — that
 * package versions independently (see CLAUDE.md).
 *
 * All node:* I/O lives here, in the CLI half. The pure string transforms
 * live in the sibling `scripts/bump-version-core.mjs`, which is what
 * `test/bump-version.spec.ts` imports (see that module's header for why).
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { updateServerJsonVersion, insertChangelogEntry } from './bump-version-core.mjs';

const SERVER_JSON_PATH = 'server.json';
const CHANGELOG_PATH = 'CHANGELOG.md';
const PACKAGE_JSON_PATH = 'package.json';

function readVersionFromPackageJson() {
	const raw = readFileSync(PACKAGE_JSON_PATH, 'utf8');
	const pkg = JSON.parse(raw);
	const version = pkg.version;
	if (typeof version !== 'string' || version.length === 0) {
		throw new Error(`${PACKAGE_JSON_PATH}: no "version" string found — expected npm to have already bumped it`);
	}
	return version;
}

function main() {
	const version = readVersionFromPackageJson();

	const serverJsonBefore = readFileSync(SERVER_JSON_PATH, 'utf8');
	const serverJsonAfter = updateServerJsonVersion(serverJsonBefore, version);
	writeFileSync(SERVER_JSON_PATH, serverJsonAfter);

	const changelogBefore = readFileSync(CHANGELOG_PATH, 'utf8');
	const { content: changelogAfter, inserted } = insertChangelogEntry(changelogBefore, version, new Date());
	if (inserted) {
		writeFileSync(CHANGELOG_PATH, changelogAfter);
		console.error(
			`\nbump-version: inserted a CHANGELOG.md stub for [${version}] — this needs REAL release notes before shipping.\n`,
		);
	}

	// npm's `version` lifecycle only auto-stages package.json + package-lock.json.
	// Without this, server.json and any CHANGELOG.md edit would be silently
	// dropped from the release commit.
	execFileSync('git', ['add', SERVER_JSON_PATH, CHANGELOG_PATH]);

	console.log(`bump-version: server.json -> ${version}${inserted ? ` (CHANGELOG.md stub inserted)` : ' (CHANGELOG.md already had this heading)'}`);
}

main();
