// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the version-bump decision core (release automation).
 *
 * Imports ONLY `scripts/bump-version-core.mjs`, which is pure by design. The
 * CLI that performs git/fs I/O lives in `scripts/bump-version.mjs` and is
 * deliberately NOT imported here — see `scripts/release-integrity.ts` /
 * `test/release-integrity.spec.ts` for the same split and the reason
 * (`node:child_process` is not real in this Workers pool and importing it is
 * a hard SIGSEGV, not a catchable failure).
 */

import { describe, expect, it } from 'vitest';
import { updateServerJsonVersion, insertChangelogEntry } from '../scripts/bump-version-core.mjs';

const REAL_SERVER_JSON = `{
\t"$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
\t"name": "com.blackveilsecurity/dns",
\t"description": "DNS and email security scanner with 76 MCP tools for SPF, DMARC, DNSSEC, SSL, and brand audits.",
\t"repository": {
\t\t"url": "https://github.com/MadaBurns/bv-mcp",
\t\t"source": "github"
\t},
\t"version": "3.63.0",
\t"remotes": [
\t\t{
\t\t\t"type": "streamable-http",
\t\t\t"url": "https://dns-mcp.blackveilsecurity.com/mcp"
\t\t}
\t]
}
`;

const REAL_CHANGELOG = `# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Some unreleased notes.

## [3.63.0] - 2026-08-21

### Changed

- Something.

## [3.62.0] - 2026-08-21

### Fixed

- Something else.
`;

describe('updateServerJsonVersion', () => {
	it('changes exactly one line of real server.json content — a pure 1-insertion/1-deletion edit', () => {
		const after = updateServerJsonVersion(REAL_SERVER_JSON, '3.64.0');

		const beforeLines = REAL_SERVER_JSON.split('\n');
		const afterLines = after.split('\n');

		expect(afterLines.length).toBe(beforeLines.length);

		const diffIndexes: number[] = [];
		for (let i = 0; i < beforeLines.length; i++) {
			if (beforeLines[i] !== afterLines[i]) diffIndexes.push(i);
		}

		expect(diffIndexes.length).toBe(1);
		expect(beforeLines[diffIndexes[0]]).toBe('\t"version": "3.63.0",');
		expect(afterLines[diffIndexes[0]]).toBe('\t"version": "3.64.0",');

		// Every other line is byte-identical.
		for (let i = 0; i < beforeLines.length; i++) {
			if (i === diffIndexes[0]) continue;
			expect(afterLines[i]).toBe(beforeLines[i]);
		}
	});

	it('never round-trips through JSON.parse/stringify (would reformat the whole file)', () => {
		const after = updateServerJsonVersion(REAL_SERVER_JSON, '3.64.0');
		// A JSON.stringify(obj, null, '\t') re-serialization is byte-identical in
		// structure to this fixture (already tab-indented), so the strongest
		// available guard is the exact single-line-diff assertion above — this
		// test additionally pins that the trailing newline and lack of a
		// reordered/re-quoted key set survive untouched.
		expect(after.endsWith('}\n')).toBe(true);
		expect(after).toContain('"$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",');
	});

	it('throws when the version line is absent', () => {
		const noVersion = REAL_SERVER_JSON.replace('\t"version": "3.63.0",\n', '');
		expect(() => updateServerJsonVersion(noVersion, '3.64.0')).toThrow();
	});

	it('throws when the version line is duplicated', () => {
		const duped = REAL_SERVER_JSON.replace('\t"version": "3.63.0",\n', '\t"version": "3.63.0",\n\t"version": "3.63.0",\n');
		expect(() => updateServerJsonVersion(duped, '3.64.0')).toThrow();
	});

	it('does not match a version line with the wrong indentation (spaces instead of a tab)', () => {
		const spaceIndented = REAL_SERVER_JSON.replace('\t"version": "3.63.0",\n', '  "version": "3.63.0",\n');
		expect(() => updateServerJsonVersion(spaceIndented, '3.64.0')).toThrow();
	});
});

describe('insertChangelogEntry', () => {
	const now = new Date('2026-08-23T12:00:00Z');

	it('is idempotent when the heading already exists', () => {
		const result = insertChangelogEntry(REAL_CHANGELOG, '3.63.0', now);
		expect(result.inserted).toBe(false);
		expect(result.content).toBe(REAL_CHANGELOG);
	});

	it('inserts above the previous top heading with today\'s date, leaving everything after untouched', () => {
		const result = insertChangelogEntry(REAL_CHANGELOG, '3.64.0', now);
		expect(result.inserted).toBe(true);

		const headingIndex = result.content.indexOf('## [3.64.0] - 2026-08-23');
		const unreleasedIndex = result.content.indexOf('## [Unreleased]');
		expect(headingIndex).toBeGreaterThanOrEqual(0);
		expect(unreleasedIndex).toBeGreaterThan(headingIndex);

		// Everything from the previous first heading onward is byte-identical —
		// only content was inserted above it, nothing below was rewritten.
		const originalFromFirstHeading = REAL_CHANGELOG.slice(REAL_CHANGELOG.indexOf('## [Unreleased]'));
		const newFromOldHeading = result.content.slice(unreleasedIndex);
		expect(newFromOldHeading).toBe(originalFromFirstHeading);

		// Everything before the first heading (the file intro) is preserved too.
		const originalIntro = REAL_CHANGELOG.slice(0, REAL_CHANGELOG.indexOf('## [Unreleased]'));
		const newIntro = result.content.slice(0, headingIndex);
		expect(newIntro).toBe(originalIntro);
	});

	it('inserts above the first heading even when there is no Unreleased section', () => {
		const noUnreleased = REAL_CHANGELOG.replace(/## \[Unreleased\]\n\nSome unreleased notes\.\n\n/, '');
		const result = insertChangelogEntry(noUnreleased, '3.64.0', now);
		expect(result.inserted).toBe(true);

		const headingIndex = result.content.indexOf('## [3.64.0] - 2026-08-23');
		const priorTopIndex = result.content.indexOf('## [3.63.0]');
		expect(headingIndex).toBeGreaterThanOrEqual(0);
		expect(priorTopIndex).toBeGreaterThan(headingIndex);
	});

	it('throws when the file has no "## [" heading to insert above', () => {
		const noHeadings = '# Changelog\n\nNothing here yet.\n';
		expect(() => insertChangelogEntry(noHeadings, '3.64.0', now)).toThrow();
	});
});
