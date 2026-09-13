/** @vitest-environment node */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// Repo-WIDE sweep for the "open source" licence claim. The licence is
// Business Source License 1.1, which is NOT an open-source licence, so the
// brand-voice guide requires "source-available" everywhere.
//
// WHY THIS EXISTS ALONGSIDE busl-positioning.audit.test.ts. That audit already
// had a "does not market the current BUSL release as open source" case, and it
// still MISSED two live claims (found 2026-09-13):
//   - src/mcp/dispatch.ts serverInfo.description — the FIRST string every MCP
//     client reads on `initialize`, so any agent quoting serverInfo repeats it;
//   - public/index.html <title> — the public landing page.
// It missed them because its `checkedSources` is a hand-enumerated map of five
// files. An allowlist guard cannot see a surface nobody remembered to add, and
// it silently gets weaker as the repo grows. This sweep discovers files via
// `git ls-files` instead, so a NEW file is covered the moment it is tracked.
//
// Keep BOTH: the other audit asserts positive phrasing and licence metadata;
// this one asserts the absence of the claim across the whole tracked surface.
//
// Runs in the node pool (needs git + fs; the Workers pool has neither).

const repoRoot = process.cwd();

// Matches "open source", "open-source", any case. \b on both ends so it cannot
// fire on unrelated compounds.
const OPEN_SOURCE_CLAIM = /\bopen[- ]source\b/i;

// Paths that may legitimately contain the phrase.
function isExempt(file: string): boolean {
	// The BUSL text itself says "...under an Open Source License, as stated in
	// this License" — that is the Change License clause, not a claim about the
	// CURRENT grant. All three LICENSE files are byte-identical by another case
	// in busl-positioning.audit.test.ts.
	if (/(^|\/)LICENSE$/.test(file)) return true;
	// These audits quote the forbidden string in order to test for it.
	if (/\.(test|spec)\.ts$/.test(file)) return true;
	// Records the licences of THIRD-PARTY dependencies, many genuinely open source.
	if (file.endsWith('dependency-license.audit.test.ts')) return true;
	return false;
}

function sweptFiles(): string[] {
	// Directory pathspecs + a JS filter, never git globs like 'src/**/*.ts' —
	// git's `**/` requires an intermediate path segment and so silently misses
	// files sitting directly in a directory root. Same trap documented in
	// license-headers.audit.test.ts.
	const out = execFileSync(
		'git',
		[
			'ls-files',
			'--',
			'src',
			'packages',
			'public',
			'.github',
			'README.md',
			'CLAUDE.md',
			'AGENTS.md',
			'CONTRIBUTING.md',
		],
		{ cwd: repoRoot, encoding: 'utf8' },
	);
	return out.split('\n').filter(Boolean).filter((f) => !isExempt(f));
}

describe('BUSL positioning — repo-wide sweep', () => {
	const files = sweptFiles();

	it('sweeps a non-trivial set of tracked files', () => {
		// Guards the guard: a broken pathspec or a cwd surprise would return an
		// empty list, and every assertion below would then pass vacuously.
		expect(files.length).toBeGreaterThan(50);
	});

	it('covers the two surfaces the allowlist audit missed', () => {
		// Regression pin for the 2026-09-13 finding. If either path is renamed,
		// this fails loudly rather than quietly dropping coverage.
		expect(files).toContain('src/mcp/dispatch.ts');
		expect(files).toContain('public/index.html');
	});

	it('never claims the BUSL-licensed product is open source', () => {
		const offenders = files
			.map((file) => {
				let text: string;
				try {
					text = readFileSync(join(repoRoot, file), 'utf8');
				} catch {
					return null; // deleted-but-tracked during a rebase; not this audit's business
				}
				if (!OPEN_SOURCE_CLAIM.test(text)) return null;
				const line = text.split('\n').findIndex((l) => OPEN_SOURCE_CLAIM.test(l)) + 1;
				return `${file}:${line}`;
			})
			.filter((hit): hit is string => hit !== null);

		expect(
			offenders,
			`Say "source-available", never "open-source" — the licence is BUSL-1.1.\nOffenders:\n${offenders.join('\n')}`,
		).toEqual([]);
	});
});
