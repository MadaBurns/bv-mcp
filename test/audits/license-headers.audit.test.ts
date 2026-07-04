/** @vitest-environment node */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// Enforces license-header hygiene across the shipped TypeScript surface:
// every source file carries the BUSL-1.1 SPDX identifier, and no header
// carries the stale "BSL 1.1" abbreviation or the "Ltd." entity form.
// Runs in the node pool (needs git + fs; the Workers pool has neither).

const repoRoot = process.cwd();
const SPDX_HEADER = '// SPDX-License-Identifier: BUSL-1.1';

function trackedSourceFiles(): string[] {
	// List everything tracked under src/ and packages/, then filter in JS to the
	// shipped-source .ts set. NOTE: do NOT use git pathspec globs like
	// 'src/**/*.ts' here — git's `**/` requires an intermediate path segment, so
	// it silently MISSES files directly in src/ or packages/*/src/ (e.g.
	// packages/dns-checks/src/index.ts). Directory pathspecs + a JS regex filter
	// cover every depth.
	const out = execFileSync('git', ['ls-files', '--', 'src', 'packages'], {
		cwd: repoRoot,
		encoding: 'utf8',
	});
	return out
		.split('\n')
		.filter(Boolean)
		.filter((f) => /^src\/.*\.ts$/.test(f) || /^packages\/[^/]+\/src\/.*\.ts$/.test(f))
		.filter((f) => !/\.(test|spec)\.ts$/.test(f))
		.filter((f) => !f.includes('/__tests__/'));
}

describe('license header hygiene', () => {
	const files = trackedSourceFiles();

	it('finds a non-trivial set of shipped source files', () => {
		// Guard against a glob that silently matches nothing (which would make
		// every assertion below vacuously pass).
		expect(files.length).toBeGreaterThan(100);
	});

	it('carries the BUSL-1.1 SPDX identifier on every shipped source file', () => {
		const missing = files.filter((f: string) => {
			const head = readFileSync(join(repoRoot, f), 'utf8').split('\n').slice(0, 5).join('\n');
			return !head.includes(SPDX_HEADER);
		});
		expect(missing).toEqual([]);
	});

	it('uses the canonical license name + holder in every header (no "BSL 1.1" / "Ltd.")', () => {
		const offenders = files.filter((f: string) => {
			const text = readFileSync(join(repoRoot, f), 'utf8');
			return /\bBSL 1\.1\b/.test(text) || /BlackVeil Security Ltd\.?/.test(text);
		});
		expect(offenders).toEqual([]);
	});
});
