/** @vitest-environment node */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

// Repo-WIDE sweep for the forbidden licence phrasing. The licence is Business
// Source License 1.1 — which its own Notice disclaims as not an open-source
// licence (LICENSE:25) — so the fleet brand-voice guide (bv-web-prod
// `docs/brand-voice-guide.md:117`, a DIFFERENT repo) requires "source-available".
//
// WHY THIS EXISTS ALONGSIDE busl-positioning.audit.test.ts. That audit already
// had a "does not market the current BUSL release as open source" case, and it
// still MISSED two live claims (found 2026-09-13):
//   - src/mcp/dispatch.ts serverInfo.description — on the wire in every MCP
//     `initialize` response;
//   - public/index.html <title> — the public landing page.
// It missed them because its `checkedSources` is a hand-enumerated map of five
// files. An allowlist guard cannot see a surface nobody remembered to add, and
// it silently gets weaker as the repo grows.
//
// This sweep therefore takes `git ls-files` with NO pathspec. Every tracked file
// is in scope the moment it is tracked — including the surfaces an enumeration
// is most likely to forget: `server.json` (the MCP registry listing),
// `smithery.yaml`, and `extensions/vscode/**` (the marketplace listing).
//
// A first cut of this audit scoped itself to `src packages public .github` plus
// four root .md files — 558 of 1468 tracked files. That reproduced the very
// defect it was written to fix, so the pathspec was removed rather than the
// claim weakened.
//
// Keep BOTH audits: the other asserts positive phrasing and licence metadata;
// this one asserts the absence of the claim everywhere.
//
// Runs in the node pool (needs git + fs; the Workers pool has neither).

const repoRoot = process.cwd();

// "open source" / "open-source", any case. \b both ends so it cannot fire on an
// unrelated compound. NOTE for anyone re-running this by hand on macOS: use
// `git grep -P`, not `-E` — BSD grep's -E does not support \b and returns a
// false zero.
const FORBIDDEN_CLAIM = /\bopen[- ]source\b/i;

// Binary/asset extensions: readFileSync(…, 'utf8') on these yields mojibake that
// cannot be meaningfully matched, and scanning them is pure cost.
const BINARY_EXT = /\.(png|jpe?g|gif|ico|svg|webp|woff2?|ttf|eot|pdf|tgz|zip|gz|mp4|webm|wasm)$/i;

function isExempt(file: string): boolean {
	// The stock BUSL Notice reads "...will eventually be made available under an
	// Open Source License" — and the sentence before it explicitly disclaims the
	// CURRENT grant. That is licence boilerplate, not a product claim. All three
	// LICENSE files are held byte-identical by busl-positioning.audit.test.ts.
	if (/(^|\/)LICENSE$/.test(file)) return true;
	// Tests quote the forbidden string in order to assert against it. This also
	// covers dependency-license.audit.test.ts, which records THIRD-PARTY licences
	// (many genuinely open source) — it needs no exemption of its own.
	if (/\.(test|spec)\.(ts|mts|mjs|js)$/.test(file)) return true;
	if (BINARY_EXT.test(file)) return true;
	return false;
}

function sweptFiles(): string[] {
	// No pathspec: every tracked file. Deliberate — see the header.
	const out = execFileSync('git', ['ls-files'], { cwd: repoRoot, encoding: 'utf8' });
	return out.split('\n').filter(Boolean).filter((f) => !isExempt(f));
}

describe('BUSL positioning — repo-wide sweep', () => {
	const files = sweptFiles();

	it('sweeps the whole tracked surface, not a subset', () => {
		// Guards the guard twice over. A bare count floor is weak — the first cut
		// swept 488 files and would have passed a `> 50` floor while missing two
		// thirds of the repo — so the real assertion is the explicit path list
		// below: the high-visibility surfaces an enumeration forgets.
		// Measured 2026-09-13: 1468 tracked, 750 exempted (mostly *.test.ts),
		// 718 swept. The floor catches a total pathspec/cwd collapse, nothing subtler.
		expect(files.length).toBeGreaterThan(600);
		for (const path of [
			'src/mcp/dispatch.ts', // the MCP initialize handshake
			'public/index.html', // the public landing page
			'server.json', // the MCP registry listing
			'smithery.yaml', // the Smithery listing
			'extensions/vscode/README.md', // the VS Code marketplace listing
			'extensions/vscode/package.json',
			'README.md',
			'CLAUDE.md',
		]) {
			expect(files, `${path} must be in the swept set`).toContain(path);
		}
	});

	it('never claims the BUSL-licensed product is open source', () => {
		const offenders = files
			.map((file) => {
				let text: string;
				try {
					text = readFileSync(join(repoRoot, file), 'utf8');
				} catch {
					return null; // deleted-but-tracked mid-rebase; not this audit's business
				}
				if (!FORBIDDEN_CLAIM.test(text)) return null;
				const line = text.split('\n').findIndex((l) => FORBIDDEN_CLAIM.test(l)) + 1;
				return `${file}:${line}`;
			})
			.filter((hit): hit is string => hit !== null);

		expect(
			offenders,
			`Say "source-available" — the licence is BUSL-1.1.\nOffenders:\n${offenders.join('\n')}`,
		).toEqual([]);
	});
});
