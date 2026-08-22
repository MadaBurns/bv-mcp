// SPDX-License-Identifier: BUSL-1.1

/**
 * Enforces that every customer-facing count token matches the derived public
 * tool surface.
 *
 * Why this exists alongside `npm run check:tool-surface`: that script runs in
 * `ci.yml`'s `fast-checks` job, which is NOT one of branch protection's
 * required checks. This audit runs inside `npm test`, i.e. inside the required
 * `build-and-test` job — so it is the actual enforcement backstop. The script
 * gives the faster, friendlier local failure; this makes it un-mergeable.
 *
 * Both read the same table from `scripts/tool-surface-tokens.ts`, so the token
 * shapes are defined once. Adding a new count-bearing string means adding one
 * entry there — this audit picks it up with no edit.
 *
 * Note the pyramid layer: `.audit.test.ts` (a repo-wide invariant), not
 * `.spec.ts`.
 */

import { describe, expect, it } from 'vitest';
import githubSettings from '../../docs/github-settings.md?raw';
import readme from '../../README.md?raw';
import serverJson from '../../server.json?raw';
import smitheryYaml from '../../smithery.yaml?raw';
import vscodePackage from '../../extensions/vscode/package.json?raw';
import vscodeReadme from '../../extensions/vscode/README.md?raw';
import { CHECK_TOOL_COUNT, PUBLIC_TOOL_COUNT, TOOL_SURFACE_TOKENS } from '../../scripts/tool-surface-tokens';

/**
 * The Workers pool has no filesystem, so contents arrive via `?raw` imports
 * rather than being read by path. Keys must match `ToolSurfaceToken.file`.
 */
const SOURCES: Record<string, string> = {
	'README.md': readme,
	'docs/github-settings.md': githubSettings,
	'extensions/vscode/README.md': vscodeReadme,
	'extensions/vscode/package.json': vscodePackage,
	'server.json': serverJson,
	'smithery.yaml': smitheryYaml,
};

describe('tool-surface prose', () => {
	it('has a loaded source for every token file', () => {
		const missing = [...new Set(TOOL_SURFACE_TOKENS.map((t) => t.file))].filter((file) => SOURCES[file] === undefined);
		expect(missing, `add these to SOURCES so their tokens are actually checked: ${missing.join(', ')}`).toEqual([]);
	});

	it.each(TOOL_SURFACE_TOKENS.map((token) => [`${token.file} — ${token.label}`, token] as const))(
		'%s advertises the derived count',
		(_name, token) => {
			const content = SOURCES[token.file];
			const match = content.match(token.pattern);

			// A non-match means the prose changed shape out from under the token
			// table. That is drift too — the generator would silently skip it.
			expect(match, `pattern did not match; the prose changed shape. Update scripts/tool-surface-tokens.ts`).not.toBeNull();
			expect(Number(match![1]), `run: npm run generate:tool-surface`).toBe(token.expected);
		},
	);

	it('derives sane counts (guards against an empty registry import)', () => {
		expect(PUBLIC_TOOL_COUNT).toBeGreaterThan(0);
		expect(CHECK_TOOL_COUNT).toBeGreaterThan(0);
		expect(CHECK_TOOL_COUNT).toBeLessThanOrEqual(PUBLIC_TOOL_COUNT);
	});
});
