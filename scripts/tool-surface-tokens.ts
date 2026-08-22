// SPDX-License-Identifier: BUSL-1.1

/**
 * The single source of truth for where the public tool count appears in prose.
 *
 * PURE — no `node:*` imports, so this is importable from a Vitest spec running
 * in the Workers pool (which has no filesystem). The CLI half that actually
 * reads and writes files lives in `scripts/generate-tool-surface.ts`. Same
 * split as `release-integrity.ts` / `release-integrity-check.ts`.
 *
 * Both the generator and `test/audits/tool-surface-prose.audit.test.ts` consume
 * this table, so the token shapes are defined once. Adding a new piece of prose
 * that advertises the count means adding one entry here and nothing else.
 */

import { INTERNAL_ONLY_TOOLS } from '../src/lib/config';
import { TOOLS } from '../src/schemas/tool-definitions';

const PUBLIC_TOOLS = TOOLS.filter((tool) => !INTERNAL_ONLY_TOOLS.has(tool.name));

/** Tools reachable via the public `tools/list`. */
export const PUBLIC_TOOL_COUNT = PUBLIC_TOOLS.length;

/**
 * Public `check_*` tools. Filtered over PUBLIC_TOOLS, not TOOLS, so the number
 * stays correct if an internal-only tool ever takes a `check_` prefix.
 */
export const CHECK_TOOL_COUNT = PUBLIC_TOOLS.filter((tool) => tool.name.startsWith('check_')).length;

export interface ToolSurfaceToken {
	/** Repo-relative path. */
	file: string;
	/** Must contain exactly one capture group: the digits to rewrite. */
	pattern: RegExp;
	expected: number;
	/** Human-readable location, used in drift reports. */
	label: string;
}

/**
 * Every count token in customer-facing prose.
 *
 * Each pattern is anchored on enough surrounding text to pin ONE specific
 * occurrence. That precision is the point: the audits previously used
 * `.toContain('76 MCP tools')`, which any single occurrence satisfies — so
 * README's ASCII header could go stale silently while the assertion stayed
 * green on a different line.
 */
export const TOOL_SURFACE_TOKENS: ToolSurfaceToken[] = [
	{ file: 'README.md', pattern: /MCP%20tools-(\d+)-brightgreen/, expected: PUBLIC_TOOL_COUNT, label: 'README shields badge' },
	{ file: 'README.md', pattern: /the current (\d+)-tool surface/, expected: PUBLIC_TOOL_COUNT, label: 'README install blurb' },
	{
		file: 'README.md',
		pattern: /\*\*(\d+) MCP tools with \d+ scoring categories\*\*/,
		expected: PUBLIC_TOOL_COUNT,
		label: 'README "What you get"',
	},
	{ file: 'README.md', pattern: /^ {2}(\d+) MCP tools · \d+ prompts · \d+ resources$/m, expected: PUBLIC_TOOL_COUNT, label: 'README ASCII header' },
	{
		file: 'docs/github-settings.md',
		pattern: /(\d+) MCP tools for SPF, DMARC, DKIM, DNSSEC, SSL\/TLS/,
		expected: PUBLIC_TOOL_COUNT,
		label: 'github-settings repo description',
	},
	{
		file: 'extensions/vscode/README.md',
		pattern: /\*\*(\d+) DNS & email security tools\*\*/,
		expected: PUBLIC_TOOL_COUNT,
		label: 'vscode README hero',
	},
	{ file: 'extensions/vscode/README.md', pattern: /All (\d+) tools are available instantly\./, expected: PUBLIC_TOOL_COUNT, label: 'vscode README quick start' },
	{ file: 'extensions/vscode/README.md', pattern: /## Tools \((\d+)\)/, expected: PUBLIC_TOOL_COUNT, label: 'vscode README Tools heading' },
	{
		file: 'extensions/vscode/README.md',
		pattern: /surface: (\d+) tools, including \d+ `check_\*` tools\./,
		expected: PUBLIC_TOOL_COUNT,
		label: 'vscode README tools/list surface (tools)',
	},
	{
		file: 'extensions/vscode/README.md',
		pattern: /surface: \d+ tools, including (\d+) `check_\*` tools\./,
		expected: CHECK_TOOL_COUNT,
		label: 'vscode README tools/list surface (check_*)',
	},
	{
		file: 'extensions/vscode/package.json',
		pattern: /"description": "(\d+) DNS & email security tools for GitHub Copilot Chat/,
		expected: PUBLIC_TOOL_COUNT,
		label: 'vscode package.json description',
	},
	{
		file: 'server.json',
		pattern: /"description": "DNS and email security scanner with (\d+) MCP tools/,
		expected: PUBLIC_TOOL_COUNT,
		label: 'server.json description',
	},
	{
		file: 'smithery.yaml',
		pattern: /DNS and email security scanner with (\d+) MCP tools\./,
		expected: PUBLIC_TOOL_COUNT,
		label: 'smithery.yaml description',
	},
];

/**
 * Rewrites the single captured group in place, leaving every other byte alone.
 *
 * `current: null` means the pattern did not match at all — the prose drifted
 * out from under the token table and the regex needs updating. That is itself
 * drift worth failing on, not a no-op.
 */
export function applyToken(content: string, token: ToolSurfaceToken): { next: string; current: number | null } {
	const match = content.match(token.pattern);
	if (!match || match.index === undefined) return { next: content, current: null };

	const groupOffset = match.index + match[0].indexOf(match[1]);
	const next = content.slice(0, groupOffset) + String(token.expected) + content.slice(groupOffset + match[1].length);
	return { next, current: Number(match[1]) };
}
