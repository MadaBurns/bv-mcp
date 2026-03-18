// SPDX-License-Identifier: BUSL-1.1

/**
 * MCP client detection from User-Agent headers.
 * Used for analytics segmentation — not security decisions.
 */

export type McpClientType = 'claude_code' | 'cursor' | 'vscode' | 'claude_desktop' | 'windsurf' | 'mcp_remote' | 'unknown';

const CLIENT_PATTERNS: ReadonlyArray<[RegExp, McpClientType]> = [
	[/claude[-_]?code/i, 'claude_code'],
	[/claude[-_]?desktop/i, 'claude_desktop'],
	[/cursor/i, 'cursor'],
	[/windsurf/i, 'windsurf'],
	[/visual studio code|vscode|github copilot/i, 'vscode'],
	[/mcp-remote/i, 'mcp_remote'],
];

/** Detect MCP client from User-Agent string. Order matters — first match wins. */
export function detectMcpClient(userAgent?: string): McpClientType {
	if (!userAgent) return 'unknown';
	for (const [pattern, client] of CLIENT_PATTERNS) {
		if (pattern.test(userAgent)) return client;
	}
	return 'unknown';
}
