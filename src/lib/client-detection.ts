// SPDX-License-Identifier: BUSL-1.1

/**
 * MCP client detection from User-Agent headers.
 * Used for analytics segmentation — not security decisions.
 */

export type McpClientType = 'claude_mobile' | 'claude_code' | 'cursor' | 'vscode' | 'claude_desktop' | 'windsurf' | 'mcp_remote' | 'blackveil_dns_action' | 'bv_claude_dns_proxy' | 'unknown';

const CLIENT_PATTERNS: ReadonlyArray<[RegExp, McpClientType]> = [
	[/claude[-_]?mobile|claude\.ai\/(android|ios)|claudeai[-_]?mobile/i, 'claude_mobile'],
	[/claude[-_]?code/i, 'claude_code'],
	[/claude[-_]?desktop/i, 'claude_desktop'],
	[/cursor/i, 'cursor'],
	[/windsurf/i, 'windsurf'],
	[/visual studio code|vscode|github copilot/i, 'vscode'],
	[/mcp-remote/i, 'mcp_remote'],
	[/blackveil[-_]?dns[-_]?action/i, 'blackveil_dns_action'],
	[/bv[-_]?claude[-_]?dns[-_]?proxy/i, 'bv_claude_dns_proxy'],
];

/** Detect MCP client from User-Agent string. Order matters — first match wins. */
export function detectMcpClient(userAgent?: string): McpClientType {
	if (!userAgent) return 'unknown';
	for (const [pattern, client] of CLIENT_PATTERNS) {
		if (pattern.test(userAgent)) return client;
	}
	return 'unknown';
}
