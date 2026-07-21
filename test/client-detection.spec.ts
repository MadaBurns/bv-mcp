import { describe, it, expect } from 'vitest';
import { detectMcpClient } from '../src/lib/client-detection';

describe('detectMcpClient', () => {
	it('detects Claude Mobile', () => {
		expect(detectMcpClient('claude-mobile/1.0.0')).toBe('claude_mobile');
		expect(detectMcpClient('ClaudeMobile/1.0.0')).toBe('claude_mobile');
		expect(detectMcpClient('claude.ai/ios/1.0.0')).toBe('claude_mobile');
		expect(detectMcpClient('claude.ai/android/1.0.0')).toBe('claude_mobile');
		expect(detectMcpClient('claudeai-mobile/1.0.0')).toBe('claude_mobile');
	});

	it('does not confuse claude_mobile with claude_code or claude_desktop', () => {
		// claude-code must not match mobile
		expect(detectMcpClient('claude-code/1.0.0')).toBe('claude_code');
		// claude-desktop must not match mobile
		expect(detectMcpClient('claude-desktop/1.0.0')).toBe('claude_desktop');
	});

	it('detects Claude Code', () => {
		expect(detectMcpClient('claude-code/1.0.0')).toBe('claude_code');
		expect(detectMcpClient('Claude-Code/2.1.3 Node/20.0.0')).toBe('claude_code');
	});

	it('detects Cursor', () => {
		expect(detectMcpClient('cursor/0.45.0')).toBe('cursor');
		expect(detectMcpClient('Mozilla/5.0 Cursor/0.45.0')).toBe('cursor');
	});

	it('detects VS Code / Copilot', () => {
		expect(detectMcpClient('vscode/1.90.0')).toBe('vscode');
		expect(detectMcpClient('Visual Studio Code/1.90.0')).toBe('vscode');
		expect(detectMcpClient('GitHub Copilot/1.0')).toBe('vscode');
	});

	it('detects Claude Desktop', () => {
		expect(detectMcpClient('claude-desktop/1.0.0')).toBe('claude_desktop');
		expect(detectMcpClient('ClaudeDesktop/1.0.0')).toBe('claude_desktop');
	});

	it('detects the Anthropic-hosted remote MCP connector (Claude-User UA)', () => {
		// The claude.ai / claude.com / Desktop / mobile "custom connector" reaches the
		// worker from Anthropic's cloud infra with User-Agent `Claude-User` (verified via
		// the 2026-07-02 connector-unblock incident). Robust to a version/URL suffix.
		expect(detectMcpClient('Claude-User/1.0')).toBe('claude_connector');
		expect(detectMcpClient('Claude-User/1.0 (+https://claude.ai)')).toBe('claude_connector');
		expect(detectMcpClient('claude_user/2.0')).toBe('claude_connector');
		expect(detectMcpClient('ClaudeUser')).toBe('claude_connector');
	});

	it('does not confuse the connector with local Claude clients', () => {
		// Claude-User must NOT steal claude_code / claude_desktop / claude_mobile, and
		// those local-client UAs must NOT collapse into the connector bucket.
		expect(detectMcpClient('claude-code/2.1.0')).toBe('claude_code');
		expect(detectMcpClient('claude-desktop/1.0.0')).toBe('claude_desktop');
		expect(detectMcpClient('claude-mobile/1.0.0')).toBe('claude_mobile');
	});

	it('detects Windsurf', () => {
		expect(detectMcpClient('windsurf/1.0.0')).toBe('windsurf');
		expect(detectMcpClient('Windsurf/2.0')).toBe('windsurf');
	});

	it('detects mcp-remote bridge', () => {
		expect(detectMcpClient('mcp-remote/1.0.0')).toBe('mcp_remote');
	});

	it('detects blackveil-dns-action', () => {
		expect(detectMcpClient('blackveil-dns-action/1.2.0')).toBe('blackveil_dns_action');
		expect(detectMcpClient('blackveil_dns_action/1.0.0')).toBe('blackveil_dns_action');
	});

	it('detects bv-claude-dns-proxy', () => {
		expect(detectMcpClient('bv-claude-dns-proxy/1.1.0')).toBe('bv_claude_dns_proxy');
		expect(detectMcpClient('bv_claude_dns_proxy/1.0.0')).toBe('bv_claude_dns_proxy');
	});

	it('returns unknown for unrecognized agents', () => {
		expect(detectMcpClient('curl/7.68.0')).toBe('unknown');
		expect(detectMcpClient('')).toBe('unknown');
		expect(detectMcpClient(undefined)).toBe('unknown');
	});

	it('detects internal bv load-test clients', () => {
		expect(detectMcpClient('bv-load-test/1.0')).toBe('bv_load_test');
		expect(detectMcpClient('bv-chaos-test/1.0 node/20')).toBe('bv_load_test');
		expect(detectMcpClient('bv-tranco-scan/1.0')).toBe('bv_load_test');
		// Case-insensitive + alternate separators
		expect(detectMcpClient('BV_Load_Test/1.0')).toBe('bv_load_test');
	});
});
