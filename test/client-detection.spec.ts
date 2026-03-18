import { describe, it, expect } from 'vitest';
import { detectMcpClient } from '../src/lib/client-detection';

describe('detectMcpClient', () => {
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

	it('detects Windsurf', () => {
		expect(detectMcpClient('windsurf/1.0.0')).toBe('windsurf');
		expect(detectMcpClient('Windsurf/2.0')).toBe('windsurf');
	});

	it('detects mcp-remote bridge', () => {
		expect(detectMcpClient('mcp-remote/1.0.0')).toBe('mcp_remote');
	});

	it('returns unknown for unrecognized agents', () => {
		expect(detectMcpClient('curl/7.68.0')).toBe('unknown');
		expect(detectMcpClient('')).toBe('unknown');
		expect(detectMcpClient(undefined)).toBe('unknown');
	});
});
