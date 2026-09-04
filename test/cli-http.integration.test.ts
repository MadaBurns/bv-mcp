// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { McpClientError, McpHttpClient, parseMcpResponseBody } from '../src/cli/mcp-http-client';

function rpc(result: unknown, headers: HeadersInit = {}): Response {
	return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200, headers });
}

describe('hosted MCP HTTP client', () => {
	it('initializes a session and keeps credentials in an authorization header', async () => {
		const requests: Array<{ url: string; init?: RequestInit }> = [];
		const responses = [
			rpc({ serverInfo: { name: 'blackveil-dns-mcp', version: '1.2.3' } }, { 'mcp-session-id': 'session-1' }),
			new Response('', { status: 202 }),
			rpc({ content: [{ type: 'text', text: 'ok' }], structuredContent: { domain: 'example.com' } }),
		];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			apiKey: 'test-secret',
			fetchFn: (async (url, init) => {
				requests.push({ url: String(url), init });
				return responses.shift()!;
			}) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});

		await client.connect();
		await client.callTool('scan_domain', { domain: 'example.com' });

		expect(requests).toHaveLength(3);
		expect(requests.every((request) => request.url === 'https://example.test/mcp')).toBe(true);
		for (const request of requests) expect(new Headers(request.init?.headers).get('authorization')).toBe('Bearer test-secret');
		expect(new Headers(requests[2]?.init?.headers).get('mcp-session-id')).toBe('session-1');
		expect(JSON.parse(String(requests[2]?.init?.body))).toMatchObject({ method: 'tools/call', params: { name: 'scan_domain' } });
	});

	it('parses JSON and SSE response bodies', () => {
		expect(parseMcpResponseBody('{"jsonrpc":"2.0","result":{}}')).toMatchObject({ jsonrpc: '2.0' });
		expect(parseMcpResponseBody('event: message\ndata: {"jsonrpc":"2.0","result":{"ok":true}}\n\n')).toMatchObject({
			result: { ok: true },
		});
	});

	it.each([401, 403, 429, 500])('maps HTTP %s to a remote error', async (status) => {
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => new Response('', { status })) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});
		await expect(client.connect()).rejects.toMatchObject<McpClientError>({ kind: 'remote', status });
	});

	it('fails closed when initialize does not issue a session', async () => {
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => rpc({ serverInfo: { name: 'server', version: '1' } })) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});
		await expect(client.connect()).rejects.toMatchObject({ kind: 'protocol' });
	});

	it('rejects endpoints that could expose credentials through URLs', () => {
		expect(() => new McpHttpClient({ endpoint: 'https://example.test/mcp?key=secret' })).toThrow('query strings');
		expect(() => new McpHttpClient({ endpoint: 'http://example.test/mcp' })).toThrow('HTTPS');
	});
});
