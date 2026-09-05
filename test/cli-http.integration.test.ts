// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { MCP_RESPONSE_BODY_MAX_BYTES, MCP_SSE_EVENT_MAX_BYTES, McpHttpClient, parseMcpResponseBody } from '../src/cli/mcp-http-client';

function rpc(result: unknown, headers: HeadersInit = {}, id = 1): Response {
	return new Response(JSON.stringify({ jsonrpc: '2.0', id, result }), {
		status: 200,
		headers: { 'content-type': 'application/json', ...Object.fromEntries(new Headers(headers)) },
	});
}

const initialized = (protocolVersion = '2025-06-18') => ({
	protocolVersion,
	serverInfo: { name: 'blackveil-dns-mcp', version: '1.2.3' },
});

describe('hosted MCP HTTP client', () => {
	it('initializes a session and keeps credentials in an authorization header', async () => {
		const requests: Array<{ url: string; init?: RequestInit }> = [];
		const responses = [
			rpc(initialized(), { 'mcp-session-id': 'session-1' }),
			new Response('', { status: 202 }),
			rpc({ content: [{ type: 'text', text: 'ok' }], structuredContent: { domain: 'example.com' } }, {}, 2),
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
		await expect(client.connect()).rejects.toMatchObject({ kind: 'remote', status });
	});

	it('rejects a successful request that omits its JSON-RPC response', async () => {
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => new Response('', { status: 200 })) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});
		await expect(client.connect()).rejects.toMatchObject({ kind: 'protocol' });
	});

	it('accepts a conforming server that does not issue a session', async () => {
		const responses = [
			rpc({ protocolVersion: '2025-06-18', serverInfo: { name: 'server', version: '1' } }),
			new Response('', { status: 202 }),
		];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => responses.shift()!) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});
		await expect(client.connect()).resolves.toMatchObject({ name: 'server' });
	});

	it('fails closed on a protocol version it does not support', async () => {
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => rpc(initialized('2099-01-01'))) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});
		await expect(client.connect()).rejects.toThrow('unsupported protocol version');
	});

	it('uses the negotiated protocol version on sessionless servers', async () => {
		const requests: RequestInit[] = [];
		const responses = [rpc(initialized('2025-03-26')), new Response('', { status: 202 }), rpc({ tools: [] }, {}, 2)];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async (_url, init) => {
				requests.push(init ?? {});
				return responses.shift()!;
			}) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});
		await client.connect();
		await client.listTools();
		expect(new Headers(requests[1]?.headers).get('mcp-protocol-version')).toBe('2025-03-26');
		expect(new Headers(requests[2]?.headers).get('mcp-session-id')).toBeNull();
	});

	it('returns a matched SSE response when stream cancellation rejects and releases the reader lock', async () => {
		let cancelled = false;
		const stream = new ReadableStream({
			start(controller) {
				controller.enqueue(
					new TextEncoder().encode(
						'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n' +
							'data: {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text",',
					),
				);
				controller.enqueue(new TextEncoder().encode('"text":"ok"}],"structuredContent":{"domain":"example.com"}}}\n\n'));
			},
			async cancel() {
				cancelled = true;
				throw new Error('cancel rejected');
			},
		});
		const responses = [
			rpc(initialized(), { 'mcp-session-id': 'session-1' }),
			new Response('', { status: 202 }),
			new Response(stream, { headers: { 'content-type': 'text/event-stream' } }),
		];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => responses.shift()!) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});
		await client.connect();
		await expect(client.callTool('scan_domain', {})).resolves.toMatchObject({ structuredContent: { domain: 'example.com' } });
		expect(cancelled).toBe(true);
		expect(stream.locked).toBe(false);
	});

	it('cancels an unexpected initialized-notification response body', async () => {
		let cancelled = false;
		const notificationStream = new ReadableStream({
			start(controller) {
				controller.enqueue(new TextEncoder().encode('unexpected'));
			},
			cancel() {
				cancelled = true;
			},
		});
		const responses = [rpc(initialized()), new Response(notificationStream, { status: 202 })];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => responses.shift()!) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});

		await expect(client.connect()).resolves.toMatchObject({ name: 'blackveil-dns-mcp' });
		expect(cancelled).toBe(true);
		expect(notificationStream.locked).toBe(false);
	});

	it.each([
		['invalid JSON', 'data: {invalid}\n\n', /invalid SSE JSON/],
		['mismatched id', 'data: {"jsonrpc":"2.0","id":9,"result":{}}\n\n', /did not match/],
	])('cancels and unlocks the SSE reader after %s', async (_label, payload, expected) => {
		let cancelled = false;
		const stream = new ReadableStream({
			start(controller) {
				controller.enqueue(new TextEncoder().encode(payload));
			},
			cancel() {
				cancelled = true;
			},
		});
		const responses = [
			rpc(initialized()),
			new Response('', { status: 202 }),
			new Response(stream, { headers: { 'content-type': 'text/event-stream' } }),
		];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => responses.shift()!) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});

		await client.connect();
		await expect(client.callTool('scan_domain', {})).rejects.toThrow(expected as RegExp);
		expect(cancelled).toBe(true);
		expect(stream.locked).toBe(false);
	});

	it('releases the SSE reader lock when reading fails', async () => {
		const stream = new ReadableStream({
			pull(controller) {
				controller.error(new Error('stream read failed'));
			},
		});
		const responses = [
			rpc(initialized()),
			new Response('', { status: 202 }),
			new Response(stream, { headers: { 'content-type': 'text/event-stream' } }),
		];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => responses.shift()!) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});

		await client.connect();
		await expect(client.callTool('scan_domain', {})).rejects.toThrow('stream read failed');
		expect(stream.locked).toBe(false);
	});

	it('rejects and disposes an oversized JSON response', async () => {
		let cancelled = false;
		const stream = new ReadableStream({
			start(controller) {
				controller.enqueue(new Uint8Array(MCP_RESPONSE_BODY_MAX_BYTES + 1));
			},
			cancel() {
				cancelled = true;
			},
		});
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => new Response(stream, { headers: { 'content-type': 'application/json' } })) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});

		await expect(client.connect()).rejects.toThrow('response body limit');
		expect(cancelled).toBe(true);
		expect(stream.locked).toBe(false);
	});

	it('rejects and disposes an oversized SSE event', async () => {
		let cancelled = false;
		const stream = new ReadableStream({
			start(controller) {
				controller.enqueue(new TextEncoder().encode(`data: ${'x'.repeat(MCP_SSE_EVENT_MAX_BYTES)}`));
			},
			cancel() {
				cancelled = true;
			},
		});
		const responses = [
			rpc(initialized()),
			new Response('', { status: 202 }),
			new Response(stream, { headers: { 'content-type': 'text/event-stream' } }),
		];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => responses.shift()!) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});

		await client.connect();
		await expect(client.callTool('scan_domain', {})).rejects.toThrow('event limit');
		expect(cancelled).toBe(true);
		expect(stream.locked).toBe(false);
	});

	it('rejects and disposes an SSE response whose individually bounded events exceed the aggregate limit', async () => {
		let cancelled = false;
		const event = new TextEncoder().encode(
			`data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"padding":"${'x'.repeat(400 * 1024)}"}}\n\n`,
		);
		expect(event.byteLength).toBeLessThan(MCP_SSE_EVENT_MAX_BYTES);
		expect(event.byteLength * 6).toBeGreaterThan(MCP_RESPONSE_BODY_MAX_BYTES);
		const stream = new ReadableStream({
			start(controller) {
				for (let index = 0; index < 6; index += 1) controller.enqueue(event);
			},
			cancel() {
				cancelled = true;
			},
		});
		const responses = [
			rpc(initialized()),
			new Response('', { status: 202 }),
			new Response(stream, { headers: { 'content-type': 'text/event-stream' } }),
		];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => responses.shift()!) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});

		await client.connect();
		await expect(client.callTool('scan_domain', {})).rejects.toThrow('response body limit');
		expect(cancelled).toBe(true);
		expect(stream.locked).toBe(false);
	});

	it.each([
		['missing', 'data: {"jsonrpc":"2.0","result":{}}\n\n', /omitted.*id/],
		['mismatched', 'data: {"jsonrpc":"2.0","id":9,"result":{}}\n\n', /did not match/],
		['server request', 'data: {"jsonrpc":"2.0","id":8,"method":"sampling/createMessage"}\n\n', /unsupported server request/],
		['duplicate', 'data: {"jsonrpc":"2.0","id":2,"result":{}}\n\ndata: {"jsonrpc":"2.0","id":2,"result":{}}\n\n', /duplicate.*id/],
	])('rejects %s SSE response ids', (_label, payload, expected) => {
		expect(() => parseMcpResponseBody(payload, 2)).toThrow(expected as RegExp);
	});

	it('uses one shrinking deadline across initialize, notification, and calls', async () => {
		let now = 1_000;
		const remaining: number[] = [];
		const responses = [rpc(initialized()), new Response('', { status: 202 }), rpc({ tools: [] }, {}, 2)];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			deadlineAt: 46_000,
			now: () => now,
			signalFactory: (remainingMs) => {
				remaining.push(remainingMs);
				return new AbortController().signal;
			},
			fetchFn: (async () => {
				const response = responses.shift()!;
				now += 5_000;
				return response;
			}) as typeof fetch,
		});
		await client.connect();
		await client.listTools();
		expect(remaining).toEqual([45_000, 40_000, 35_000]);
		now = 46_000;
		await expect(client.listTools()).rejects.toThrow('command deadline exceeded');
	});

	it('reinitializes once and retries a read-only call after a session 404', async () => {
		const requests: RequestInit[] = [];
		const responses = [
			rpc(initialized(), { 'mcp-session-id': 'old' }),
			new Response('', { status: 202 }),
			new Response('', { status: 404 }),
			rpc(initialized(), { 'mcp-session-id': 'new' }, 3),
			new Response('', { status: 202 }),
			rpc({ content: [{ type: 'text', text: 'ok' }], structuredContent: { domain: 'example.com' } }, {}, 4),
			new Response('', { status: 404 }),
		];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async (_url, init) => {
				requests.push(init ?? {});
				return responses.shift()!;
			}) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});
		await client.connect();
		await client.callTool('scan_domain', {}, { readOnly: true });
		expect(requests).toHaveLength(6);
		expect(new Headers(requests[2]?.headers).get('mcp-session-id')).toBe('old');
		expect(new Headers(requests[5]?.headers).get('mcp-session-id')).toBe('new');
		await expect(client.callTool('scan_domain', {}, { readOnly: true })).rejects.toMatchObject({ status: 404 });
		expect(requests).toHaveLength(7);
	});

	it('does not retry a non-read-only call after a session 404', async () => {
		let requests = 0;
		const responses = [
			rpc(initialized(), { 'mcp-session-id': 'old' }),
			new Response('', { status: 202 }),
			new Response('', { status: 404 }),
		];
		const client = new McpHttpClient({
			endpoint: 'https://example.test/mcp',
			fetchFn: (async () => {
				requests += 1;
				return responses.shift()!;
			}) as typeof fetch,
			signalFactory: () => new AbortController().signal,
		});
		await client.connect();
		await expect(client.callTool('write_tool', {})).rejects.toMatchObject({ status: 404 });
		expect(requests).toBe(3);
	});

	it('rejects endpoints that could expose credentials through URLs', () => {
		expect(() => new McpHttpClient({ endpoint: 'https://example.test/mcp?key=secret' })).toThrow('query strings');
		expect(() => new McpHttpClient({ endpoint: 'http://example.test/mcp' })).toThrow('HTTPS');
	});
});
