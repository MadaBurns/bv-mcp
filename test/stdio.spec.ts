import { describe, expect, it } from 'vitest';
import { createStdioServer } from '../src/stdio';

describe('stdio MCP server', () => {
	it('returns initialize success and marks the server initialized', async () => {
		const server = createStdioServer();
		const [output] = await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }));
		const payload = JSON.parse(output ?? 'null') as { result: { protocolVersion: string } };

		expect(payload.result.protocolVersion).toBe('2025-03-26');
		expect(server.state.initialized).toBe(true);
	});

	it('rejects requests before initialize', async () => {
		const server = createStdioServer();
		const [output] = await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }));
		const payload = JSON.parse(output ?? 'null') as { error: { code: number; message: string } };

		expect(payload.error.code).toBe(-32600);
		expect(payload.error.message).toContain('not initialized');
	});

	it('ignores notifications and responds to subsequent requests after initialize', async () => {
		const server = createStdioServer();
		await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'initialize', params: {} }));
		const notificationOutputs = await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }));
		const [output] = await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', id: 4, method: 'ping', params: {} }));
		const payload = JSON.parse(output ?? 'null') as { result: Record<string, never> };

		expect(notificationOutputs).toEqual([]);
		expect(payload.result).toEqual({});
	});

	it('supports JSON-RPC batch messages', async () => {
		const server = createStdioServer();
		await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'initialize', params: {} }));
		const [output] = await server.handleMessage(
			JSON.stringify([
				{ jsonrpc: '2.0', id: 6, method: 'ping', params: {} },
				{ jsonrpc: '2.0', method: 'notifications/initialized' },
				{ jsonrpc: '2.0', id: 7, method: 'tools/list', params: {} },
			]),
		);
		const payload = JSON.parse(output ?? 'null') as Array<{ id: number; result?: unknown }>;

		expect(payload.map((entry) => entry.id)).toEqual([6, 7]);
		expect(payload[0]?.result).toEqual({});
		expect(payload[1]?.result).toHaveProperty('tools');
	});

	it('rejects initialize inside multi-message batches', async () => {
		const server = createStdioServer();
		const [output] = await server.handleMessage(
			JSON.stringify([
				{ jsonrpc: '2.0', id: 8, method: 'initialize', params: {} },
				{ jsonrpc: '2.0', id: 9, method: 'ping', params: {} },
			]),
		);
		const payload = JSON.parse(output ?? 'null') as Array<{ id: number; error?: { message: string } }>;

		expect(payload[0]?.id).toBe(8);
		expect(payload[0]?.error?.message).toContain('initialize cannot be batched');
		expect(payload[1]?.id).toBe(9);
		expect(payload[1]?.error?.message).toContain('not initialized');
	});
});