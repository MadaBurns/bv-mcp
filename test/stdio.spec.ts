import { describe, expect, it } from 'vitest';
import { createStdioServer } from '../src/stdio';

describe('stdio MCP server', () => {
	it('returns initialize success and marks the server initialized', async () => {
		const server = createStdioServer();
		const [output] = await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }));
		const payload = JSON.parse(output ?? 'null') as {
			result: { protocolVersion: string; instructions: string; capabilities: { prompts: { listChanged: boolean } } };
		};

		// Request sent params:{} (no protocolVersion) → negotiation returns the server's latest.
		expect(payload.result.protocolVersion).toBe('2025-06-18');
		expect(typeof payload.result.instructions).toBe('string');
		expect(payload.result.instructions.length).toBeGreaterThan(0);
		expect(payload.result.capabilities.prompts).toEqual({ listChanged: false });
		expect(server.state.initialized).toBe(true);
	});

	it('rejects requests before initialize', async () => {
		const server = createStdioServer();
		const [output] = await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }));
		const payload = JSON.parse(output ?? 'null') as { error: { code: number; message: string } };

		expect(payload.error.code).toBe(-32600);
		expect(payload.error.message).toContain('not initialized');
	});

	it('treats id:null as a real request (JSON-RPC 2.0), not a notification', async () => {
		// Per JSON-RPC 2.0 a notification is a request WITHOUT an `id` member.
		// `id: null` is a valid id that REQUIRES a response — it must not be swallowed.
		const server = createStdioServer();
		const outputs = await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', id: null, method: 'tools/list', params: {} }));

		// A swallowed notification would yield [] — a real request yields one response carrying id:null.
		expect(outputs).toHaveLength(1);
		const payload = JSON.parse(outputs[0] ?? 'null') as { id: number | null; error: { code: number; message: string } };
		expect(payload.id).toBe(null);
		expect(payload.error.message).toContain('not initialized');
	});

	it('still swallows true notifications (request without an id member)', async () => {
		const server = createStdioServer();
		await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }));
		const outputs = await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }));
		expect(outputs).toEqual([]);
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

	it('does not throw on a request with no method member, returns a JSON-RPC error carrying its id', async () => {
		// Regression: stdio's notification detection used to call method.startsWith on an
		// unvalidated method. A `{ jsonrpc, id }` message (no method) made `undefined.startsWith`
		// throw a TypeError that flushLine swallowed, leaving the client with no response.
		const server = createStdioServer();
		const outputs = await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', id: 1 }));

		expect(outputs).toHaveLength(1);
		const payload = JSON.parse(outputs[0] ?? 'null') as { id: number | null; error: { code: number; message: string } };
		expect(payload.id).toBe(1);
		// Not initialized → buildNotInitializedError; the point is a real error response, not a swallowed throw.
		expect(payload.error.message).toContain('not initialized');
	});

	it('batch resilience: one malformed (no-method) entry does not wipe responses for valid entries', async () => {
		// Regression: a throw inside Promise.all(entries.map(...)) rejected the whole batch,
		// dropping responses for every valid request alongside the bad one.
		const server = createStdioServer();
		await server.handleMessage(JSON.stringify({ jsonrpc: '2.0', id: 5, method: 'initialize', params: {} }));
		const [output] = await server.handleMessage(
			JSON.stringify([
				{ jsonrpc: '2.0', id: 6, method: 'ping', params: {} },
				{ jsonrpc: '2.0', id: 7 },
				{ jsonrpc: '2.0', id: 8, method: 'ping', params: {} },
			]),
		);
		const payload = JSON.parse(output ?? 'null') as Array<{ id: number; result?: unknown; error?: { code: number; message: string } }>;

		expect(payload.map((entry) => entry.id)).toEqual([6, 7, 8]);
		// Valid entries still answered.
		expect(payload.find((entry) => entry.id === 6)?.result).toEqual({});
		expect(payload.find((entry) => entry.id === 8)?.result).toEqual({});
		// Malformed entry gets its own error, not a silent drop.
		expect(payload.find((entry) => entry.id === 7)?.error?.code).toBe(-32600);
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