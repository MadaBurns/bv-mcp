import { describe, it, expect } from 'vitest';
import { JsonRpcRequestSchema, JsonRpcBatchSchema, JsonRpcBodySchema } from '../../src/schemas/json-rpc';

describe('JsonRpcRequestSchema', () => {
	it('accepts valid request', () => {
		const result = JsonRpcRequestSchema.safeParse({ jsonrpc: '2.0', method: 'tools/list', id: 1 });
		expect(result.success).toBe(true);
	});
	it('accepts request with params', () => {
		const result = JsonRpcRequestSchema.safeParse({ jsonrpc: '2.0', method: 'tools/call', id: '1', params: { name: 'check_spf' } });
		expect(result.success).toBe(true);
	});
	it('accepts notification (no id)', () => {
		const result = JsonRpcRequestSchema.safeParse({ jsonrpc: '2.0', method: 'notifications/cancelled' });
		expect(result.success).toBe(true);
	});
	it('accepts null id', () => {
		const result = JsonRpcRequestSchema.safeParse({ jsonrpc: '2.0', method: 'test', id: null });
		expect(result.success).toBe(true);
	});
	it('rejects wrong jsonrpc version', () => {
		const result = JsonRpcRequestSchema.safeParse({ jsonrpc: '1.0', method: 'test' });
		expect(result.success).toBe(false);
	});
	it('rejects missing method', () => {
		const result = JsonRpcRequestSchema.safeParse({ jsonrpc: '2.0' });
		expect(result.success).toBe(false);
	});
	it('rejects non-string/number/null id', () => {
		const result = JsonRpcRequestSchema.safeParse({ jsonrpc: '2.0', method: 'test', id: true });
		expect(result.success).toBe(false);
	});
	it('passes through extra properties', () => {
		const result = JsonRpcRequestSchema.safeParse({ jsonrpc: '2.0', method: 'test', extra: true });
		expect(result.success).toBe(true);
		if (result.success) expect((result.data as Record<string, unknown>).extra).toBe(true);
	});
});

describe('JsonRpcBatchSchema', () => {
	it('accepts array of valid requests', () => {
		const result = JsonRpcBatchSchema.safeParse([
			{ jsonrpc: '2.0', method: 'a', id: 1 },
			{ jsonrpc: '2.0', method: 'b', id: 2 },
		]);
		expect(result.success).toBe(true);
	});
	it('rejects empty array', () => {
		const result = JsonRpcBatchSchema.safeParse([]);
		expect(result.success).toBe(false);
	});
});

describe('JsonRpcBodySchema', () => {
	it('accepts single request', () => {
		const result = JsonRpcBodySchema.safeParse({ jsonrpc: '2.0', method: 'test', id: 1 });
		expect(result.success).toBe(true);
	});
	it('accepts batch', () => {
		const result = JsonRpcBodySchema.safeParse([{ jsonrpc: '2.0', method: 'test', id: 1 }]);
		expect(result.success).toBe(true);
	});
});
