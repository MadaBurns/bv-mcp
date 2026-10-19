// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';

// dispatchMcpMethod resolves methods through a table. These specs pin the contract that
// table must keep: unknown names (including inherited Object.prototype member names) fall to the
// JSON-RPC method-not-found path, and the params-free methods keep their log fields.

const base = { ip: '203.0.113.9', isAuthenticated: false, rateHeaders: {}, serverVersion: '1.0.0', params: undefined };

describe('dispatchMcpMethod method table', () => {
	it.each(['constructor', 'toString', '__proto__', 'hasOwnProperty', 'unknown/method', ''])(
		'routes %j to method-not-found (-32601) instead of resolving an inherited member',
		async (method) => {
			const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
			const result = await dispatchMcpMethod({ ...base, id: 7, method });
			expect(result.kind).toBe('success');
			if (result.kind !== 'success') throw new Error('expected success result');
			expect(result.logCategory).toBe('error');
			expect(result.logResult).toBe('method_not_found');
			expect(result.payload).toMatchObject({ id: 7, error: { code: -32601, message: 'Method not found' } });
		},
	);

	it.each([
		['tools/list', 'tools', 'list'],
		['resources/list', 'resources', 'list'],
		['prompts/list', 'prompts', 'list'],
		['ping', 'session', 'ping'],
	])('%s returns a success payload tagged %s/%s', async (method, logCategory, logResult) => {
		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const result = await dispatchMcpMethod({ ...base, id: 'req-1', method });
		expect(result.kind).toBe('success');
		if (result.kind !== 'success') throw new Error('expected success result');
		expect(result.logCategory).toBe(logCategory);
		expect(result.logResult).toBe(logResult);
		expect(result.logTool).toBeUndefined();
		expect(result.payload).toMatchObject({ jsonrpc: '2.0', id: 'req-1' });
		expect('result' in result.payload).toBe(true);
	});

	it('ping returns an empty result object', async () => {
		const { dispatchMcpMethod } = await import('../src/mcp/dispatch');
		const result = await dispatchMcpMethod({ ...base, id: 3, method: 'ping' });
		if (result.kind !== 'success' || !('result' in result.payload)) throw new Error('expected success payload');
		expect(result.payload.result).toEqual({});
	});
});
