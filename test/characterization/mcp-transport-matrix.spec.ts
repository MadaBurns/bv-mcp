// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { createStdioServer } from '../../src/stdio';
import { executeMcpRequest, type ExecuteMcpRequestOptions } from '../../src/mcp/execute';
import type { JsonRpcRequest } from '../../src/lib/json-rpc';

function options(body: JsonRpcRequest): ExecuteMcpRequestOptions {
	return {
		body,
		allowStreaming: false,
		batchMode: false,
		batchSize: 1,
		responseTransport: 'json',
		startTime: Date.now(),
		ip: '203.0.113.10',
		isAuthenticated: true,
		validateSession: false,
		createSessionOnInitialize: false,
		serverVersion: 'characterization',
	};
}

describe('MCP transport characterization', () => {
	it('keeps direct execution and stdio aligned for a sessionless tools/list request', async () => {
		const request = { jsonrpc: '2.0', id: 'matrix-1', method: 'tools/list', params: {} } as JsonRpcRequest;
		const direct = await executeMcpRequest(options(request));
		expect(direct.kind).toBe('response');
		if (direct.kind !== 'response') throw new Error('expected response');

		const stdio = createStdioServer();
		stdio.state.initialized = true;
		const lines = await stdio.handleMessage(JSON.stringify(request));
		expect(lines).toHaveLength(1);
		const payload = JSON.parse(lines[0]) as { result?: { tools?: unknown[] } };

		expect(direct.httpStatus).toBe(200);
		expect((direct.payload as { result?: { tools?: unknown[] } }).result?.tools).toHaveLength(payload.result?.tools?.length ?? -1);
	});

	it('suppresses notifications consistently on the direct execution path', async () => {
		const result = await executeMcpRequest(
			options({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} } as JsonRpcRequest),
		);
		expect(result).toEqual({ kind: 'notification' });
	});
});
