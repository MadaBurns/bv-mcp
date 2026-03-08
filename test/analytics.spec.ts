import { describe, it, expect, vi } from 'vitest';
import { createAnalyticsClient } from '../src/lib/analytics';

describe('analytics client', () => {
	it('is a no-op when dataset binding is missing', () => {
		const client = createAnalyticsClient(undefined);
		expect(() => {
			client.emitRequestEvent({
				method: 'tools/list',
				status: 'ok',
				durationMs: 5,
				isAuthenticated: false,
				hasJsonRpcError: false,
				transport: 'json',
			});
			client.emitToolEvent({
				toolName: 'check_spf',
				status: 'pass',
				durationMs: 8,
				domain: 'example.com',
				isError: false,
			});
		}).not.toThrow();
	});

	it('writes request and tool events to dataset', () => {
		const writeDataPoint = vi.fn();
		const client = createAnalyticsClient({ writeDataPoint });

		client.emitRequestEvent({
			method: 'tools/call',
			status: 'ok',
			durationMs: 12,
			isAuthenticated: true,
			hasJsonRpcError: false,
			transport: 'sse',
		});
		client.emitToolEvent({
			toolName: 'check_dkim',
			status: 'fail',
			durationMs: 25,
			domain: 'example.com',
			isError: false,
		});

		expect(writeDataPoint).toHaveBeenCalledTimes(2);
		expect(writeDataPoint.mock.calls[0]?.[0]).toEqual({
			indexes: ['mcp_request'],
			blobs: ['tools/call', 'sse', 'ok', 'auth', 'jsonrpc_ok'],
			doubles: [12],
		});
		expect(writeDataPoint.mock.calls[1]?.[0]).toEqual({
			indexes: ['tool_call'],
			blobs: ['check_dkim', 'fail', 'ok', writeDataPoint.mock.calls[1]?.[0]?.blobs?.[3]],
			doubles: [25],
		});
		expect(String(writeDataPoint.mock.calls[1]?.[0]?.blobs?.[3])).toMatch(/^d_[0-9a-f]+$/);
	});

	it('hashes domains consistently and case-insensitively', () => {
		const writeDataPoint = vi.fn();
		const client = createAnalyticsClient({ writeDataPoint });

		client.emitToolEvent({
			toolName: 'check_spf',
			status: 'pass',
			durationMs: 10,
			domain: 'Example.COM',
			isError: false,
		});
		client.emitToolEvent({
			toolName: 'check_spf',
			status: 'pass',
			durationMs: 11,
			domain: 'example.com',
			isError: false,
		});

		const firstHash = writeDataPoint.mock.calls[0]?.[0]?.blobs?.[3];
		const secondHash = writeDataPoint.mock.calls[1]?.[0]?.blobs?.[3];
		expect(firstHash).toBe(secondHash);
		expect(String(firstHash)).toMatch(/^d_[0-9a-f]+$/);
	});

	it('swallows writeDataPoint errors (fail-open)', () => {
		const writeDataPoint = vi.fn(() => {
			throw new Error('dataset unavailable');
		});
		const client = createAnalyticsClient({ writeDataPoint });

		expect(() => {
			client.emitRequestEvent({
				method: 'initialize',
				status: 'ok',
				durationMs: 1,
				isAuthenticated: false,
				hasJsonRpcError: false,
				transport: 'json',
			});
		}).not.toThrow();
	});
});
