import { describe, it, expect, vi } from 'vitest';
import { createAnalyticsClient } from '../src/lib/analytics';
import type { AnalyticsContext } from '../src/lib/analytics';

function mockDataset() {
	return { writeDataPoint: vi.fn() };
}

const ctx: AnalyticsContext = {
	country: 'NZ',
	clientType: 'claude_code',
	authTier: 'agent',
	sessionHash: 's_abcd1234',
};

describe('createAnalyticsClient', () => {
	it('returns disabled client when no dataset provided', () => {
		const client = createAnalyticsClient();
		expect(client.enabled).toBe(false);
	});

	it('emitRequestEvent includes enriched blobs', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitRequestEvent({
			method: 'tools/call',
			status: 'ok',
			durationMs: 100,
			isAuthenticated: true,
			hasJsonRpcError: false,
			transport: 'json',
			...ctx,
		});
		expect(ds.writeDataPoint).toHaveBeenCalledOnce();
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.indexes).toEqual(['mcp_request']);
		expect(point.blobs).toHaveLength(10);
		expect(point.blobs[5]).toBe('NZ');
		expect(point.blobs[6]).toBe('claude_code');
		expect(point.blobs[7]).toBe('agent');
		expect(point.blobs[8]).toBe('s_abcd1234');
		expect(point.blobs[9]).toBe('none');
	});

	it('emitToolEvent includes enriched blobs and score double', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitToolEvent({
			toolName: 'scan_domain',
			status: 'pass',
			durationMs: 3200,
			domain: 'example.com',
			isError: false,
			score: 85,
			cacheStatus: 'miss',
			...ctx,
		});
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.indexes).toEqual(['tool_call']);
		expect(point.blobs).toHaveLength(9);
		expect(point.blobs[4]).toBe('NZ');
		expect(point.blobs[8]).toBe('none');
		expect(point.doubles).toEqual([3200, 85]);
	});

	it('emitRateLimitEvent writes rate_limit index', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitRateLimitEvent({
			limitType: 'daily_tool',
			toolName: 'scan_domain',
			limit: 75,
			remaining: 0,
			...ctx,
		});
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.indexes).toEqual(['rate_limit']);
		expect(point.blobs[0]).toBe('daily_tool');
		expect(point.blobs[1]).toBe('scan_domain');
		expect(point.doubles).toEqual([75, 0]);
	});

	it('emitSessionEvent writes session index', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitSessionEvent({
			action: 'created',
			...ctx,
		});
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.indexes).toEqual(['session']);
		expect(point.blobs).toEqual(['created', 'NZ', 'claude_code', 'agent', 'unknown', 'none']);
	});

	it('no-ops gracefully when dataset is undefined', () => {
		const client = createAnalyticsClient();
		// Should not throw
		client.emitRequestEvent({ method: 'ping', status: 'ok', durationMs: 1, isAuthenticated: false, hasJsonRpcError: false, transport: 'json', ...ctx });
		client.emitToolEvent({ toolName: 'check_spf', status: 'pass', durationMs: 50, isError: false, ...ctx });
		client.emitRateLimitEvent({ limitType: 'minute', toolName: 'n/a', limit: 50, remaining: 0, ...ctx });
		client.emitSessionEvent({ action: 'created', ...ctx });
		client.emitDegradationEvent({ degradationType: 'dns_resolver_failure', component: 'fetchDohResponse', ...ctx });
	});

	it('emitDegradationEvent writes degradation index', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitDegradationEvent({
			degradationType: 'dns_resolver_failure',
			component: 'fetchDohResponse',
			domain: 'example.com',
			...ctx,
		});
		expect(ds.writeDataPoint).toHaveBeenCalledOnce();
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.indexes).toEqual(['degradation']);
		expect(point.blobs[0]).toBe('dns_resolver_failure');
		expect(point.blobs[1]).toBe('fetchdohresponse');
		expect(point.blobs[3]).toBe('NZ');
		expect(point.blobs[4]).toBe('claude_code');
		expect(point.blobs[5]).toBe('agent');
	});

	it('emitDegradationEvent handles missing optional fields', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitDegradationEvent({
			degradationType: 'kv_fallback',
			component: 'sessionStore',
		});
		expect(ds.writeDataPoint).toHaveBeenCalledOnce();
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.indexes).toEqual(['degradation']);
		expect(point.blobs[0]).toBe('kv_fallback');
		expect(point.blobs[2]).toBe('none');
		expect(point.blobs[3]).toBe('unknown');
	});
});
