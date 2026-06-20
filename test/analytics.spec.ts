// SPDX-License-Identifier: BUSL-1.1

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
		// blob12 (index 11) = colo, appended trailing. Existing positions unchanged.
		expect(point.blobs).toHaveLength(12);
		expect(point.blobs[5]).toBe('NZ');
		expect(point.blobs[6]).toBe('claude_code');
		expect(point.blobs[7]).toBe('agent');
		expect(point.blobs[8]).toBe('s_abcd1234');
		expect(point.blobs[9]).toBe('none');
		// colo absent in ctx → defaults to 'unknown' (fail-open).
		expect(point.blobs[11]).toBe('unknown');
	});

	it('emitRequestEvent appends colo as the trailing blob12 without shifting existing positions', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitRequestEvent({
			method: 'tools/call',
			status: 'ok',
			durationMs: 100,
			isAuthenticated: true,
			hasJsonRpcError: false,
			transport: 'json',
			ipHash: 'i_deadbeef',
			...ctx,
			colo: 'AKL',
		});
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.blobs).toHaveLength(12);
		// Existing position-indexed fields stay put.
		expect(point.blobs[0]).toBe('tools/call');
		expect(point.blobs[5]).toBe('NZ');
		expect(point.blobs[10]).toBe('i_deadbeef'); // blob11 ipHash unmoved
		// New trailing dimension.
		expect(point.blobs[11]).toBe('AKL');
	});

	it('emitRequestEvent records the JSON-RPC error code as abs(code) in double2', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitRequestEvent({
			method: 'tools/call',
			status: 'error',
			durationMs: 42,
			isAuthenticated: true,
			hasJsonRpcError: true,
			jsonRpcErrorCode: -32602,
			transport: 'sse',
			...ctx,
		});
		const point = ds.writeDataPoint.mock.calls[0][0];
		// Codes are negative per JSON-RPC; sanitizeNumber clamps <0 to 0, so we store abs().
		expect(point.doubles).toEqual([42, 32602]);
	});

	it('emitRequestEvent defaults double2 to 0 when no error code is present', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitRequestEvent({
			method: 'ping',
			status: 'ok',
			durationMs: 7,
			isAuthenticated: false,
			hasJsonRpcError: false,
			transport: 'json',
			...ctx,
		});
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.doubles).toEqual([7, 0]);
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
		// blob11 (index 10) = colo, appended trailing. Existing positions unchanged.
		expect(point.blobs).toHaveLength(11);
		expect(point.blobs[4]).toBe('NZ');
		expect(point.blobs[8]).toBe('none');
		// colo absent in ctx → defaults to 'unknown' (fail-open).
		expect(point.blobs[10]).toBe('unknown');
		expect(point.doubles).toEqual([3200, 85]);
	});

	it('emitToolEvent appends colo as the trailing blob11 without shifting existing positions', () => {
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
			ipHash: 'i_cafef00d',
			...ctx,
			colo: 'SYD',
		});
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.blobs).toHaveLength(11);
		// Existing position-indexed fields stay put.
		expect(point.blobs[0]).toBe('scan_domain');
		expect(point.blobs[4]).toBe('NZ');
		expect(point.blobs[9]).toBe('i_cafef00d'); // blob10 ipHash unmoved
		// New trailing dimension.
		expect(point.blobs[10]).toBe('SYD');
	});

	it('emitRateLimitEvent writes rate_limit index', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitRateLimitEvent({
			limitType: 'daily_tool',
			toolName: 'scan_domain',
			limit: 5,
			remaining: 0,
			...ctx,
		});
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.indexes).toEqual(['rate_limit']);
		expect(point.blobs[0]).toBe('daily_tool');
		expect(point.blobs[1]).toBe('scan_domain');
		expect(point.doubles).toEqual([5, 0]);
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
		client.emitRequestEvent({
			method: 'ping',
			status: 'ok',
			durationMs: 1,
			isAuthenticated: false,
			hasJsonRpcError: false,
			transport: 'json',
			...ctx,
		});
		client.emitToolEvent({ toolName: 'check_spf', status: 'pass', durationMs: 50, isError: false, ...ctx });
		client.emitRateLimitEvent({ limitType: 'minute', toolName: 'n/a', limit: 50, remaining: 0, ...ctx });
		client.emitSessionEvent({ action: 'created', ...ctx });
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session', ...ctx });
	});

	it('emitDegradationEvent writes degradation index', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitDegradationEvent({
			degradationType: 'kv_fallback',
			component: 'session',
			domain: 'example.com',
			...ctx,
		});
		expect(ds.writeDataPoint).toHaveBeenCalledOnce();
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.indexes).toEqual(['degradation']);
		expect(point.blobs[0]).toBe('kv_fallback');
		expect(point.blobs[1]).toBe('session');
		// blobs[2] = domain fingerprint, blobs[3] = country, blobs[4] = clientType, blobs[5] = authTier
		expect(point.blobs[3]).toBe('NZ');
		expect(point.blobs[4]).toBe('claude_code');
		expect(point.blobs[5]).toBe('agent');
		// scanId/dedup/collision-probe plumbing removed — no doubles emitted.
		expect(point.doubles).toBeUndefined();
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
		expect(point.blobs[2]).toBe('none'); // no domain
		expect(point.blobs[3]).toBe('unknown'); // country
	});

	it('does NOT dedup identical kv_fallback emits (dead dedup window removed)', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session' });
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session' });
		// Two identical emits → two writes (no module-level dedup state).
		expect(ds.writeDataPoint).toHaveBeenCalledTimes(2);
	});

	it('writes the binding-degradation members (recon binding_5xx)', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitDegradationEvent({ degradationType: 'binding_5xx', component: 'recon', domain: 'example.com', ...ctx });
		expect(ds.writeDataPoint).toHaveBeenCalledOnce();
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.indexes).toEqual(['degradation']);
		expect(point.blobs[0]).toBe('binding_5xx');
		expect(point.blobs[1]).toBe('recon');
	});

	it('writes the tls_probe binding_timeout member', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitDegradationEvent({ degradationType: 'binding_timeout', component: 'tls_probe' });
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.blobs[0]).toBe('binding_timeout');
		expect(point.blobs[1]).toBe('tls_probe');
	});
});
