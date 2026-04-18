// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi, beforeEach } from 'vitest';
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
		// blobs[2] = domain fingerprint, blobs[3] = scanId (''), blobs[4] = country
		expect(point.blobs[4]).toBe('NZ');
		expect(point.blobs[5]).toBe('claude_code');
		expect(point.blobs[6]).toBe('agent');
		// doubles[0] = hashCollisionSuspected flag (0 = no collision)
		expect(point.doubles?.[0]).toBe(0);
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
		expect(point.blobs[3]).toBe(''); // no scanId
		expect(point.blobs[4]).toBe('unknown'); // country
	});
});

describe('analytics degradation dedup + collision probe', () => {
	function makeClient() {
		const writes: Array<{ indexes?: string[]; blobs?: string[]; doubles?: number[] }> = [];
		const dataset = {
			writeDataPoint: (p: { indexes?: string[]; blobs?: string[]; doubles?: number[] }) => writes.push(p),
		};
		return { dataset, writes };
	}

	beforeEach(() => {
		// Clear any module-level state between tests.
		vi.resetModules();
	});

	it('dedups identical (scanId, degradationType, component) within the rolling window', async () => {
		const { dataset, writes } = makeClient();
		const { createAnalyticsClient } = await import('../src/lib/analytics');
		const client = createAnalyticsClient(dataset as never);
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session', scanId: 'A' });
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session', scanId: 'A' });
		// Same (scanId, type, component) → only one write.
		const degWrites = writes.filter((w) => w.indexes?.[0] === 'degradation');
		expect(degWrites.length).toBe(1);
	});

	it('does NOT dedup across different scanIds', async () => {
		const { dataset, writes } = makeClient();
		const { createAnalyticsClient } = await import('../src/lib/analytics');
		const client = createAnalyticsClient(dataset as never);
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session', scanId: 'A' });
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session', scanId: 'B' });
		const degWrites = writes.filter((w) => w.indexes?.[0] === 'degradation');
		expect(degWrites.length).toBe(2);
	});

	it('does NOT dedup when scanId is undefined (each call is independent)', async () => {
		const { dataset, writes } = makeClient();
		const { createAnalyticsClient } = await import('../src/lib/analytics');
		const client = createAnalyticsClient(dataset as never);
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session' });
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'session' });
		const degWrites = writes.filter((w) => w.indexes?.[0] === 'degradation');
		expect(degWrites.length).toBe(2);
	});

	it('emits hashCollisionSuspected when two different domains hash identically', async () => {
		const { dataset, writes } = makeClient();
		const { createAnalyticsClient, hashDomain, __forceCollisionForTest } = await import('../src/lib/analytics');
		const client = createAnalyticsClient(dataset as never);
		// Prime the collision cache so the next hash call sees a collision.
		hashDomain('example.com');
		// Force-inject a collision for different.com → same hash as example.com.
		(__forceCollisionForTest as ((a: string, b: string) => void) | undefined)?.('example.com', 'different.com');
		client.emitDegradationEvent({ degradationType: 'kv_fallback', component: 'probe-emit' });
		const degWrites = writes.filter((w) => w.indexes?.[0] === 'degradation');
		expect(degWrites.length).toBeGreaterThanOrEqual(1);
		// hashCollisionSuspected is the 0th double.
		expect(degWrites[0].doubles?.[0]).toBe(1);
	});
});
