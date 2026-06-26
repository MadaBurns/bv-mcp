// Focused unit tests for the optional ipHash dimension on analytics events.
//
// We add ipHash as a context field (truncated FNV-1a of cf-connecting-ip,
// `i_` prefix to match `s_`/`d_` conventions) so future analytics queries can
// filter by client IP. The hash is lossy by design — it groups equal IPs but
// is trivially reversible by anyone who can guess an IPv4. This is acceptable
// because the alternative (raw IP) is what we explicitly chose to avoid.

import { describe, it, expect, vi } from 'vitest';
import { createAnalyticsClient, hashIpForAnalytics } from '../src/lib/analytics';
import type { AnalyticsContext } from '../src/lib/analytics';

function mockDataset() {
	return { writeDataPoint: vi.fn() };
}

const baseCtx: AnalyticsContext = {
	country: 'PH',
	clientType: 'claude_code',
	authTier: 'agent',
	sessionHash: 's_abcd1234',
	ipHash: 'i_cafef00d',
};

describe('hashIpForAnalytics', () => {
	it('produces an i_-prefixed hex token', () => {
		const h = hashIpForAnalytics('143.44.164.31');
		expect(h).toMatch(/^i_[0-9a-f]{1,8}$/);
	});

	it('returns the same token for the same input', () => {
		expect(hashIpForAnalytics('143.44.164.31')).toBe(hashIpForAnalytics('143.44.164.31'));
	});

	it('returns different tokens for clearly different IPs', () => {
		expect(hashIpForAnalytics('143.44.164.31')).not.toBe(hashIpForAnalytics('1.1.1.1'));
	});
});

describe('createAnalyticsClient — ipHash blob', () => {
	it('emitRequestEvent keeps ipHash at blob11 (colo now appended after it as blob12)', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitRequestEvent({
			method: 'tools/call',
			status: 'ok',
			durationMs: 100,
			isAuthenticated: true,
			hasJsonRpcError: false,
			transport: 'json',
			...baseCtx,
		});
		const point = ds.writeDataPoint.mock.calls[0][0];
		// blob12 (index 11) = colo trailing append; ipHash stays at blob11 (index 10).
		expect(point.blobs).toHaveLength(12);
		expect(point.blobs[10]).toBe('i_cafef00d');
	});

	it('emitToolEvent keeps ipHash at blob10 (colo at blob11, priorTool at blob12)', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		client.emitToolEvent({
			toolName: 'scan_domain',
			status: 'pass',
			durationMs: 200,
			isError: false,
			...baseCtx,
		});
		const point = ds.writeDataPoint.mock.calls[0][0];
		// blob12 (index 11) = priorTool (C2 append); colo at blob11 (index 10); ipHash stays at blob10 (index 9).
		expect(point.blobs).toHaveLength(15);
		expect(point.blobs[9]).toBe('i_cafef00d');
	});

	it('emitRequestEvent records "none" when ipHash is missing (back-compat)', () => {
		const ds = mockDataset();
		const client = createAnalyticsClient(ds);
		const ctxNoIp = { ...baseCtx, ipHash: undefined };
		client.emitRequestEvent({
			method: 'tools/call',
			status: 'ok',
			durationMs: 100,
			isAuthenticated: false,
			hasJsonRpcError: false,
			transport: 'json',
			...ctxNoIp,
		});
		const point = ds.writeDataPoint.mock.calls[0][0];
		expect(point.blobs).toHaveLength(12);
		expect(point.blobs[10]).toBe('none');
	});
});
