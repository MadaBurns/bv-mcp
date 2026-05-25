// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi, afterEach } from 'vitest';

afterEach(() => vi.restoreAllMocks());

function reconBinding(body: unknown, status = 200) {
	return { fetch: vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })) };
}

describe('checkRealtimeThreatFeed', () => {
	it('returns unprovisioned info when binding absent', async () => {
		const { checkRealtimeThreatFeed } = await import('../src/tools/check-realtime-threat-feed');
		const r = await checkRealtimeThreatFeed('example.com', {});
		expect(r.findings.some(f => f.metadata?.unprovisioned === true)).toBe(true);
		expect(r.passed).toBe(true);
	});

	it('surfaces a high finding when the feed reports a hit', async () => {
		const { checkRealtimeThreatFeed } = await import('../src/tools/check-realtime-threat-feed');
		const binding = reconBinding({ findings: [{ severity: 'high', title: 'Live threat-feed hit', detail: 'seen 2026-05-24' }] });
		const r = await checkRealtimeThreatFeed('evil.com', { reconBinding: binding, reconAuthToken: 'tok' });
		expect(r.findings.some(f => f.severity === 'high')).toBe(true);
	});

	it('reports a clean result when the feed returns no findings', async () => {
		const { checkRealtimeThreatFeed } = await import('../src/tools/check-realtime-threat-feed');
		const binding = reconBinding({ findings: [] });
		const r = await checkRealtimeThreatFeed('good.com', { reconBinding: binding, reconAuthToken: 'tok' });
		expect(r.passed).toBe(true);
	});
});
