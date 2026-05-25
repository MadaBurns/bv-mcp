// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi, afterEach } from 'vitest';
afterEach(() => vi.restoreAllMocks());

function binding(body: unknown, status = 200) {
	return { fetch: vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })) };
}

describe('recon async proxies', () => {
	it('callReconInvestigateStart returns null when binding absent', async () => {
		const { callReconInvestigateStart } = await import('../src/lib/recon-binding');
		expect(await callReconInvestigateStart(undefined, 't', 'domain', 'example.com')).toBeNull();
	});
	it('callReconInvestigateStart POSTs the type path with bearer + body and parses id', async () => {
		const { callReconInvestigateStart } = await import('../src/lib/recon-binding');
		const b = binding({ investigationId: 'inv_1', workflowId: 'wf_1', status: 'running', pollUrl: '/api/investigation/inv_1' });
		const out = await callReconInvestigateStart(b, 'tok', 'deep_infrastructure', 'example.com');
		const [url, init] = b.fetch.mock.calls[0];
		expect(String(url)).toContain('/osint/api/investigate/deep_infrastructure');
		expect((init as RequestInit).method).toBe('POST');
		expect((init as RequestInit).headers).toMatchObject({ Authorization: 'Bearer tok' });
		expect(out?.investigationId).toBe('inv_1');
	});
	it('callReconInvestigationStatus GETs by id and returns null on non-ok', async () => {
		const { callReconInvestigationStatus } = await import('../src/lib/recon-binding');
		expect(await callReconInvestigationStatus(binding({ error: 'x' }, 404), 'tok', 'inv_1')).toBeNull();
	});
	it('callReconBucketScanStart POSTs trigger and parses scanId', async () => {
		const { callReconBucketScanStart } = await import('../src/lib/recon-binding');
		const b = binding({ scanId: 'scan_1', status: 'running' });
		const out = await callReconBucketScanStart(b, 'tok', { target: 'example.com' });
		expect(String(b.fetch.mock.calls[0][0])).toContain('/buckets/api/scan/trigger');
		expect(out?.scanId).toBe('scan_1');
	});
	it('callReconBucketScanStatus returns null on non-ok', async () => {
		const { callReconBucketScanStatus } = await import('../src/lib/recon-binding');
		expect(await callReconBucketScanStatus(binding({}, 500), 'tok', 'scan_1')).toBeNull();
	});
});
