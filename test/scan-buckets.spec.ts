// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi, afterEach } from 'vitest';
afterEach(() => vi.restoreAllMocks());
function binding(body: unknown, status = 200) {
	return { fetch: vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })) };
}
describe('scan_buckets tools', () => {
	it('start: unprovisioned info when binding absent', async () => {
		const { scanBucketsStart } = await import('../src/tools/scan-buckets');
		const r = await scanBucketsStart({ target: 'example.com' }, {});
		expect(r.findings.some(f => f.metadata?.unprovisioned === true)).toBe(true);
		expect(r.passed).toBe(true);
	});
	it('start: returns scanId when started', async () => {
		const { scanBucketsStart } = await import('../src/tools/scan-buckets');
		const r = await scanBucketsStart({ target: 'example.com' }, { reconBinding: binding({ scanId: 'scan_1', status: 'running' }), reconAuthToken: 'tok' });
		expect(r.findings.some(f => f.metadata?.scanId === 'scan_1')).toBe(true);
	});
	it('status: unprovisioned when absent; passes through payload when bound', async () => {
		const { scanBucketsStatus } = await import('../src/tools/scan-buckets');
		expect((await scanBucketsStatus({ scanId: 's1' }, {})).findings.some(f => f.metadata?.unprovisioned === true)).toBe(true);
		const r = await scanBucketsStatus({ scanId: 's1' }, { reconBinding: binding({ scanId: 's1', status: 'completed' }), reconAuthToken: 't' });
		expect(r.findings.some(f => f.metadata?.summary === true)).toBe(true);
	});
	it('findings: unprovisioned when absent; passes through when bound', async () => {
		const { scanBucketsFindings } = await import('../src/tools/scan-buckets');
		expect((await scanBucketsFindings({}, {})).findings.some(f => f.metadata?.unprovisioned === true)).toBe(true);
		const r = await scanBucketsFindings({ scanId: 's1' }, { reconBinding: binding({ findings: [] }), reconAuthToken: 't' });
		expect(r.findings.some(f => f.metadata?.summary === true)).toBe(true);
	});
});
