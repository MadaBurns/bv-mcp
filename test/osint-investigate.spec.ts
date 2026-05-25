// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi, afterEach } from 'vitest';
afterEach(() => vi.restoreAllMocks());
function binding(body: unknown, status = 200) {
	return { fetch: vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })) };
}
describe('osint investigation tools', () => {
	it('domain start: unprovisioned when binding absent', async () => {
		const { osintInvestigateDomainStart } = await import('../src/tools/osint-investigate');
		const r = await osintInvestigateDomainStart('example.com', {});
		expect(r.findings.some((f) => f.metadata?.unprovisioned === true)).toBe(true);
		expect(r.passed).toBe(true);
	});
	it('domain start: returns investigationId when bound', async () => {
		const { osintInvestigateDomainStart } = await import('../src/tools/osint-investigate');
		const r = await osintInvestigateDomainStart('example.com', { reconBinding: binding({ investigationId: 'inv_1', status: 'running' }), reconAuthToken: 't' });
		expect(r.findings.some((f) => f.metadata?.investigationId === 'inv_1')).toBe(true);
	});
	it('infrastructure + supply_chain starts set their type', async () => {
		const m = await import('../src/tools/osint-investigate');
		const ri = await m.osintInvestigateInfrastructureStart('example.com', { reconBinding: binding({ investigationId: 'inv_2' }), reconAuthToken: 't' });
		expect(ri.findings.some((f) => f.metadata?.type === 'deep_infrastructure')).toBe(true);
		const rs = await m.osintInvestigateSupplyChainStart('example.com', { reconBinding: binding({ investigationId: 'inv_3' }), reconAuthToken: 't' });
		expect(rs.findings.some((f) => f.metadata?.type === 'supply_chain')).toBe(true);
	});
	it('status + report: unprovisioned when absent; summary finding when bound', async () => {
		const m = await import('../src/tools/osint-investigate');
		expect((await m.osintInvestigationStatus('inv_1', {})).findings.some((f) => f.metadata?.unprovisioned === true)).toBe(true);
		const rs = await m.osintInvestigationStatus('inv_1', { reconBinding: binding({ status: 'completed' }), reconAuthToken: 't' });
		expect(rs.findings.some((f) => f.metadata?.summary === true)).toBe(true);
		const rr = await m.osintInvestigationReport('inv_1', { reconBinding: binding({ findings: [] }), reconAuthToken: 't' });
		expect(rr.findings.some((f) => f.metadata?.summary === true)).toBe(true);
	});
});
