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
	it('status + report: unprovisioned when binding absent', async () => {
		const m = await import('../src/tools/osint-investigate');
		expect((await m.osintInvestigationStatus('inv_1', {})).findings.some((f) => f.metadata?.unprovisioned === true)).toBe(true);
		expect((await m.osintInvestigationReport('inv_1', {})).findings.some((f) => f.metadata?.unprovisioned === true)).toBe(true);
	});

	it('status: omits heavy findings[] and preserves upstream summary text (not boolean true)', async () => {
		const m = await import('../src/tools/osint-investigate');
		const upstream = {
			id: 'inv_9',
			type: 'deep_infrastructure',
			status: 'completed',
			progress: 100,
			totalChecks: 8,
			completedChecks: 8,
			foundCount: 44,
			summary: 'Investigation complete: 44 entities found.',
			findings: Array.from({ length: 44 }, (_, i) => ({ id: String(i), title: 'f', rawData: 'x'.repeat(2000) })),
		};
		const r = await m.osintInvestigationStatus('inv_9', { reconBinding: binding(upstream), reconAuthToken: 't' });
		const meta = r.findings[0]!.metadata!;
		// Bug #7: status must not inline the heavy findings[] array (caused 53 KB token-cap overflow).
		expect(meta.findings).toBeUndefined();
		// Bug #8: `summary: true` is the codebase summary-finding sentinel — it must survive,
		// and the upstream summary TEXT must be preserved under investigationSummary (it was clobbered before).
		expect(meta.summary).toBe(true);
		expect(meta.investigationSummary).toBe('Investigation complete: 44 entities found.');
		expect(meta.status).toBe('completed');
		expect(meta.foundCount).toBe(44);
		// 44 × 2 KB of rawData must not leak into status metadata.
		expect(JSON.stringify(meta).length).toBeLessThan(12_000);
	});

	it('report: shapes findings (drops heavy rawData), caps count, preserves summary', async () => {
		const m = await import('../src/tools/osint-investigate');
		const upstream = {
			summary: 'Report ready.',
			total: 120,
			findings: Array.from({ length: 120 }, (_, i) => ({
				id: String(i),
				type: 'domain_dns',
				severity: 'high',
				title: `finding ${i}`,
				details: 'detail text',
				confidence: 95,
				platform: 'dns-worker',
				url: null,
				rawData: 'Z'.repeat(5000),
				evidenceR2Key: null,
			})),
		};
		const r = await m.osintInvestigationReport('inv_9', { reconBinding: binding(upstream), reconAuthToken: 't' });
		const meta = r.findings[0]!.metadata!;
		expect(meta.summary).toBe(true); // summary-finding sentinel preserved
		expect(meta.investigationSummary).toBe('Report ready.'); // upstream text under non-colliding key
		const shaped = meta.findings as Array<Record<string, unknown>>;
		expect(shaped.length).toBeLessThanOrEqual(100);
		expect(shaped[0]!.rawData).toBeUndefined();
		expect(shaped[0]!.title).toBe('finding 0');
		expect(shaped[0]!.severity).toBe('high');
	});
});
