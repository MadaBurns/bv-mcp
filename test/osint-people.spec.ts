// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, vi, afterEach } from 'vitest';
afterEach(() => vi.restoreAllMocks());
function binding(body: unknown, status = 200) {
	return { fetch: vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })) };
}
/** An owner record must be storable or the start is refused (SQ-566). */
function startOpts() {
	const store = new Map<string, string>();
	const reconJobKv = {
		get: vi.fn(async (key: string) => store.get(key) ?? null),
		put: vi.fn(async (key: string, value: string) => {
			store.set(key, value);
		}),
	} as unknown as KVNamespace;
	return { reconJobKv, principalId: 'p1' };
}
describe('people-OSINT tier gate', () => {
	it('denies a developer-tier caller and makes NO bv-recon call', async () => {
		const { osintInvestigateUsernameStart } = await import('../src/tools/osint-people');
		const b = binding({ investigationId: 'inv_1' });
		const r = await osintInvestigateUsernameStart('alice', { reconBinding: b, reconAuthToken: 't', authTier: 'developer' });
		expect(r.findings.some((f) => f.metadata?.tierDenied === true)).toBe(true);
		expect(b.fetch).not.toHaveBeenCalled();
	});
	it('denies free/agent/partner/undefined tiers', async () => {
		const { osintInvestigateUsernameStart } = await import('../src/tools/osint-people');
		for (const t of ['free', 'agent', 'partner', undefined] as const) {
			const r = await osintInvestigateUsernameStart('alice', { authTier: t });
			expect(r.findings.some((f) => f.metadata?.tierDenied === true)).toBe(true);
		}
	});
	it('allows owner tier and starts the investigation', async () => {
		const { osintInvestigateUsernameStart } = await import('../src/tools/osint-people');
		const r = await osintInvestigateUsernameStart('alice', { reconBinding: binding({ investigationId: 'inv_1', status: 'running' }), reconAuthToken: 't', authTier: 'owner', ...startOpts() });
		expect(r.findings.some((f) => f.metadata?.investigationId === 'inv_1')).toBe(true);
	});
	it('allows enterprise tier (email)', async () => {
		const { osintInvestigateEmailStart } = await import('../src/tools/osint-people');
		const r = await osintInvestigateEmailStart('a@b.com', { reconBinding: binding({ investigationId: 'inv_2' }), reconAuthToken: 't', authTier: 'enterprise', ...startOpts() });
		expect(r.findings.some((f) => f.metadata?.investigationId === 'inv_2')).toBe(true);
	});
});
