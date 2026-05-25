// SPDX-License-Identifier: BUSL-1.1
// Audit: people-OSINT start tools deny all tiers except owner/enterprise,
// and make NO bv-recon call on denial. Governance invariant — do not weaken.
import { describe, it, expect, vi } from 'vitest';

const PEOPLE_TOOLS = ['osint_investigate_username_start', 'osint_investigate_email_start'] as const;
const DENIED_TIERS = ['free', 'agent', 'developer', 'partner', undefined] as const;
const ALLOWED_TIERS = ['owner', 'enterprise'] as const;

function spyBinding() {
	return { fetch: vi.fn(async () => new Response(JSON.stringify({ investigationId: 'inv_x', status: 'running' }), { status: 200, headers: { 'Content-Type': 'application/json' } })) };
}

describe('people-OSINT tier-gate audit', () => {
	it('denies non-owner/enterprise tiers without calling bv-recon', async () => {
		const { osintInvestigateUsernameStart, osintInvestigateEmailStart } = await import('../../src/tools/osint-people');
		const fns = { osint_investigate_username_start: osintInvestigateUsernameStart, osint_investigate_email_start: osintInvestigateEmailStart };
		for (const name of PEOPLE_TOOLS) {
			for (const tier of DENIED_TIERS) {
				const b = spyBinding();
				const r = await fns[name]('subject', { reconBinding: b, reconAuthToken: 't', authTier: tier });
				expect(r.findings.some((f) => f.metadata?.tierDenied === true), `${name} should deny tier=${tier}`).toBe(true);
				expect(b.fetch, `${name} must not call bv-recon for tier=${tier}`).not.toHaveBeenCalled();
			}
		}
	});
	it('permits owner and enterprise tiers', async () => {
		const { osintInvestigateUsernameStart } = await import('../../src/tools/osint-people');
		for (const tier of ALLOWED_TIERS) {
			const b = spyBinding();
			const r = await osintInvestigateUsernameStart('subject', { reconBinding: b, reconAuthToken: 't', authTier: tier });
			expect(r.findings.some((f) => f.metadata?.tierDenied === true), `tier=${tier} should be allowed`).toBe(false);
			expect(b.fetch).toHaveBeenCalledOnce();
		}
	});
});
