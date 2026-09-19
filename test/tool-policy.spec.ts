// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { AUTH_REQUIRED_TOOLS, evaluateToolPolicy, INTERNAL_ONLY_TOOLS } from '../src/lib/config';

/**
 * SQ-67 — the shared per-tool policy chokepoint. One function answers for both
 * entry points, so the public `/mcp` path and the `/internal/tools/*` door
 * cannot drift apart again. The per-surface dispositions are the contract; this
 * spec is where they are written down as executable truth.
 */
describe('evaluateToolPolicy — public surface', () => {
	it('blocks an internal-only tool for every caller', () => {
		expect(evaluateToolPolicy({ surface: 'public', tool: 'map_registrar_products', authenticated: false, tier: null })).toEqual({
			allowed: false,
			block: 'internal_only',
		});
		expect(evaluateToolPolicy({ surface: 'public', tool: 'map_registrar_products', authenticated: true, tier: 'owner' })).toEqual({
			allowed: false,
			block: 'internal_only',
		});
	});

	it('blocks a paid-only tool for an unauthenticated caller', () => {
		expect(evaluateToolPolicy({ surface: 'public', tool: 'discover_subdomains', authenticated: false, tier: null })).toEqual({
			allowed: false,
			block: 'paid_only',
		});
	});

	it('blocks a paid-only tool for a tier pinned to a zero quota', () => {
		for (const tier of ['free', 'agent'] as const) {
			expect(evaluateToolPolicy({ surface: 'public', tool: 'discover_subdomains', authenticated: true, tier })).toEqual({
				allowed: false,
				block: 'paid_only',
			});
		}
	});

	it('allows a paid-only tool for a paid tier', () => {
		for (const tier of ['developer', 'enterprise', 'partner', 'owner'] as const) {
			expect(evaluateToolPolicy({ surface: 'public', tool: 'discover_subdomains', authenticated: true, tier })).toEqual({ allowed: true });
		}
	});

	it('blocks a contract-flagged tool for a paid tier without the claim, only while the gate is on', () => {
		const base = { surface: 'public', tool: 'discover_subdomains', authenticated: true, tier: 'developer' } as const;
		expect(evaluateToolPolicy({ ...base, contractFlagGateEnabled: false, hasContractFlag: false })).toEqual({ allowed: true });
		expect(evaluateToolPolicy({ ...base, contractFlagGateEnabled: true, hasContractFlag: false })).toEqual({
			allowed: false,
			block: 'contract_flag',
		});
		expect(evaluateToolPolicy({ ...base, contractFlagGateEnabled: true, hasContractFlag: true })).toEqual({ allowed: true });
		// `owner` bypasses the flag.
		expect(evaluateToolPolicy({ ...base, tier: 'owner', contractFlagGateEnabled: true, hasContractFlag: false })).toEqual({
			allowed: true,
		});
	});

	it('leaves an ordinary hygiene tool alone', () => {
		expect(evaluateToolPolicy({ surface: 'public', tool: 'check_spf', authenticated: false, tier: null })).toEqual({ allowed: true });
	});

	it('answers internal_only, not auth_required, for the identity_secops tools', () => {
		// The documented shadowing: all four AUTH_REQUIRED_TOOLS are ALSO in
		// INTERNAL_ONLY_TOOLS since 3.63.0, and internal-only has the higher
		// precedence (no existence leak). The coupling is pinned by
		// test/identity-secops-auth-gate.spec.ts — a tool leaving INTERNAL_ONLY_TOOLS
		// re-exposes the 401 arm, which is why it is kept, not deleted.
		for (const tool of AUTH_REQUIRED_TOOLS) {
			expect(INTERNAL_ONLY_TOOLS.has(tool)).toBe(true);
			expect(evaluateToolPolicy({ surface: 'public', tool, authenticated: false, tier: null })).toEqual({
				allowed: false,
				block: 'internal_only',
			});
		}
	});
});

describe('evaluateToolPolicy — internal surface', () => {
	/** bv-web's fleet capability. */
	const web = { surface: 'internal', authenticated: true, tier: 'owner', fullInternalAuthority: true } as const;
	/** REQUIRE_INTERNAL_AUTH=false: the cf-connecting-ip guard alone, no key presented. */
	const network = { surface: 'internal', authenticated: false, tier: 'free', fullInternalAuthority: true } as const;
	/** The BizFit mobile Worker: a real key, but a narrow one. */
	const mobile = { surface: 'internal', authenticated: true, tier: 'free', fullInternalAuthority: false } as const;
	/** bv-web tenant delegation, carrying the tenant's own paid tier. */
	const tenantTool = { surface: 'internal', authenticated: true, tier: 'developer', fullInternalAuthority: false } as const;

	it('allows internal-only tools — that is what the set means', () => {
		for (const caller of [web, network, mobile, tenantTool]) {
			expect(evaluateToolPolicy({ ...caller, tool: 'map_registrar_products' })).toEqual({ allowed: true });
		}
	});

	it('restricts auth-required M365 reads to a full-authority principal holding a real capability key', () => {
		expect(evaluateToolPolicy({ ...web, tool: 'query_signins' })).toEqual({ allowed: true });
		// No key presented: the network guard is not enough to forward the trusted
		// internal bearer into a customer's Entra tenant.
		expect(evaluateToolPolicy({ ...network, tool: 'query_signins' })).toEqual({ allowed: false, block: 'auth_required' });
		// A real key, but a narrow capability.
		expect(evaluateToolPolicy({ ...mobile, tool: 'query_signins' })).toEqual({ allowed: false, block: 'auth_required' });
		expect(evaluateToolPolicy({ ...tenantTool, tool: 'query_signins' })).toEqual({ allowed: false, block: 'auth_required' });
	});

	it('passes paid-only tools for first-party full-authority callers', () => {
		// Ops sweeps, load tests and the bv-web service binding all land here; the
		// paid-only gate is a commercial control on the public catalog, not on the
		// operator's own door.
		expect(evaluateToolPolicy({ ...web, tool: 'discover_subdomains' })).toEqual({ allowed: true });
		expect(evaluateToolPolicy({ ...network, tool: 'discover_subdomains' })).toEqual({ allowed: true });
	});

	it('applies the paid-only quota rule to every narrower internal principal', () => {
		// The mobile credential is free-tier: if its scan-only allowlist were ever
		// widened, the paid surface still stays shut.
		expect(evaluateToolPolicy({ ...mobile, tool: 'discover_subdomains' })).toEqual({ allowed: false, block: 'paid_only' });
		// Tenant delegation carries the tenant's paid tier, so its three brand-watch
		// tools (all paid-only) keep working.
		expect(evaluateToolPolicy({ ...tenantTool, tool: 'register_brand_audit_watch' })).toEqual({ allowed: true });
		expect(evaluateToolPolicy({ ...tenantTool, tool: 'delete_brand_audit_watch' })).toEqual({ allowed: true });
	});

	it('honours the contract-flag gate for a delegated paid tier once the operator turns it on', () => {
		expect(evaluateToolPolicy({ ...tenantTool, tool: 'discover_subdomains', contractFlagGateEnabled: false })).toEqual({ allowed: true });
		expect(evaluateToolPolicy({ ...tenantTool, tool: 'discover_subdomains', contractFlagGateEnabled: true })).toEqual({
			allowed: false,
			block: 'contract_flag',
		});
	});

	it('leaves an ordinary hygiene tool alone for every internal principal', () => {
		for (const caller of [web, network, mobile, tenantTool]) {
			expect(evaluateToolPolicy({ ...caller, tool: 'check_spf' })).toEqual({ allowed: true });
		}
	});

	it('allows an empty tool name to fall through to the dispatcher unknown-tool answer', () => {
		expect(evaluateToolPolicy({ surface: 'internal', tool: '', authenticated: true, tier: 'owner' })).toEqual({ allowed: true });
	});
});
