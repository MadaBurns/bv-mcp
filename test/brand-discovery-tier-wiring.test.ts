// SPDX-License-Identifier: BUSL-1.1

/**
 * Wiring tests for the brand-discovery tier closures.
 *
 * The unit tests in `test/discover-brand-domains.spec.ts` inject `tier0Lookup`,
 * `tier1Lookup`, and `tier2Lookup` mocks directly into `discoverBrandDomains`'
 * `deps` arg. They verify the *behavior* of the closures (Tier 0 short-circuit,
 * Tier 3 fallback heuristics, etc.).
 *
 * These tests cover the *wiring* — that the pipeline-level injection point
 * (`BrandAuditPipelineDeps`) actually forwards tier closures through to
 * `discoverBrandDomains`. Without this assertion, the production seam at
 * `src/index.ts` could silently drop the closures and we wouldn't notice
 * until tiered audits regressed to Tier-3-equivalent classic mode (the
 * exact bug T7 deferred).
 *
 * Per testing-methodology.md principle 4 — audit/unit tests replace review
 * checklists. The "wiring is connected" assertion belongs at the lowest
 * layer where it's catchable, which is the pipeline-deps contract.
 */

import { describe, expect, it, vi } from 'vitest';
import { runBrandAuditPipeline } from '../src/lib/brand-audit-pipeline';
import type { CheckResult, Finding } from '../src/lib/scoring';

function summaryFinding(seedDomain: string, surfaced: number): Finding {
	return {
		category: 'brand_discovery',
		title: `Brand-domain discovery: ${surfaced} candidate(s)`,
		severity: 'info',
		detail: `Seed=${seedDomain}`,
		metadata: { summary: true, signals: ['ns'], signalStatus: {}, minConfidence: 0.5, totalAggregated: surfaced, surfaced },
	};
}

function emptyDiscovery(seedDomain: string): CheckResult {
	return {
		category: 'brand_discovery',
		score: 100,
		findings: [summaryFinding(seedDomain, 0)],
	};
}

function rdapResult(): CheckResult {
	return {
		category: 'rdap',
		score: 100,
		findings: [
			{
				category: 'rdap',
				title: 'RDAP registrar',
				severity: 'info',
				detail: 'MarkMonitor Inc.',
				metadata: { registrar: 'MarkMonitor Inc.', registrarIanaId: null, registrarSource: 'rdap', registrant: 'Example Inc.' },
			},
		],
	};
}

describe('brand-audit pipeline → discoverBrandDomains tier-closure wiring', () => {
	it('forwards tier0Lookup / tier1Lookup / tier2Lookup deps through to discoverBrandDomains', async () => {
		// The pipeline calls `discover(seedDomain, opts)` with *two* args in
		// pre-wiring code. Once tier closures land in `BrandAuditPipelineDeps`,
		// the call site must pass a 3rd `deps` arg containing them — otherwise
		// the production seam is dropped on the floor and tiered mode degrades
		// to Tier-3-equivalent classic. This test fails RED until that 3rd arg
		// is added; GREEN once the production wiring is correct.
		const tier0Lookup = vi.fn();
		const tier1Lookup = vi.fn();
		const tier2Lookup = vi.fn();
		const discoverBrandDomains = vi.fn(async (seed: string, _opts: unknown, deps?: { tier0Lookup?: unknown; tier1Lookup?: unknown; tier2Lookup?: unknown }) => {
			// Assert the deps arrived — if the pipeline didn't pass a 3rd arg
			// these would all be undefined.
			expect(deps?.tier0Lookup, 'pipeline must forward tier0Lookup to discoverBrandDomains').toBe(tier0Lookup);
			expect(deps?.tier1Lookup, 'pipeline must forward tier1Lookup to discoverBrandDomains').toBe(tier1Lookup);
			expect(deps?.tier2Lookup, 'pipeline must forward tier2Lookup to discoverBrandDomains').toBe(tier2Lookup);
			return emptyDiscovery(seed);
		});
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult());

		await runBrandAuditPipeline(
			'example.com',
			{ discovery_mode: 'tiered' },
			{
				discoverBrandDomains: discoverBrandDomains as never,
				checkRdapLookup,
				tier0Lookup,
				tier1Lookup,
				tier2Lookup,
			},
		);

		expect(discoverBrandDomains).toHaveBeenCalled();
	});

	it('passes no tier deps to discoverBrandDomains when pipeline deps omit them (BSL self-host)', async () => {
		// On BSL self-hosts the tier closures are undefined — the pipeline must
		// still call discoverBrandDomains cleanly and the closures stay undefined
		// inside. (Reverse of the prior test: confirms we don't fabricate
		// closures when the operator hasn't provisioned the bindings.)
		const discoverBrandDomains = vi.fn(async (seed: string, _opts: unknown, deps?: { tier0Lookup?: unknown; tier1Lookup?: unknown; tier2Lookup?: unknown }) => {
			expect(deps?.tier0Lookup).toBeUndefined();
			expect(deps?.tier1Lookup).toBeUndefined();
			expect(deps?.tier2Lookup).toBeUndefined();
			return emptyDiscovery(seed);
		});
		const checkRdapLookup = vi.fn().mockResolvedValue(rdapResult());

		await runBrandAuditPipeline(
			'example.com',
			{},
			{ discoverBrandDomains: discoverBrandDomains as never, checkRdapLookup },
		);

		expect(discoverBrandDomains).toHaveBeenCalled();
	});
});
