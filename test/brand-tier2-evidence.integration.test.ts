// SPDX-License-Identifier: BUSL-1.1
/**
 * Integration tests for the Tier 2 evidence wrapper against a live
 * `BV_INTEL_GATEWAY` service binding.
 *
 * Skipped until the bv-intel-gateway producer ships `getDomainEvidence` on
 * its `WorkerEntrypoint` (cross-Worker contract § 1.2) AND the binding is
 * wired into this Worker's `wrangler.jsonc` (T7 in the brand-discovery TDD
 * plan).
 *
 * These tests intentionally exercise the RPC boundary — the unit tests
 * (`brand-tier2-evidence.test.ts`) cover the wrapper logic with a mock
 * binding.
 */

import { describe, it, expect } from 'vitest';
import { tier2EvidenceLookup, type IntelGatewayBinding } from '../src/lib/brand-tier2-evidence';

// Placeholder — populated when the binding is wired into `env`.
declare const env: { BV_INTEL_GATEWAY?: IntelGatewayBinding };

describe.skip('tier2EvidenceLookup — integration (live BV_INTEL_GATEWAY)', () => {
	it('returns Tier 2 observation for a known-in-corpus seed', async () => {
		const result = await tier2EvidenceLookup('example.com', env.BV_INTEL_GATEWAY);

		expect(result.status).toBe('ok');
		expect(result.observations.find((o) => o.tier === 2)).toBeDefined();
	});

	it('returns skipped for a seed not in the GSI corpus', async () => {
		const result = await tier2EvidenceLookup('definitely-not-in-corpus.invalid', env.BV_INTEL_GATEWAY);

		expect(result.status).toBe('skipped');
		expect(result.observations).toHaveLength(0);
	});

	it('returns skipped for an opted-out seed (source-layer filter applied)', async () => {
		// One of the 5 production rows in `gsi_domain_optouts`. Replace with a
		// fixture domain once T7 wires the binding.
		const result = await tier2EvidenceLookup('opted-out-fixture.example', env.BV_INTEL_GATEWAY);

		expect(result.status).toBe('skipped');
		expect(result.observations).toHaveLength(0);
	});
});
