// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit: the two infrastructure-provider allowlists must agree.
 *
 * Two separate sets serve the same intent today:
 *   1. INFRASTRUCTURE_PROVIDERS in src/tools/discover-brand-domains.ts —
 *      orchestrator-level filter (drop matching candidates entirely).
 *   2. KNOWN_DMARC_PROCESSORS in src/tenants/discovery/dmarc-rua-miner.ts —
 *      miner-level classifier (emit `processor` with confidence 0).
 *
 * Any host the orchestrator considers infrastructure SHOULD also be a known
 * processor at the miner — otherwise the miner emits `related @ 0.6` for
 * that host before the orchestrator gets a chance to filter it. Defense in
 * depth: the orchestrator should never see a `related`-classed aggregator.
 *
 * Ref: v2.14.0 audit, "Cross-module consistency" / Patch 3.
 */

import { describe, it, expect } from 'vitest';
import { INFRASTRUCTURE_PROVIDERS } from '../../src/tools/discover-brand-domains';
import { KNOWN_DMARC_PROCESSORS } from '../../src/tenants/discovery/dmarc-rua-miner';

describe('infrastructure allowlist cross-module consistency', () => {
	it('every INFRASTRUCTURE_PROVIDER is also a KNOWN_DMARC_PROCESSOR', () => {
		const missing = [...INFRASTRUCTURE_PROVIDERS].filter(
			(p) => !KNOWN_DMARC_PROCESSORS.has(p),
		);
		expect(missing).toEqual([]);
	});

	it('the two sets are mutually consistent (no miner-only entries either)', () => {
		const orphans = [...KNOWN_DMARC_PROCESSORS].filter(
			(p) => !INFRASTRUCTURE_PROVIDERS.has(p),
		);
		expect(orphans).toEqual([]);
	});
});
