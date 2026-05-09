// Audit test: partner-tier scan_domain quota must support Tenant-class
// enterprise customers (one-shot 2.5M-domain portfolio audits).
//
// Background: Phase 0 of the Tenant enterprise enablement plan. Tenant's headline
// customer has 2.5M-domain portfolios; the prior 100K/day partner-tier cap
// blocked one-shot audits. This audit locks the floor so a future regression
// toward the lower number trips CI.
//
// Per testing-methodology.md principle 4 — audit tests replace review checklists.

import { describe, it, expect } from 'vitest';
import { TIER_TOOL_DAILY_LIMITS } from '../../src/lib/config';

const Tenant_FLOOR = 2_500_000;

describe('tenant-scale-quota audit', () => {
	it('partner.scan_domain meets Tenant-class one-shot portfolio audit floor (>= 2.5M)', () => {
		const limit = TIER_TOOL_DAILY_LIMITS.partner?.scan_domain;
		expect(limit, 'TIER_TOOL_DAILY_LIMITS.partner.scan_domain must be defined').toBeDefined();
		expect(limit).toBeGreaterThanOrEqual(Tenant_FLOOR);
	});

	it('partner.scan alias meets Tenant-class one-shot portfolio audit floor (>= 2.5M)', () => {
		// `tools/call` resolves `scan` → `scan_domain`, so the alias must match.
		const limit = TIER_TOOL_DAILY_LIMITS.partner?.scan;
		expect(limit, 'TIER_TOOL_DAILY_LIMITS.partner.scan must be defined').toBeDefined();
		expect(limit).toBeGreaterThanOrEqual(Tenant_FLOOR);
	});

	it('partner.scan_domain and partner.scan stay in sync', () => {
		const scanDomain = TIER_TOOL_DAILY_LIMITS.partner?.scan_domain;
		const scan = TIER_TOOL_DAILY_LIMITS.partner?.scan;
		expect(scan, 'partner.scan must equal partner.scan_domain (alias)').toBe(scanDomain);
	});
});
