// SPDX-License-Identifier: BUSL-1.1
//
// Audit test: BRAND_AUDIT_QUOTAS must cover every McpApiKeyTier with an explicit
// value, and the values must match the published pricing matrix in CLAUDE.md.
//
// Background: brand_audit_single is metered separately from FREE_TOOL_DAILY_LIMITS
// because each target is a multi-minute deep-discovery operation. A missing or
// silently-defaulting tier would translate directly into either a refund event
// (over-grant) or a customer complaint (under-grant) — neither is recoverable
// at runtime, so it's audited here.
//
// Per testing-methodology.md principle 4 — audit tests replace review checklists.

import { describe, it, expect } from 'vitest';
import { BRAND_AUDIT_QUOTAS } from '../../src/lib/brand-audit-quota';
import { TIER_DAILY_LIMITS } from '../../src/lib/config';

describe('brand-audit-quota audit', () => {
	it('covers every McpApiKeyTier in TIER_DAILY_LIMITS', () => {
		const tiers = Object.keys(TIER_DAILY_LIMITS).sort();
		const covered = Object.keys(BRAND_AUDIT_QUOTAS).sort();
		expect(covered, `BRAND_AUDIT_QUOTAS must cover the same tier set as TIER_DAILY_LIMITS`).toEqual(tiers);
	});

	it('free and agent tiers are excluded (paid feature, not part of static-key allowance)', () => {
		expect(BRAND_AUDIT_QUOTAS.free).toBe(0);
		expect(BRAND_AUDIT_QUOTAS.agent).toBe(0);
	});

	it('owner tier is unlimited', () => {
		expect(BRAND_AUDIT_QUOTAS.owner).toBe(Number.POSITIVE_INFINITY);
	});

	it('paid tiers form a non-decreasing series (developer ≤ partner ≤ enterprise)', () => {
		expect(BRAND_AUDIT_QUOTAS.developer).toBeLessThanOrEqual(BRAND_AUDIT_QUOTAS.partner);
		expect(BRAND_AUDIT_QUOTAS.partner).toBeLessThanOrEqual(BRAND_AUDIT_QUOTAS.enterprise);
	});

	it('paid tier values match the published pricing matrix (developer=50, partner=200, enterprise=500)', () => {
		expect(BRAND_AUDIT_QUOTAS.developer).toBe(50);
		expect(BRAND_AUDIT_QUOTAS.partner).toBe(200);
		expect(BRAND_AUDIT_QUOTAS.enterprise).toBe(500);
	});
});
