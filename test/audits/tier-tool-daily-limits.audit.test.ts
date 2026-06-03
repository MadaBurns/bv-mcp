// SPDX-License-Identifier: BUSL-1.1
//
// Audit test: TIER_TOOL_DAILY_LIMITS values match the published pricing matrix.
//
// Background: `TIER_DAILY_LIMITS` sets a flat per-tool daily cap by tier.
// `TIER_TOOL_DAILY_LIMITS` overrides specific (tier, tool) pairs — used to give
// `partner` higher caps on common tools, `agent` zero caps on brand-audit
// (a paid feature), and `developer`/`enterprise` explicit brand-audit ceilings.
//
// The existing `test/audits/brand-audit-quota.audit.test.ts` pins
// `BRAND_AUDIT_QUOTAS` (monthly per-tier). This complements it by pinning the
// daily-per-tool overrides — without this lock, silent drift between the
// pricing matrix and the runtime config would only surface in customer
// support tickets.
//
// Per testing-methodology.md principle 4 — audit tests replace review checklists.

import { describe, it, expect } from 'vitest';
import { TIER_DAILY_LIMITS, TIER_TOOL_DAILY_LIMITS, TIER_CONCURRENT_LIMITS } from '../../src/lib/config';

const ALL_TIERS = ['free', 'agent', 'developer', 'enterprise', 'partner', 'owner'] as const;

const BRAND_AUDIT_TOOLS = [
	'brand_audit_single',
	'brand_audit_batch_start',
	'brand_audit_status',
	'brand_audit_get_report',
	'list_brand_audit_watches',
	'register_brand_audit_watch',
	'delete_brand_audit_watch',
] as const;

describe('TIER_DAILY_LIMITS audit (flat per-tier defaults)', () => {
	it('covers every tier from the McpApiKeyTier union', () => {
		expect(new Set(Object.keys(TIER_DAILY_LIMITS))).toEqual(new Set(ALL_TIERS));
	});

	it('locks the documented per-tier daily values', () => {
		// These values are the published pricing-matrix baseline. Any drift requires an
		// explicit doc update + audit-test update — it MUST be a deliberate decision.
		expect(TIER_DAILY_LIMITS).toEqual({
			free: 50,
			agent: 200,
			developer: 500,
			enterprise: 10_000,
			partner: 100_000,
			owner: Infinity,
		});
	});

	it('paid tiers form a non-decreasing series (free ≤ agent ≤ developer ≤ enterprise ≤ partner ≤ owner)', () => {
		expect(TIER_DAILY_LIMITS.free).toBeLessThanOrEqual(TIER_DAILY_LIMITS.agent);
		expect(TIER_DAILY_LIMITS.agent).toBeLessThanOrEqual(TIER_DAILY_LIMITS.developer);
		expect(TIER_DAILY_LIMITS.developer).toBeLessThanOrEqual(TIER_DAILY_LIMITS.enterprise);
		expect(TIER_DAILY_LIMITS.enterprise).toBeLessThanOrEqual(TIER_DAILY_LIMITS.partner);
		expect(TIER_DAILY_LIMITS.partner).toBeLessThanOrEqual(TIER_DAILY_LIMITS.owner);
	});
});

describe('TIER_TOOL_DAILY_LIMITS audit (per-tool per-tier overrides)', () => {
	it('brand-audit family is zero for agent (paid feature; double-locks with BRAND_AUDIT_QUOTAS.agent = 0)', () => {
		const agentOverrides = TIER_TOOL_DAILY_LIMITS.agent ?? {};
		for (const tool of BRAND_AUDIT_TOOLS) {
			expect(agentOverrides[tool], `agent tier must have explicit 0 for ${tool}`).toBe(0);
		}
	});

	it('developer brand-audit ceilings match the published monthly tier (50 audits/month, 5000 read calls/day)', () => {
		const developerOverrides = TIER_TOOL_DAILY_LIMITS.developer ?? {};
		expect(developerOverrides).toEqual({
			brand_audit_single: 50,
			brand_audit_batch_start: 50,
			brand_audit_status: 5_000,
			brand_audit_get_report: 5_000,
			list_brand_audit_watches: 20,
			register_brand_audit_watch: 20,
			delete_brand_audit_watch: 20,
		});
	});

	it('enterprise brand-audit ceilings match the published monthly tier (500 audits/month, 25k read calls/day)', () => {
		const enterpriseOverrides = TIER_TOOL_DAILY_LIMITS.enterprise ?? {};
		expect(enterpriseOverrides).toEqual({
			brand_audit_single: 500,
			brand_audit_batch_start: 500,
			brand_audit_status: 25_000,
			brand_audit_get_report: 25_000,
			list_brand_audit_watches: 100,
			register_brand_audit_watch: 100,
			delete_brand_audit_watch: 100,
		});
	});

	it('partner brand-audit ceilings are between developer and enterprise (200 audits, 10k read calls)', () => {
		// Partner is an operator-deploy tier, between developer (50/month) and
		// enterprise (500/month). The daily-per-tool caps mirror that monthly budget
		// because brand audits are multi-minute operations: a customer who is
		// allowed 200/month should not be allowed to burn 500 in one day.
		const partnerOverrides = TIER_TOOL_DAILY_LIMITS.partner ?? {};
		expect(partnerOverrides.brand_audit_single).toBe(200);
		expect(partnerOverrides.brand_audit_batch_start).toBe(200);
		expect(partnerOverrides.list_brand_audit_watches).toBe(100);
		expect(partnerOverrides.register_brand_audit_watch).toBe(100);
		expect(partnerOverrides.delete_brand_audit_watch).toBe(100);
		// Non-brand_audit partner overrides exist too; we only lock the brand-audit
		// subset here to keep the audit scoped to the paywall-relevant rows.
	});

	it('brand-audit daily caps are non-decreasing across paid tiers (developer ≤ partner ≤ enterprise) for write ops', () => {
		const dev = TIER_TOOL_DAILY_LIMITS.developer ?? {};
		const part = TIER_TOOL_DAILY_LIMITS.partner ?? {};
		const ent = TIER_TOOL_DAILY_LIMITS.enterprise ?? {};
		for (const tool of ['brand_audit_single', 'brand_audit_batch_start'] as const) {
			expect(dev[tool], `${tool}: developer ≤ partner`).toBeLessThanOrEqual(part[tool] ?? Infinity);
			expect(part[tool], `${tool}: partner ≤ enterprise`).toBeLessThanOrEqual(ent[tool] ?? Infinity);
		}
	});

	it('partner override map covers every tool listed in TIER_TOOL_DAILY_LIMITS.partner from the pricing matrix', () => {
		// Partner is a special operator-deploy tier with elevated caps. This test
		// pins which tools have per-partner overrides — adding new partner override
		// rows requires explicit update here.
		const partner = TIER_TOOL_DAILY_LIMITS.partner ?? {};
		const expectedKeys = new Set([
			'scan_domain',
			'scan',
			'compare_baseline',
			'check_spf',
			'check_dmarc',
			'check_dkim',
			'check_mx',
			'check_ns',
			'check_ssl',
			'check_dnssec',
			'check_mta_sts',
			'check_caa',
			'check_bimi',
			'check_tlsrpt',
			'check_lookalikes',
			'check_shadow_domains',
			'check_txt_hygiene',
			'check_http_security',
			'check_dane',
			'check_ptr',
			'check_mx_reputation',
			'check_srv',
			'check_zone_hygiene',
			'check_subdomailing',
			'explain_finding',
			'discover_brand_domains',
			'brand_audit_single',
			'brand_audit_batch_start',
			'brand_audit_status',
			'brand_audit_get_report',
			'list_brand_audit_watches',
			'register_brand_audit_watch',
			'delete_brand_audit_watch',
		]);
		expect(new Set(Object.keys(partner))).toEqual(expectedKeys);
	});
});

describe('TIER_CONCURRENT_LIMITS audit', () => {
	it('locks the published concurrency caps', () => {
		expect(TIER_CONCURRENT_LIMITS).toEqual({
			free: 3,
			agent: 5,
			developer: 10,
			enterprise: 25,
			partner: 50,
			owner: Infinity,
		});
	});
});
