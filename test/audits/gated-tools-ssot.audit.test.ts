import { describe, it, expect } from 'vitest';
import {
	GATED_PAID_ONLY_TOOLS,
	FREE_DISTINCT_DOMAIN_DAILY_LIMIT,
	FREE_TOOL_DAILY_LIMITS,
	TIER_TOOL_DAILY_LIMITS,
} from '../../src/lib/config';

describe('gated paid-only tools SSOT', () => {
	it('contains the offensive + multi-domain surface', () => {
		for (const tool of [
			'discover_subdomains',
			'simulate_attack_paths',
			'check_fast_flux',
			'map_supply_chain',
			'check_lookalikes',
			'check_shadow_domains',
			'scan_buckets_start',
			'osint_investigate_domain_start',
			'osint_investigate_infrastructure_start',
			'osint_investigate_supply_chain_start',
			'osint_investigate_username_start',
			'osint_investigate_email_start',
			'check_realtime_threat_feed',
			'batch_scan',
			'compare_domains',
		]) {
			expect(GATED_PAID_ONLY_TOOLS.has(tool)).toBe(true);
		}
	});

	it('does NOT gate the pollers', () => {
		for (const poller of ['scan_buckets_status', 'scan_buckets_findings', 'osint_investigation_status', 'osint_investigation_report']) {
			expect(GATED_PAID_ONLY_TOOLS.has(poller)).toBe(false);
		}
	});

	it('every gated tool is pinned to 0 in all three free/agent maps', () => {
		for (const tool of GATED_PAID_ONLY_TOOLS) {
			expect(FREE_TOOL_DAILY_LIMITS[tool]).toBe(0);
			expect(TIER_TOOL_DAILY_LIMITS.free?.[tool]).toBe(0);
			expect(TIER_TOOL_DAILY_LIMITS.agent?.[tool]).toBe(0);
		}
	});

	it('uses a positive, finite distinct-domain daily limit', () => {
		expect(Number.isInteger(FREE_DISTINCT_DOMAIN_DAILY_LIMIT)).toBe(true);
		expect(FREE_DISTINCT_DOMAIN_DAILY_LIMIT).toBeGreaterThan(0);
	});
});
