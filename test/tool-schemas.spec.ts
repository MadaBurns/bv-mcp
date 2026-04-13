// SPDX-License-Identifier: BUSL-1.1

/**
 * Static validation tests for MCP tool schema metadata.
 * Ensures every tool has complete group/tier/scanIncluded metadata
 * and that values stay consistent with scan_domain orchestration.
 */

import { describe, it, expect } from 'vitest';
import { TOOLS } from '../src/handlers/tool-schemas';
import type { ToolGroup, ToolTier } from '../src/handlers/tool-schemas';

const VALID_GROUPS: ToolGroup[] = ['email_auth', 'infrastructure', 'brand_threats', 'dns_hygiene', 'intelligence', 'remediation', 'meta'];
const VALID_TIERS: ToolTier[] = ['core', 'protective', 'hardening'];

/** Tools included in scan_domain parallel orchestration (excludes check_subdomain_takeover which is internal). */
const SCAN_DOMAIN_TOOL_NAMES = new Set([
	'check_spf', 'check_dmarc', 'check_dkim', 'check_dnssec', 'check_ssl',
	'check_mta_sts', 'check_ns', 'check_caa', 'check_bimi', 'check_tlsrpt',
	'check_http_security', 'check_dane', 'check_dane_https', 'check_svcb_https', 'check_mx',
	'check_subdomailing',
]);

/** Tools that are standalone-only or non-scoring orchestration/meta tools. */
const NON_SCAN_TOOL_NAMES = new Set([
	'check_lookalikes', 'check_shadow_domains', 'check_txt_hygiene',
	'check_mx_reputation', 'check_srv', 'check_zone_hygiene', 'check_resolver_consistency',
	'scan_domain', 'batch_scan', 'compare_domains', 'compare_baseline', 'generate_fix_plan', 'generate_spf_record',
	'generate_dmarc_record', 'generate_dkim_config', 'generate_mta_sts_policy',
	'get_benchmark', 'get_provider_insights', 'assess_spoofability', 'explain_finding',
	'map_supply_chain', 'analyze_drift', 'validate_fix', 'generate_rollout_plan',
	'resolve_spf_chain', 'discover_subdomains', 'map_compliance', 'simulate_attack_paths',
	'check_dbl',
	'check_rbl',
	'cymru_asn',
	'rdap_lookup',
	'check_nsec_walkability',
	'check_dnssec_chain',
	'check_fast_flux',
]);

describe('tool-schemas metadata', () => {
	it('exports exactly 42 tools', () => {
		expect(TOOLS).toHaveLength(51);
	});

	it('all tool names are unique', () => {
		const names = TOOLS.map((t) => t.name);
		expect(new Set(names).size).toBe(names.length);
	});

	it('every tool has a valid group', () => {
		for (const tool of TOOLS) {
			expect(VALID_GROUPS, `${tool.name}: group must be a ToolGroup value`).toContain(tool.group);
		}
	});

	it('every tool has a boolean scanIncluded', () => {
		for (const tool of TOOLS) {
			expect(typeof tool.scanIncluded, `${tool.name}: scanIncluded must be boolean`).toBe('boolean');
		}
	});

	it('tools with a tier have a valid tier value', () => {
		for (const tool of TOOLS) {
			if (tool.tier !== undefined) {
				expect(VALID_TIERS, `${tool.name}: tier must be a ToolTier value`).toContain(tool.tier);
			}
		}
	});

	it('tools included in scan_domain are marked scanIncluded=true', () => {
		for (const tool of TOOLS) {
			if (SCAN_DOMAIN_TOOL_NAMES.has(tool.name)) {
				expect(tool.scanIncluded, `${tool.name} is in scan_domain orchestration but scanIncluded=false`).toBe(true);
			}
		}
	});

	it('standalone and non-scoring tools are marked scanIncluded=false', () => {
		for (const name of NON_SCAN_TOOL_NAMES) {
			const tool = TOOLS.find((t) => t.name === name);
			expect(tool, `${name} not found in TOOLS`).toBeDefined();
			expect(tool!.scanIncluded, `${name} should have scanIncluded=false`).toBe(false);
		}
	});

	it('all scoring check tools have a tier (except check_resolver_consistency)', () => {
		const checkTools = TOOLS.filter((t) => t.name.startsWith('check_') && t.name !== 'check_resolver_consistency' && t.group !== 'intelligence');
		for (const tool of checkTools) {
			expect(tool.tier, `${tool.name} is a scoring check but is missing a tier`).toBeDefined();
		}
	});

	it('non-scoring tools (meta/intelligence/remediation) have no tier', () => {
		const nonScoringGroups: ToolGroup[] = ['meta', 'intelligence', 'remediation'];
		for (const tool of TOOLS) {
			if (nonScoringGroups.includes(tool.group)) {
				expect(tool.tier, `${tool.name} in group '${tool.group}' should not have a tier`).toBeUndefined();
			}
		}
	});

	it('scan and non-scan tool sets are exhaustive and non-overlapping', () => {
		// Verify SCAN + NON_SCAN covers all 33 tools with no overlap
		const allExpected = new Set([...SCAN_DOMAIN_TOOL_NAMES, ...NON_SCAN_TOOL_NAMES]);
		expect(allExpected.size).toBe(SCAN_DOMAIN_TOOL_NAMES.size + NON_SCAN_TOOL_NAMES.size); // no overlap
		for (const tool of TOOLS) {
			expect(allExpected, `${tool.name} is not listed in either scan or non-scan set`).toContain(tool.name);
		}
	});
});
