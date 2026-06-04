// SPDX-License-Identifier: BUSL-1.1

/**
 * Static validation tests for MCP tool schema metadata.
 * Ensures every tool has complete group/tier/scanIncluded metadata
 * and that values stay consistent with scan_domain orchestration.
 */

import { describe, it, expect } from 'vitest';
import { TOOLS } from '../src/schemas/tool-definitions';
import type { ToolGroup, ToolTier } from '../src/schemas/tool-definitions';

const VALID_GROUPS: ToolGroup[] = [
	'email_auth',
	'infrastructure',
	'brand_threats',
	'dns_hygiene',
	'intelligence',
	'remediation',
	'meta',
	'discovery',
	'identity_secops',
];
const VALID_TIERS: ToolTier[] = ['core', 'protective', 'hardening'];

/**
 * The exact set of tools wired into scan_domain parallel orchestration (excludes
 * check_subdomain_takeover, which runs inside scan_domain but is not a standalone
 * scanIncluded tool).
 *
 * This is an intentional exact-set tripwire: `scanIncluded` drives the scoring
 * denominator (a tool scored into scan_domain but mis-flagged drags every domain's
 * score), so any change to what scan_domain runs MUST be acknowledged here. The
 * derived set `TOOLS.filter((t) => t.scanIncluded)` is the source of truth; this
 * list is the guard. Mirrors the MUTATING_DEDUP_TOOLS exact-set pattern.
 */
const EXPECTED_SCAN_DOMAIN_TOOLS = new Set([
	'check_spf',
	'check_dmarc',
	'check_dkim',
	'check_dnssec',
	'check_ssl',
	'check_mta_sts',
	'check_ns',
	'check_caa',
	'check_bimi',
	'check_tlsrpt',
	'check_http_security',
	'check_dane',
	'check_dane_https',
	'check_svcb_https',
	'check_mx',
	'check_subdomailing',
	'check_dnskey_strength',
	'check_ptr',
]);

describe('tool-schemas metadata', () => {
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

	it('the scanIncluded tool set exactly matches the expected scan_domain orchestration set', () => {
		// scanIncluded is the source of truth; EXPECTED_SCAN_DOMAIN_TOOLS is the
		// acknowledgment tripwire. Asserting exact equality pins membership in both
		// directions, replacing the old hand-maintained scan/non-scan partition.
		const scanIncludedNames = TOOLS.filter((t) => t.scanIncluded).map((t) => t.name);
		expect(scanIncludedNames.sort()).toEqual([...EXPECTED_SCAN_DOMAIN_TOOLS].sort());
	});

	it('all scoring check tools have a tier (except check_resolver_consistency)', () => {
		const checkTools = TOOLS.filter(
			(t) => t.name.startsWith('check_') && t.name !== 'check_resolver_consistency' && t.group !== 'intelligence',
		);
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

});
