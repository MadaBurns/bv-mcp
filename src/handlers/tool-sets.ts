// SPDX-License-Identifier: BUSL-1.1

// Tool-name sets derived from TOOL_DEFS plus the NXDOMAIN gate, split out of `handlers/tools.ts`.

import type { CheckCategory } from '../lib/scoring';
import { TOOLS } from '../schemas/tool-definitions';
import type { ToolName } from '../schemas/tool-definitions';

export const DOMAIN_REQUIRED_TOOLS = new Set(
	TOOLS.filter((tool) => Array.isArray(tool.inputSchema.required) && tool.inputSchema.required.includes('domain')).map((tool) => tool.name),
);

/**
 * Internal `/tools/batch` is a fan-out read door, never a generic mutation
 * executor. Derive its allowlist from the tool-definition SSOT so a newly added
 * write/destructive tool is denied by default until it is deliberately exposed
 * through a separately idempotent, quota-aware contract.
 */
export const INTERNAL_BATCH_SAFE_TOOLS = new Set(
	TOOLS.filter(
		(tool) =>
			tool.annotations?.readOnlyHint === true && Array.isArray(tool.inputSchema.required) && tool.inputSchema.required.includes('domain'),
	).map((tool) => tool.name),
);

/**
 * Tools eligible for the request-dedup window (#363 item 3): mutating
 * (`readOnlyHint === false`) AND non-destructive (`destructiveHint === false`).
 * That's the 8 `*_start` / `register_*` creators — the ones a client retry can
 * DUPLICATE. The naturally-idempotent `delete_brand_audit_watch` (destructive)
 * is excluded. Derived from annotations (the SSOT), so a future mutating tool
 * auto-joins — guarded by an exact-set test so that's a conscious decision.
 */
export const MUTATING_DEDUP_TOOLS = new Set(
	TOOLS.filter((tool) => tool.annotations?.readOnlyHint === false && tool.annotations?.destructiveHint === false).map((tool) => tool.name),
);

/**
 * Tool names handled by the explicit dispatcher rather than TOOL_REGISTRY.
 * Kept as an executable dispatch manifest so the characterization suite detects
 * a newly declared tool that is listed but has no resolution path.
 */
export const DIRECT_DISPATCH_TOOLS: Set<string> = new Set<ToolName>([
	'scan_domain',
	'batch_scan',
	'batch_scan_start',
	'batch_scan_status',
	'batch_scan_findings',
	'compare_domains',
	'compare_baseline',
	'generate',
	'get_domain_rank',
	'get_benchmark',
	'get_provider_insights',
	'assess_spoofability',
	'check_resolver_consistency',
	'explain_finding',
	'validate_fix',
	'map_supply_chain',
	'analyze_drift',
	'resolve_spf_chain',
	'discover_subdomains',
	'map_compliance',
	'sge_quickscan',
	'map_registrar_products',
	'prioritize_portfolio_leads',
	'simulate_attack_paths',
	'query_signins',
	'query_ual',
	'get_ca_policies',
	'assess_coverage',
]);

export function toolRequiresDomain(name: string): boolean {
	return DOMAIN_REQUIRED_TOOLS.has(name);
}

/**
 * #1128 — `TOOL_REGISTRY` tools that abstain on a non-resolving (NXDOMAIN) apex, keyed
 * to the category their result reports. `scan_domain` never runs these on an NXDOMAIN
 * (`buildNonResolvingResult`); called individually they used to score the absence of
 * every record as a measured negative (critical "No SPF record found") or a clean 100
 * (`check_subdomain_takeover`). The gate is applied ONCE at the dispatch boundary in `handleToolsCall` (`tools.ts`),
 * using the same predicate as `scan_domain` (`lib/apex-resolution.ts`).
 *
 * Deliberately NOT gated: tools whose subject is the non-existence itself or whose
 * input is not the apex's own posture — `check_lookalikes` / `check_shadow_domains`
 * (NXDOMAIN permutations/siblings ARE the measurement), `rdap_lookup` (registration
 * data exists independently of DNS delegation), `check_dbl` / `check_rbl` /
 * `check_realtime_threat_feed` / `check_fast_flux` (reputation of the NAME, listed or
 * not, whether or not it currently resolves), and the rest of the registry, which #1128
 * observed already abstaining or staying neutral on an NXDOMAIN. `check_mta_sts`,
 * `check_bimi` and `check_tlsrpt` were NOT in that group — each emits an absence
 * finding on an NXDOMAIN — and are gated since SQ-268. Tools outside the registry are
 * not on this path: `check_resolver_consistency` is not gated, and the composites
 * (`assess_spoofability`, `simulate_attack_paths`) apply the same predicate themselves.
 */
export const NXDOMAIN_GATED_TOOLS: Readonly<Record<string, CheckCategory>> = {
	check_spf: 'spf',
	check_dmarc: 'dmarc',
	check_mx: 'mx',
	check_ns: 'ns',
	check_dnssec: 'dnssec',
	check_dnssec_chain: 'dnssec_chain' as CheckCategory,
	check_caa: 'caa',
	check_dkim: 'dkim',
	check_zone_hygiene: 'zone_hygiene',
	check_subdomain_takeover: 'subdomain_takeover',
	check_ssl: 'ssl',
	check_mta_sts: 'mta_sts',
	check_bimi: 'bimi',
	check_tlsrpt: 'tlsrpt',
};

/**
 * The category to abstain under when `name` is NXDOMAIN-gated for these `args`, else
 * `undefined`. `check_subdomain_takeover` with an explicit `subdomains` list is exempt:
 * full FQDNs there are swept as given and need not sit under the (non-existent) apex.
 */
export function nxdomainGateCategory(name: string, args: Record<string, unknown>): CheckCategory | undefined {
	if (name === 'check_subdomain_takeover' && Array.isArray(args.subdomains) && args.subdomains.length > 0) return undefined;
	return Object.hasOwn(NXDOMAIN_GATED_TOOLS, name) ? NXDOMAIN_GATED_TOOLS[name] : undefined;
}
