// SPDX-License-Identifier: BUSL-1.1

import { z } from 'zod';
import {
	BaseDomainArgs,
	ScanDomainArgs,
	BatchScanArgs,
	CompareDomainsArgs,
	CheckDkimArgs,
	CheckResolverConsistencyArgs,
	GenerateSpfArgs,
	GenerateDmarcArgs,
	GenerateDkimConfigArgs,
	GenerateMtaStsArgs,
	ExplainFindingArgs,
	CompareBaselineArgs,
	GetBenchmarkArgs,
	GetProviderInsightsArgs,
	ValidateFixArgs,
	MapSupplyChainArgs,
	AnalyzeDriftArgs,
	GenerateRolloutPlanArgs,
	TOOL_SCHEMA_MAP,
} from './tool-args';

export type ToolGroup = 'email_auth' | 'infrastructure' | 'brand_threats' | 'dns_hygiene' | 'intelligence' | 'remediation' | 'meta';
export type ToolTier = 'core' | 'protective' | 'hardening';

export interface McpTool {
	name: string;
	description: string;
	inputSchema: {
		type: string;
		properties: Record<string, unknown>;
		required?: string[];
		[key: string]: unknown;
	};
	annotations?: {
		title?: string;
		readOnlyHint?: boolean;
		destructiveHint?: boolean;
		idempotentHint?: boolean;
		openWorldHint?: boolean;
	};
	/** Functional group for client-side tool discoverability. Not used in dispatch. */
	group: ToolGroup;
	/** Scoring tier from the three-tier model. Absent for non-scoring tools (meta/intelligence/remediation). */
	tier?: ToolTier;
	/** True when this tool is included in the scan_domain parallel orchestration. */
	scanIncluded: boolean;
}

interface ToolDef {
	description: string;
	schema: z.ZodTypeAny;
	group: ToolGroup;
	tier?: ToolTier;
	scanIncluded: boolean;
}

/** DNS/security acronyms that should be uppercased in human-readable tool titles. */
const KNOWN_ACRONYMS = new Set(['mx', 'spf', 'dmarc', 'dkim', 'dnssec', 'ssl', 'mta', 'sts', 'ns', 'caa', 'bimi', 'tlsrpt', 'http', 'https', 'dane', 'svcb', 'srv', 'txt', 'doh', 'rpm', 'dbl']);

/** Convert a snake_case tool name to a human-readable title. e.g. "check_mta_sts" → "Check MTA STS" */
function toolNameToTitle(name: string): string {
	return name
		.split('_')
		.map((word) => (KNOWN_ACRONYMS.has(word) ? word.toUpperCase() : word.charAt(0).toUpperCase() + word.slice(1)))
		.join(' ');
}

/** Convert a Zod schema to a JSON Schema object suitable for MCP inputSchema. */
function toInputSchema(schema: z.ZodTypeAny): McpTool['inputSchema'] {
	const jsonSchema = z.toJSONSchema(schema) as Record<string, unknown>;
	delete jsonSchema.$schema;
	// Clean up additionalProperties: {} (equivalent to not having it, but cleaner)
	if (
		jsonSchema.additionalProperties !== undefined &&
		typeof jsonSchema.additionalProperties === 'object' &&
		jsonSchema.additionalProperties !== null &&
		Object.keys(jsonSchema.additionalProperties).length === 0
	) {
		delete jsonSchema.additionalProperties;
	}
	return jsonSchema as McpTool['inputSchema'];
}

/** All 45 MCP tool definitions. */
const TOOL_DEFS: Record<string, ToolDef> = {
	check_mx: {
		description: 'Look up MX records for a domain. Shows mail servers, email provider detection, and validates configuration.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'protective',
		scanIncluded: true,
	},
	check_spf: {
		description: 'Look up and validate SPF record for a domain. Shows authorized senders, syntax issues, and trust surface.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	check_dmarc: {
		description: 'Look up and validate DMARC record for a domain. Shows policy enforcement, alignment mode, and reporting config.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	check_dkim: {
		description: 'Look up DKIM records for a domain. Probes common selectors and validates key strength and algorithm.',
		schema: CheckDkimArgs,
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	check_dnssec: {
		description: 'Check DNSSEC status for a domain. Verifies DNSKEY/DS records and validation chain.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'core',
		scanIncluded: true,
	},
	check_ssl: {
		description: 'Check SSL/TLS certificate for a domain. Shows issuer, expiry, protocol versions, and HTTPS configuration.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'core',
		scanIncluded: true,
	},
	check_mta_sts: {
		description: 'Validate MTA-STS SMTP encryption policy.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'protective',
		scanIncluded: true,
	},
	check_ns: {
		description: 'Look up NS (nameserver) records for a domain. Shows DNS provider, delegation, and redundancy.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	check_caa: {
		description: 'Look up CAA records for a domain. Shows which Certificate Authorities are authorized to issue certificates.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	check_bimi: {
		description: 'Validate BIMI record and VMC evidence.',
		schema: BaseDomainArgs,
		group: 'brand_threats',
		tier: 'hardening',
		scanIncluded: true,
	},
	check_tlsrpt: {
		description: 'Validate TLS-RPT SMTP failure reporting.',
		schema: BaseDomainArgs,
		group: 'brand_threats',
		tier: 'hardening',
		scanIncluded: true,
	},
	check_http_security: {
		description: 'Audit HTTP security headers (CSP, COOP, etc.).',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	check_dane: {
		description: 'Verify DANE/TLSA certificate pinning.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: true,
	},
	check_dane_https: {
		description: 'Verify DANE certificate pinning for HTTPS via TLSA records at _443._tcp.{domain}.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	check_svcb_https: {
		description: 'Validate HTTPS/SVCB records (RFC 9460) for modern transport capability advertisement.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	check_lookalikes: {
		description: 'Detect active typosquat/lookalike domains. Standalone.',
		schema: BaseDomainArgs,
		group: 'brand_threats',
		tier: 'protective',
		scanIncluded: false,
	},
	check_subdomailing: {
		description: 'Detect SubdoMailing risk by analyzing SPF include chain for takeover-vulnerable domains.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'protective',
		scanIncluded: true,
	},
	scan_domain: {
		description:
			'Look up any domain to get a full DNS and email security audit. Use this whenever a user mentions a domain name, asks to check/scan/lookup/analyze a domain, or wants to know about a domain\'s security posture. Returns score, grade, maturity stage, and prioritized findings. Start here for any domain-related question.',
		schema: ScanDomainArgs,
		group: 'meta',
		scanIncluded: false,
	},
	batch_scan: {
		description: 'Scan up to 10 domains at once. Returns score, grade, and finding counts per domain.',
		schema: BatchScanArgs,
		group: 'meta',
		scanIncluded: false,
	},
	compare_domains: {
		description: 'Side-by-side security comparison of 2–5 domains. Shows scores, category gaps, and unique weaknesses.',
		schema: CompareDomainsArgs,
		group: 'meta',
		scanIncluded: false,
	},
	compare_baseline: {
		description: 'Compare domain security against a policy baseline.',
		schema: CompareBaselineArgs,
		group: 'meta',
		scanIncluded: false,
	},
	check_shadow_domains: {
		description: 'Find TLD variants with email auth gaps. Standalone.',
		schema: BaseDomainArgs,
		group: 'brand_threats',
		tier: 'protective',
		scanIncluded: false,
	},
	check_txt_hygiene: {
		description: 'Audit TXT records for stale entries and SaaS exposure.',
		schema: BaseDomainArgs,
		group: 'dns_hygiene',
		tier: 'hardening',
		scanIncluded: false,
	},
	check_mx_reputation: {
		description: 'Check MX blocklist status and reverse DNS.',
		schema: BaseDomainArgs,
		group: 'email_auth',
		tier: 'hardening',
		scanIncluded: false,
	},
	check_srv: {
		description: 'Probe SRV records for service footprint.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: false,
	},
	check_zone_hygiene: {
		description: 'Audit SOA propagation and sensitive subdomains.',
		schema: BaseDomainArgs,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: false,
	},
	generate_fix_plan: {
		description: 'Generate prioritized remediation plan with effort estimates.',
		schema: BaseDomainArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	generate_spf_record: {
		description: 'Generate corrected SPF record from detected providers.',
		schema: GenerateSpfArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	generate_dmarc_record: {
		description: 'Generate DMARC record with configurable policy.',
		schema: GenerateDmarcArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	generate_dkim_config: {
		description: 'Generate DKIM setup instructions and DNS record.',
		schema: GenerateDkimConfigArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	generate_mta_sts_policy: {
		description: 'Generate MTA-STS record and policy file.',
		schema: GenerateMtaStsArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	get_benchmark: {
		description: 'Get score benchmarks: percentiles, mean, top failures.',
		schema: GetBenchmarkArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	get_provider_insights: {
		description: 'Get provider cohort benchmarks and common issues.',
		schema: GetProviderInsightsArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	assess_spoofability: {
		description: 'Composite email spoofability score (0-100).',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_resolver_consistency: {
		description: 'Check DNS consistency across 4 public resolvers.',
		schema: CheckResolverConsistencyArgs,
		group: 'infrastructure',
		scanIncluded: false,
	},
	explain_finding: {
		description: 'Explain a finding with impact and remediation.',
		schema: ExplainFindingArgs,
		group: 'meta',
		scanIncluded: false,
	},
	map_supply_chain: {
		description: 'Map third-party service dependencies from DNS records. Correlates SPF, NS, TXT verifications, SRV services, and CAA to show who can send as you, control your DNS, and what services are integrated.',
		schema: MapSupplyChainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	analyze_drift: {
		description: 'Compare current security posture against a previous baseline. Shows what improved, regressed, or changed.',
		schema: AnalyzeDriftArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	validate_fix: {
		description: 'Re-check a specific control after applying a fix. Confirms whether the finding is resolved.',
		schema: ValidateFixArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	generate_rollout_plan: {
		description: 'Generate a phased DMARC enforcement timeline with exact DNS records per phase.',
		schema: GenerateRolloutPlanArgs,
		group: 'remediation',
		scanIncluded: false,
	},
	resolve_spf_chain: {
		description: 'Trace the full SPF include chain for a domain. Recursively resolves all includes, shows lookup count, tree depth, and flags circular includes or exceeding the 10-lookup limit.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	discover_subdomains: {
		description: 'Find subdomains of a domain using Certificate Transparency logs. Reveals shadow IT, forgotten services, and unauthorized certificate issuance.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	map_compliance: {
		description: 'Map scan findings to compliance frameworks: NIST 800-177, PCI DSS 4.0, SOC 2, CIS Controls. Shows pass/fail/partial status per control.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	simulate_attack_paths: {
		description: 'Analyze current DNS posture and enumerate specific attack paths an adversary could exploit, with severity, feasibility, steps, and mitigations.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_dbl: {
		description: 'Check domain reputation against DNS-based Domain Block Lists (Spamhaus DBL, URIBL, SURBL). Returns listing status with decoded return codes.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
	check_rbl: {
		description:
			'Check MX server IP reputation against 8 DNS-based Real-time Blocklists (Spamhaus ZEN, SpamCop, UCEProtect, Mailspike, Barracuda, PSBL, SORBS). Resolves MX hosts to IPs first.',
		schema: BaseDomainArgs,
		group: 'intelligence',
		scanIncluded: false,
	},
};

export const TOOLS: McpTool[] = Object.entries(TOOL_DEFS).map(([name, def]) => ({
	name,
	description: def.description,
	inputSchema: toInputSchema(def.schema),
	annotations: {
		title: toolNameToTitle(name),
		readOnlyHint: true,
		destructiveHint: false,
		idempotentHint: true,
		openWorldHint: true,
	},
	group: def.group,
	...(def.tier !== undefined && { tier: def.tier }),
	scanIncluded: def.scanIncluded,
}));

export { TOOL_SCHEMA_MAP };
