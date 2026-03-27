// SPDX-License-Identifier: BUSL-1.1

/**
 * MCP Tool schema definitions for Blackveil DNS.
 * Contains all tool metadata (names, descriptions, input schemas)
 * used by the tools/list MCP method.
 *
 * Separated from dispatch logic in tools.ts for clarity.
 */

/** Functional group describing a tool's primary concern. Used for client-side discoverability. */
export type ToolGroup = 'email_auth' | 'infrastructure' | 'brand_threats' | 'dns_hygiene' | 'intelligence' | 'remediation' | 'meta';

/** Scoring tier from the three-tier model. Only present on tools that map to a scoring CheckCategory. */
export type ToolTier = 'core' | 'protective' | 'hardening';

/** MCP Tool definition */
export interface McpTool {
	name: string;
	description: string;
	inputSchema: {
		type: 'object';
		properties: Record<string, unknown>;
		required: string[];
	};
	/** Functional group for client-side tool discoverability. Not used in dispatch. */
	group: ToolGroup;
	/** Scoring tier from the three-tier model. Absent for non-scoring tools (meta/intelligence/remediation). */
	tier?: ToolTier;
	/** True when this tool is included in the scan_domain parallel orchestration. */
	scanIncluded: boolean;
}

/** Shared format property for output verbosity control */
const FORMAT_PROPERTY = {
	format: {
		type: 'string',
		enum: ['full', 'compact'],
		description: 'Output verbosity. Auto-detected if omitted.',
	},
} as const;

/** Domain-only input schema shared by most tools */
export const DOMAIN_INPUT_SCHEMA = {
	type: 'object' as const,
	properties: {
		domain: {
			type: 'string',
			description: 'Domain to check (e.g., example.com)',
		},
		...FORMAT_PROPERTY,
	},
	required: ['domain'],
};

/** All MCP tool definitions */
export const TOOLS: McpTool[] = [
	{
		name: 'check_mx',
		description: 'Validate MX records and email provider detection.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'email_auth',
		tier: 'protective',
		scanIncluded: true,
	},
	{
		name: 'check_spf',
		description: 'Validate SPF syntax, policy, and trust surface.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	{
		name: 'check_dmarc',
		description: 'Validate DMARC policy, alignment, and reporting.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	{
		name: 'check_dkim',
		description: 'Probe DKIM selectors and validate key strength.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'Domain to check (e.g., example.com)',
				},
				selector: {
					type: 'string',
					description: 'DKIM selector. Omit to probe common ones.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
		group: 'email_auth',
		tier: 'core',
		scanIncluded: true,
	},
	{
		name: 'check_dnssec',
		description: 'Verify DNSSEC validation and DNSKEY/DS records.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'infrastructure',
		tier: 'core',
		scanIncluded: true,
	},
	{
		name: 'check_ssl',
		description: 'Verify SSL/TLS certificate and HTTPS config.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'infrastructure',
		tier: 'core',
		scanIncluded: true,
	},
	{
		name: 'check_mta_sts',
		description: 'Validate MTA-STS SMTP encryption policy.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'email_auth',
		tier: 'protective',
		scanIncluded: true,
	},
	{
		name: 'check_ns',
		description: 'Analyze NS delegation and provider diversity.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	{
		name: 'check_caa',
		description: 'Check authorized Certificate Authorities via CAA.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	{
		name: 'check_bimi',
		description: 'Validate BIMI record and VMC evidence.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'brand_threats',
		tier: 'hardening',
		scanIncluded: true,
	},
	{
		name: 'check_tlsrpt',
		description: 'Validate TLS-RPT SMTP failure reporting.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'brand_threats',
		tier: 'hardening',
		scanIncluded: true,
	},
	{
		name: 'check_http_security',
		description: 'Audit HTTP security headers (CSP, COOP, etc.).',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	{
		name: 'check_dane',
		description: 'Verify DANE/TLSA certificate pinning.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: true,
	},
	{
		name: 'check_dane_https',
		description: 'Verify DANE certificate pinning for HTTPS via TLSA records at _443._tcp.{domain}.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	{
		name: 'check_svcb_https',
		description: 'Validate HTTPS/SVCB records (RFC 9460) for modern transport capability advertisement.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'infrastructure',
		tier: 'protective',
		scanIncluded: true,
	},
	{
		name: 'check_lookalikes',
		description: 'Detect active typosquat/lookalike domains. Standalone.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'brand_threats',
		tier: 'protective',
		scanIncluded: false,
	},
	{
		name: 'scan_domain',
		description: 'Full DNS and email security audit. Score, grade, maturity, findings. Start here.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'Domain to check (e.g., example.com)',
				},
				profile: {
					type: 'string',
					enum: ['auto', 'mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal'],
					description: 'Scoring profile. Default "auto" detects.',
				},
				force_refresh: {
					type: 'boolean',
					description: 'Bypass cache and run a fresh scan. Useful after DNS changes.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
		group: 'meta',
		scanIncluded: false,
	},
	{
		name: 'compare_baseline',
		description: 'Compare domain security against a policy baseline.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'Domain to scan and compare.',
				},
				...FORMAT_PROPERTY,
				baseline: {
					type: 'object',
					description: 'Policy baseline requirements.',
					properties: {
						grade: {
							type: 'string',
							description: 'Min grade (e.g., "B+").',
						},
						score: {
							type: 'number',
							description: 'Min score (0-100).',
						},
						require_dmarc_enforce: {
							type: 'boolean',
							description: 'Require DMARC enforce.',
						},
						require_spf: {
							type: 'boolean',
							description: 'Require SPF.',
						},
						require_dkim: {
							type: 'boolean',
							description: 'Require DKIM.',
						},
						require_dnssec: {
							type: 'boolean',
							description: 'Require DNSSEC.',
						},
						require_mta_sts: {
							type: 'boolean',
							description: 'Require MTA-STS.',
						},
						require_caa: {
							type: 'boolean',
							description: 'Require CAA.',
						},
						max_critical_findings: {
							type: 'number',
							description: 'Max critical findings (default 0).',
						},
						max_high_findings: {
							type: 'number',
							description: 'Max high findings allowed.',
						},
					},
				},
			},
			required: ['domain', 'baseline'],
		},
		group: 'meta',
		scanIncluded: false,
	},
	{
		name: 'check_shadow_domains',
		description: 'Find TLD variants with email auth gaps. Standalone.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'brand_threats',
		tier: 'protective',
		scanIncluded: false,
	},
	{
		name: 'check_txt_hygiene',
		description: 'Audit TXT records for stale entries and SaaS exposure.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'dns_hygiene',
		tier: 'hardening',
		scanIncluded: false,
	},
	{
		name: 'check_mx_reputation',
		description: 'Check MX blocklist status and reverse DNS.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'email_auth',
		tier: 'hardening',
		scanIncluded: false,
	},
	{
		name: 'check_srv',
		description: 'Probe SRV records for service footprint.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: false,
	},
	{
		name: 'check_zone_hygiene',
		description: 'Audit SOA propagation and sensitive subdomains.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'infrastructure',
		tier: 'hardening',
		scanIncluded: false,
	},
	{
		name: 'generate_fix_plan',
		description: 'Generate prioritized remediation plan with effort estimates.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'remediation',
		scanIncluded: false,
	},
	{
		name: 'generate_spf_record',
		description: 'Generate corrected SPF record from detected providers.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'Domain (e.g., example.com)',
				},
				include_providers: {
					type: 'array',
					items: { type: 'string' },
					description: 'Providers to include (e.g., ["google"]).',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
		group: 'remediation',
		scanIncluded: false,
	},
	{
		name: 'generate_dmarc_record',
		description: 'Generate DMARC record with configurable policy.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'Domain (e.g., example.com)',
				},
				policy: {
					type: 'string',
					enum: ['none', 'quarantine', 'reject'],
					description: 'Policy (default "reject").',
				},
				rua_email: {
					type: 'string',
					description: 'Report email. Default: dmarc-reports@{domain}.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
		group: 'remediation',
		scanIncluded: false,
	},
	{
		name: 'generate_dkim_config',
		description: 'Generate DKIM setup instructions and DNS record.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'Domain (e.g., example.com)',
				},
				provider: {
					type: 'string',
					description: 'Provider (e.g., "google"). Omit for generic.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
		group: 'remediation',
		scanIncluded: false,
	},
	{
		name: 'generate_mta_sts_policy',
		description: 'Generate MTA-STS record and policy file.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'Domain (e.g., example.com)',
				},
				mx_hosts: {
					type: 'array',
					items: { type: 'string' },
					description: 'MX hosts. Omit to detect from DNS.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
		group: 'remediation',
		scanIncluded: false,
	},
	{
		name: 'get_benchmark',
		description: 'Get score benchmarks: percentiles, mean, top failures.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				profile: {
					type: 'string',
					enum: ['mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal'],
					description: 'Profile to benchmark (default "mail_enabled").',
				},
				...FORMAT_PROPERTY,
			},
			required: [],
		},
		group: 'intelligence',
		scanIncluded: false,
	},
	{
		name: 'get_provider_insights',
		description: 'Get provider cohort benchmarks and common issues.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				provider: {
					type: 'string',
					description: 'Provider (e.g., "google workspace").',
				},
				profile: {
					type: 'string',
					enum: ['mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal'],
					description: 'Profile (default "mail_enabled").',
				},
				...FORMAT_PROPERTY,
			},
			required: ['provider'],
		},
		group: 'intelligence',
		scanIncluded: false,
	},
	{
		name: 'assess_spoofability',
		description: 'Composite email spoofability score (0-100).',
		inputSchema: DOMAIN_INPUT_SCHEMA,
		group: 'intelligence',
		scanIncluded: false,
	},
	{
		name: 'check_resolver_consistency',
		description: 'Check DNS consistency across 4 public resolvers.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'Domain to check (e.g., example.com)',
				},
				record_type: {
					type: 'string',
					enum: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA'],
					description: 'Record type. Omit for A/AAAA/MX/TXT/NS.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
		group: 'infrastructure',
		scanIncluded: false,
	},
	{
		name: 'explain_finding',
		description: 'Explain a finding with impact and remediation.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				checkType: {
					type: 'string',
					description: "Check type (e.g., 'SPF', 'DMARC').",
				},
				status: {
					type: 'string',
					enum: ['pass', 'fail', 'warning', 'critical', 'high', 'medium', 'low', 'info'],
					description: 'Finding severity or status.',
				},
				details: {
					type: 'string',
					description: 'Additional detail from check result.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['checkType', 'status'],
		},
		group: 'meta',
		scanIncluded: false,
	},
];
