// SPDX-License-Identifier: BUSL-1.1

/**
 * MCP Tool schema definitions for Blackveil DNS.
 * Contains all tool metadata (names, descriptions, input schemas)
 * used by the tools/list MCP method.
 *
 * Separated from dispatch logic in tools.ts for clarity.
 */

/** MCP Tool definition */
export interface McpTool {
	name: string;
	description: string;
	inputSchema: {
		type: 'object';
		properties: Record<string, unknown>;
		required: string[];
	};
}

/** Shared format property for output verbosity control */
const FORMAT_PROPERTY = {
	format: {
		type: 'string',
		enum: ['full', 'compact'],
		description: 'Output detail level. Auto-detected from client type when omitted.',
	},
} as const;

/** Domain-only input schema shared by most tools */
export const DOMAIN_INPUT_SCHEMA = {
	type: 'object' as const,
	properties: {
		domain: {
			type: 'string',
			description: 'The domain name to check (e.g., example.com)',
		},
		...FORMAT_PROPERTY,
	},
	required: ['domain'],
};

/** All MCP tool definitions */
export const TOOLS: McpTool[] = [
	{
		name: 'check_mx',
		description: 'Validate MX records, priority ordering, and email provider detection.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_spf',
		description: 'Validate SPF records for syntax, policy strictness, lookup limits, and trust surface exposure.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_dmarc',
		description: 'Validate DMARC policy enforcement, reporting configuration, alignment, and subdomain policy.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_dkim',
		description: 'Probe DKIM selectors across major providers, validate key strength and tag configuration.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'The domain name to check (e.g., example.com)',
				},
				selector: {
					type: 'string',
					description: 'Specific DKIM selector to check. If omitted, common selectors are probed.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
	},
	{
		name: 'check_dnssec',
		description: 'Verify DNSSEC validation and DNSKEY/DS record presence for DNS tamper protection.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_ssl',
		description: 'Verify SSL/TLS certificate availability, expiry, and HTTPS configuration.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_mta_sts',
		description: 'Validate MTA-STS policy for SMTP transport encryption enforcement.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_ns',
		description: 'Analyze nameserver delegation, provider diversity, and infrastructure resilience.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_caa',
		description: 'Check which Certificate Authorities are authorized to issue certificates for a domain.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_bimi',
		description: 'Validate BIMI record, logo URL format, and VMC authority evidence.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_tlsrpt',
		description: 'Validate TLS-RPT records for SMTP TLS failure reporting.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_http_security',
		description: 'Audit HTTP security headers (CSP, X-Frame-Options, COOP, CORP, Permissions-Policy, Referrer-Policy).',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_dane',
		description: 'Verify DANE/TLSA certificate pinning for mail servers and HTTPS endpoints.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_lookalikes',
		description: 'Detect registered lookalike/typosquat domains with active infrastructure. Standalone, not in scan_domain.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'scan_domain',
		description:
			'Comprehensive DNS and email security audit. Returns score (0-100), grade, maturity stage, and prioritized findings. Start here.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'The domain name to check (e.g., example.com)',
				},
				profile: {
					type: 'string',
					enum: ['auto', 'mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal'],
					description: 'Scoring profile. "auto" (default) detects from results. Explicit values override detection.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
	},
	{
		name: 'compare_baseline',
		description: 'Compare domain security against a policy baseline. Returns pass/fail with specific violations.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'The domain to scan and compare.',
				},
				...FORMAT_PROPERTY,
				baseline: {
					type: 'object',
					description: 'Policy baseline with minimum requirements.',
					properties: {
						grade: {
							type: 'string',
							description: 'Minimum grade (e.g., "B+").',
						},
						score: {
							type: 'number',
							description: 'Minimum overall score (0-100).',
						},
						require_dmarc_enforce: {
							type: 'boolean',
							description: 'Require DMARC enforcement.',
						},
						require_spf: {
							type: 'boolean',
							description: 'Require valid SPF record.',
						},
						require_dkim: {
							type: 'boolean',
							description: 'Require DKIM key.',
						},
						require_dnssec: {
							type: 'boolean',
							description: 'Require DNSSEC validation.',
						},
						require_mta_sts: {
							type: 'boolean',
							description: 'Require MTA-STS policy.',
						},
						require_caa: {
							type: 'boolean',
							description: 'Require CAA records.',
						},
						max_critical_findings: {
							type: 'number',
							description: 'Max critical findings (default: 0).',
						},
						max_high_findings: {
							type: 'number',
							description: 'Max high findings.',
						},
					},
				},
			},
			required: ['domain', 'baseline'],
		},
	},
	{
		name: 'check_shadow_domains',
		description: 'Discover alternate-TLD variants with spoofable email auth gaps. Standalone, not in scan_domain.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_txt_hygiene',
		description: 'Audit TXT records for stale verifications, SaaS exposure, and cross-domain trust delegations.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_mx_reputation',
		description: 'Check mail server blocklist status (Spamhaus, SpamCop, Barracuda) and reverse DNS consistency.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_srv',
		description: 'Probe SRV records to map DNS-visible service footprint and flag insecure protocols.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_zone_hygiene',
		description: 'Audit SOA serial propagation and detect sensitive subdomains exposed in public DNS.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'generate_fix_plan',
		description: 'Generate a prioritized remediation plan with ordered action items, effort estimates, and dependencies.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'generate_spf_record',
		description: 'Generate a corrected SPF TXT record based on detected providers and current issues.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'The domain name (e.g., example.com)',
				},
				include_providers: {
					type: 'array',
					items: { type: 'string' },
					description: 'Email providers to include (e.g., ["google", "sendgrid"]). Known names are auto-mapped to include domains.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
	},
	{
		name: 'generate_dmarc_record',
		description: 'Generate a DMARC record fixing detected issues. Provider-aware with configurable policy and reporting.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'The domain name (e.g., example.com)',
				},
				policy: {
					type: 'string',
					enum: ['none', 'quarantine', 'reject'],
					description: 'DMARC policy (default: "reject").',
				},
				rua_email: {
					type: 'string',
					description: 'Aggregate report email address. Defaults to dmarc-reports@{domain}.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
	},
	{
		name: 'generate_dkim_config',
		description: 'Generate provider-specific DKIM setup instructions and DNS record template.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'The domain name (e.g., example.com)',
				},
				provider: {
					type: 'string',
					description: 'Email provider (e.g., "google", "microsoft"). Omit for generic instructions.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
	},
	{
		name: 'generate_mta_sts_policy',
		description: 'Generate MTA-STS TXT record and policy file content for SMTP transport encryption.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'The domain name (e.g., example.com)',
				},
				mx_hosts: {
					type: 'array',
					items: { type: 'string' },
					description: 'MX hostnames for the policy. If omitted, detected from DNS.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['domain'],
		},
	},
	{
		name: 'explain_finding',
		description: 'Plain-language explanation of a finding with impact, consequences, and remediation steps.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				checkType: {
					type: 'string',
					description: "Check type (e.g., 'SPF', 'DMARC', 'DKIM', 'SSL')",
				},
				status: {
					type: 'string',
					enum: ['pass', 'fail', 'warning', 'critical', 'high', 'medium', 'low', 'info'],
					description: 'Finding severity or check status.',
				},
				details: {
					type: 'string',
					description: 'Optional details from the check result.',
				},
				...FORMAT_PROPERTY,
			},
			required: ['checkType', 'status'],
		},
	},
];
