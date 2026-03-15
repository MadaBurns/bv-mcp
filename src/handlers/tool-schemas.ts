// SPDX-License-Identifier: MIT

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

/** Domain-only input schema shared by most tools */
export const DOMAIN_INPUT_SCHEMA = {
	type: 'object' as const,
	properties: {
		domain: {
			type: 'string',
			description: 'The domain name to check (e.g., example.com)',
		},
	},
	required: ['domain'],
};

/** All MCP tool definitions */
export const TOOLS: McpTool[] = [
	{
		name: 'check_mx',
		description:
			'Check MX (Mail Exchange) records for a domain. Validates presence and quality of MX records, assesses outbound email usage.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_spf',
		description:
			'Check SPF (Sender Policy Framework) records for a domain. Validates SPF TXT records for proper syntax, mechanisms, and policy.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_dmarc',
		description:
			'Check DMARC (Domain-based Message Authentication) records for a domain. Validates _dmarc TXT records for policy configuration.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_dkim',
		description: 'Check DKIM (DomainKeys Identified Mail) records for a domain. Probes common selectors for DKIM key records.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'The domain name to check (e.g., example.com)',
				},
				selector: {
					type: 'string',
					description: "Optional: specific DKIM selector to check (e.g., 'google', 'selector1'). If omitted, common selectors are probed.",
				},
			},
			required: ['domain'],
		},
	},
	{
		name: 'check_dnssec',
		description:
			'Check DNSSEC (DNS Security Extensions) status for a domain. Verifies if DNS responses are cryptographically signed and validated.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_ssl',
		description: 'Check SSL/TLS certificate configuration for a domain. Validates certificate status and configuration.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_mta_sts',
		description: 'Check MTA-STS (Mail Transfer Agent Strict Transport Security) for a domain. Validates _mta-sts TXT records and policy.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_ns',
		description: 'Check name server (NS) configuration for a domain. Analyzes NS records for redundancy, diversity, and proper delegation.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_caa',
		description:
			'Check CAA (Certificate Authority Authorization) records for a domain. Validates which CAs are authorized to issue certificates.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_bimi',
		description:
			'Check BIMI (Brand Indicators for Message Identification) records for a domain. Validates logo and authority evidence configuration for email client brand display.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_tlsrpt',
		description:
			'Check TLS-RPT (SMTP TLS Reporting) records for a domain. Validates reporting configuration for SMTP TLS failures (RFC 8460).',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_lookalikes',
		description:
			'Detect registered lookalike/typosquat domains with DNS or mail infrastructure. Generates domain permutations and checks for active registrations. Standalone check — not included in scan_domain due to query volume.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'scan_domain',
		description:
			'Run a comprehensive DNS security scan on a domain. Executes all checks (SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, Subdomain Takeover) in parallel and returns an overall security score and grade.',
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
					description:
						'Scoring profile to apply. "auto" (default) detects the profile from scan results. Explicit values override detection and change scoring weights.',
				},
			},
			required: ['domain'],
		},
	},
	{
		name: 'compare_baseline',
		description:
			'Compare a domain scan against a policy baseline. Returns violations where the domain falls below the specified minimums. Useful for MSPs and security teams enforcing org-level standards.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				domain: {
					type: 'string',
					description: 'The domain to scan and compare.',
				},
				baseline: {
					type: 'object',
					description: 'Policy baseline. Keys are category names or "grade"/"score". Values are minimums.',
					properties: {
						grade: {
							type: 'string',
							description: 'Minimum acceptable grade (e.g., "B+"). Violation if scan grade is worse.',
						},
						score: {
							type: 'number',
							description: 'Minimum acceptable overall score (0-100).',
						},
						require_dmarc_enforce: {
							type: 'boolean',
							description: 'Require DMARC p=quarantine or p=reject (not p=none).',
						},
						require_spf: {
							type: 'boolean',
							description: 'Require a valid SPF record.',
						},
						require_dkim: {
							type: 'boolean',
							description: 'Require at least one DKIM key.',
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
							description: 'Maximum allowed critical-severity findings (default: 0).',
						},
						max_high_findings: {
							type: 'number',
							description: 'Maximum allowed high-severity findings.',
						},
					},
				},
			},
			required: ['domain', 'baseline'],
		},
	},
	{
		name: 'check_shadow_domains',
		description:
			'Discover registered alternate-TLD variants of a domain with active DNS/mail infrastructure and assess email spoofing risk. Checks whether shadow domains (e.g., .org.nz, .co.nz, .com variants) have proper email authentication (SPF, DMARC) or are fully spoofable. Standalone check — not included in scan_domain due to query volume.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_txt_hygiene',
		description:
			"Audit all TXT records on a domain for governance and security concerns: stale verification records, unexpected foreign service registrations (e.g., Yandex on non-Russian domains), excessive record accumulation, duplicate verifications, and cross-domain trust delegations. Maps the organisation's verified platform exposure from public DNS.",
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'explain_finding',
		description: 'Get a plain-language explanation of a DNS security finding, including potential impact, adverse consequences, and recommended remediation steps.',
		inputSchema: {
			type: 'object' as const,
			properties: {
				checkType: {
					type: 'string',
					description: "The check type (e.g. 'SPF', 'DMARC', 'DKIM', 'DNSSEC', 'SSL', 'MTA_STS')",
				},
				status: {
					type: 'string',
					enum: ['pass', 'fail', 'warning', 'critical', 'high', 'medium', 'low', 'info'],
					description: 'The check status or finding severity (e.g., pass, fail, warning, critical, high, medium, low, info)',
				},
				details: {
					type: 'string',
					description: 'Optional details from the check result',
				},
			},
			required: ['checkType', 'status'],
		},
	},
];
