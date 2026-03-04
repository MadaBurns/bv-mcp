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
		name: 'scan_domain',
		description:
			'Run a comprehensive DNS security scan on a domain. Executes all checks (SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, NS, CAA, MX, Subdomain Takeover) in parallel and returns an overall security score and grade.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'explain_finding',
		description: 'Get a plain-language explanation of a DNS security finding and recommended remediation steps.',
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
