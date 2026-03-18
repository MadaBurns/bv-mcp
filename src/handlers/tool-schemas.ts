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
			'Validate mail exchange infrastructure and email routing configuration. Checks MX record presence, priority ordering, and provider detection to assess whether a domain can send and receive email reliably.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_spf',
		description:
			'Detect email spoofing risk from missing or misconfigured SPF records. Validates SPF TXT records for syntax, mechanism quality, lookup limits, policy strictness (-all vs ~all), and trust surface exposure from shared SaaS platforms.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_dmarc',
		description:
			'Assess domain protection against email impersonation and phishing. Validates DMARC policy enforcement level (none/quarantine/reject), reporting configuration, alignment modes, subdomain policy, and percentage coverage.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_dkim',
		description:
			'Verify email message integrity and sender authenticity via DKIM. Probes common selectors across major providers, validates key strength, and checks tag configuration.',
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
			'Check whether DNS responses are cryptographically signed and tamper-proof. Verifies DNSSEC validation, DNSKEY/DS record presence — protects against DNS cache poisoning and man-in-the-middle attacks.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_ssl',
		description:
			'Verify SSL/TLS certificate health and HTTPS configuration. Validates certificate availability, expiry, and configuration — essential for transport security and browser trust.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_mta_sts',
		description:
			'Check if email transport is protected against TLS downgrade attacks. Validates MTA-STS (RFC 8461) policy ensuring SMTP connections between mail servers are encrypted and cannot be intercepted.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_ns',
		description:
			'Evaluate DNS infrastructure resilience and redundancy. Analyzes nameserver delegation, provider diversity, and proper delegation to identify single points of failure.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_caa',
		description:
			'Check which Certificate Authorities are authorized to issue SSL certificates for a domain. Missing CAA records mean any CA can issue certificates, increasing unauthorized issuance risk.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_bimi',
		description:
			'Check if a domain has Brand Indicators for Message Identification (BIMI) configured for email client logo display. Validates BIMI TXT record, logo URL format, and VMC authority evidence.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_tlsrpt',
		description:
			'Check if SMTP TLS failure reporting is configured. Validates TLS-RPT (RFC 8460) records that enable receiving reports when email transport encryption fails — critical for monitoring MTA-STS enforcement.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_http_security',
		description:
			'Audit HTTP security headers protecting against XSS, clickjacking, and data leakage. Checks Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy, CORP, and COOP.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_dane',
		description:
			'Verify DNS-based certificate pinning (DANE/TLSA) for mail servers and HTTPS endpoints. Prevents certificate substitution attacks even if a CA is compromised.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_lookalikes',
		description:
			'Detect registered lookalike and typosquat domains that could be used for phishing or brand impersonation. Generates permutations (character swaps, homoglyphs, TLD variants) and checks for active infrastructure. Standalone — not in scan_domain due to query volume.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'scan_domain',
		description:
			'Run a comprehensive DNS and email security audit on any domain. Executes 14 checks in parallel (SPF, DMARC, DKIM, DNSSEC, SSL, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, Subdomain Takeover, HTTP Security, DANE) and returns an overall security score (0-100), letter grade (A+ to F), maturity stage, and prioritized findings with remediation guidance. Start here for any domain security question.',
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
			'Enforce security policy compliance by comparing a domain against minimum acceptable standards. Returns specific violations below baseline requirements. Designed for MSPs, security teams, and CI/CD pipelines enforcing organization-level DNS security standards.',
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
			'Discover alternate-TLD variants of a domain (e.g., .org, .net, .co) with active DNS/mail infrastructure and assess email spoofing risk. Identifies shadow domains lacking email authentication that attackers could use for impersonation. Standalone — not in scan_domain due to query volume.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_txt_hygiene',
		description:
			'Audit TXT records for stale service verifications, unexpected platform registrations, excessive accumulation, and cross-domain trust delegations. Maps the organization\'s verified SaaS platform exposure from public DNS — useful for shadow IT discovery.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_mx_reputation',
		description:
			'Check mail server reputation and deliverability risk. Resolves MX IPs, checks against major blocklists (Spamhaus, SpamCop, Barracuda), and validates reverse DNS (PTR/FCrDNS) consistency.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_srv',
		description:
			'Map the DNS-visible service footprint by probing SRV records. Discovers email, calendar, messaging, and other service advertisements, and flags insecure protocol advertisements.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'check_zone_hygiene',
		description:
			'Audit DNS zone consistency and detect exposed internal infrastructure. Checks SOA serial propagation and probes sensitive subdomains (vpn, admin, staging, corp) for unintended public DNS resolution.',
		inputSchema: DOMAIN_INPUT_SCHEMA,
	},
	{
		name: 'explain_finding',
		description:
			'Get a plain-language explanation of any DNS security finding, including real-world impact, adverse consequences if unresolved, and step-by-step remediation guidance with RFC references.',
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
