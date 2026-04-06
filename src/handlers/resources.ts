/**
 * MCP Resources handler for Blackveil DNS.
 * Exposes static documentation resources about DNS/email security checks,
 * scoring methodology, and supported DNS record types.
 *
 * Handles JSON-RPC methods: resources/list, resources/read
 * Compatible with Cloudflare Workers runtime (no Node.js APIs).
 */

/** MCP Resource descriptor */
interface McpResource {
	uri: string;
	name: string;
	description: string;
	mimeType: string;
}

/** MCP Resource content */
interface McpResourceContent {
	uri: string;
	mimeType: string;
	text: string;
}

/** Static resource definitions */
const RESOURCES: McpResource[] = [
 {
   uri: 'dns-security://guides/security-checks',
   name: 'DNS Security Checks Guide',
   description:
		 'Overview of all DNS/email security checks performed by Blackveil DNS, including SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, CAA, MX, and Subdomain Takeover.',
   mimeType: 'text/markdown',
 },
 {
   uri: 'dns-security://guides/scoring',
   name: 'Scoring Methodology',
   description: 'How DNS/email security scores and grades are calculated, including category weights and severity penalties.',
   mimeType: 'text/markdown',
 },
	{
		uri: 'dns-security://guides/record-types',
		name: 'Supported DNS Record Types',
		description: 'List of DNS record types queried by this server and their purpose in security analysis.',
		mimeType: 'text/markdown',
	},
	{
		uri: 'dns-security://guides/agent-workflows',
		name: 'Agent Workflow Guide',
		description: 'Recommended tool usage patterns and decision trees for common DNS security tasks.',
		mimeType: 'text/markdown',
	},
	{
		uri: 'dns-security://guides/intelligence',
		name: 'Intelligence Layer Guide',
		description: 'How benchmark and provider cohort features work, privacy guarantees, and data freshness.',
		mimeType: 'text/markdown',
	},
	{
		uri: 'dns-security://guides/remediation',
		name: 'DNS Remediation Guide',
		description: 'Step-by-step DNS record fix patterns for each check category, using generate_* tools.',
		mimeType: 'text/markdown',
	},
];

/** Resource content keyed by URI */
const RESOURCE_CONTENT: Record<string, string> = {
	'dns-security://guides/security-checks': `# DNS Security Checks

22 check tools covering **57+ checks** across 20 categories.

## Tool -> Category Mapping

| Tool | Category | What It Checks |
|------|----------|---------------|
| \`check_spf\` | SPF | Policy, syntax, mechanism quality, lookup limits, trust surface |
| \`check_dmarc\` | DMARC | Enforcement, rua/ruf URIs, alignment, subdomain policy, aggregator detection |
| \`check_dkim\` | DKIM | Selector discovery, RSA key strength (512-4096 bit), v=DKIM1 tags |
| \`check_dnssec\` | DNSSEC | AD validation, DNSKEY/DS records, algorithm strength |
| \`check_ssl\` | SSL/TLS | HTTPS reachability, HSTS policy |
| \`check_mta_sts\` | MTA-STS | TXT policy presence, policy retrieval |
| \`check_ns\` | NS | Delegation resilience, provider diversity |
| \`check_caa\` | CAA | CA authorization, issuance restrictions |
| \`check_mx\` | MX | MX presence, routing quality, provider detection |
| \`check_http_security\` | HTTP Security | CSP, X-Frame-Options, COOP, CORP, Permissions-Policy |
| \`check_dane\` | DANE | TLSA records for MX SMTP ports |
| \`check_dane_https\` | DANE HTTPS | TLSA records for HTTPS endpoints |
| \`check_svcb_https\` | SVCB HTTPS | HTTPS/SVCB records (RFC 9460) |
| \`check_shadow_domains\` | Shadow Domains | Alternate-TLD variants, email spoofing risk |
| \`check_txt_hygiene\` | TXT Hygiene | Stale verifications, SaaS exposure |
| \`check_mx_reputation\` | MX Reputation | DNSBL lookups, PTR/FCrDNS validation |
| \`check_srv\` | SRV | Service footprint via SRV records |
| \`check_zone_hygiene\` | Zone Hygiene | SOA consistency, sensitive subdomain detection |
| \`check_bimi\` | BIMI | Record presence, logo URL, VMC |
| \`check_tlsrpt\` | TLS-RPT | Record presence, reporting URI |
| \`check_lookalikes\` | Lookalikes | Typosquat detection, DNS + MX probing |
| _(internal)_ | Subdomain Takeover | Dangling CNAMEs to unresolved services (via \`scan_domain\` only) |

## Composite Tools

- **\`scan_domain\`** - 16 checks in parallel, returns score + grade + prioritized findings
- **\`explain_finding\`** - plain-language context + remediation for any finding
- **\`compare_baseline\`** - pass/fail against minimum security standards
`,

	'dns-security://guides/scoring': `# Scoring Methodology

Three-tier weighted scoring. Each category starts at 100, reduced by severity penalties.

## Three-Tier Model

**Core (70%):** DMARC (16), DKIM (10), SPF (10), DNSSEC (8), SSL (8)
**Protective (20%):** Subdomain Takeover (3), HTTP Security (3), MTA-STS (2), MX (2), DANE HTTPS (2), TLS-RPT (1), DANE (1)
**Hardening (10%):** BIMI, CAA, NS, Lookalikes, Shadow Domains, TXT Hygiene, MX Reputation, SRV, Zone Hygiene, SVCB HTTPS — bonus-only, never subtracts.

Email bonus: up to **+5 pts** for strong SPF+DKIM+DMARC.

## Severity Penalties

Critical: -40 | High: -25 | Medium: -15 | Low: -5 | Info: 0

## Special Rules

- **Missing control** -> category contribution zeroed (Core tier, deterministic/verified confidence only)
- **Verified critical finding** -> additional **-15 overall** penalty

## Grades

A+: 92+ | A: 87-91 | B+: 82-86 | B: 76-81 | C+: 70-75 | C: 63-69 | D+: 56-62 | D: 50-55 | F: <50
`,

	'dns-security://guides/agent-workflows': `# Agent Workflow Guide

## Tool Selection

| Intent | Tools |
|--------|-------|
| Full audit / "Is my domain secure?" | \`scan_domain\` then \`explain_finding\` for critical/high |
| Email spoofing risk | \`check_spf\` -> \`check_dmarc\` -> \`check_dkim\` |
| Brand impersonation | \`check_lookalikes\` + \`check_shadow_domains\` |
| DNS infrastructure | \`check_ns\` + \`check_zone_hygiene\` + \`check_dnssec\` |
| Web security | \`check_http_security\` + \`check_ssl\` + \`check_caa\` |
| Email transport encryption | \`check_mta_sts\` + \`check_tlsrpt\` + \`check_dane\` |
| Compliance gate | \`compare_baseline\` with policy requirements |
| Explain a finding | \`explain_finding\` |
| Service discovery | \`check_srv\` + \`check_txt_hygiene\` |
| Mail server blacklist | \`check_mx_reputation\` |

## Workflows

**Full Audit:** \`scan_domain\` -> \`explain_finding\` per critical/high -> summarize action plan

**Email Hardening:** \`check_spf\` -> \`check_dmarc\` -> \`check_dkim\` -> \`check_mta_sts\` -> \`explain_finding\` for failures

**Brand Protection:** \`check_lookalikes\` -> \`check_shadow_domains\` -> \`scan_domain\` for baseline

**CI/CD Gate:** \`compare_baseline\` with \`{"grade":"B","require_spf":true,"require_dmarc_enforce":true,"require_dkim":true,"max_critical_findings":0}\` -> returns pass/fail + violations

## Tips
- \`scan_domain\` caches 5 min; subsequent checks use cached data
- \`check_lookalikes\`/\`check_shadow_domains\`: 20/day limit (unauth)
- All checks are passive/read-only
- Use \`profile\` param on \`scan_domain\` for non-mail domains (\`web_only\`, \`non_mail\`)
`,

	'dns-security://guides/intelligence': `# Intelligence Layer Guide

Anonymized, aggregate telemetry from scans for benchmarking and provider cohort insights.

## Tools

| Tool | Purpose |
|------|---------|
| \`get_benchmark\` | Score distribution, percentile ranks, top failing categories |
| \`get_provider_insights\` | Provider-specific cohort comparison |

## Data Collected Per Scan
- Score histogram (10-point buckets) -- no domain names stored
- Provider cohort EMA-smoothed averages
- Hourly trend snapshots (30-day rolling window)

## Privacy
No domain names, IPs, or PII stored. All data is aggregate (profile-level or provider-level) with EMA smoothing.

## Profiles
\`mail_enabled\` (default) | \`enterprise_mail\` | \`non_mail\` | \`web_only\` | \`minimal\` (>50% failures)

## Usage
1. \`scan_domain\` -> note score + detected profile/provider
2. \`get_benchmark\` or \`get_provider_insights\` -> compare against population/cohort

Benchmarks require 100+ scans per profile to be meaningful.
`,

	'dns-security://guides/remediation': `# DNS Remediation Guide

## Tools

| Tool | Output | When |
|------|--------|------|
| \`generate_fix_plan\` | Prioritized action list | Start here |
| \`generate_spf_record\` | SPF TXT record | Missing/broken SPF |
| \`generate_dmarc_record\` | DMARC TXT record | Missing/weak DMARC |
| \`generate_dkim_config\` | DKIM setup instructions | Missing DKIM |
| \`generate_mta_sts_policy\` | MTA-STS TXT + policy | No transport encryption |

## Workflow
1. \`generate_fix_plan\` -> prioritized actions by impact
2. \`generate_spf_record\` -> SPF first (sender authorization)
3. \`generate_dkim_config\` -> DKIM second (message signing)
4. \`generate_dmarc_record\` -> DMARC last (start \`p=none\`, upgrade to \`reject\`)
5. \`generate_mta_sts_policy\` -> transport encryption

## Maturity Progression

| Stage | Records to Add |
|-------|----------------|
| 0->1 | SPF + DMARC (p=none) |
| 1->2 | DKIM + DMARC rua reporting |
| 2->3 | DMARC p=reject + MTA-STS |
| 3->4 | DNSSEC + DANE + BIMI |

## Verification
Re-run the relevant check tool after publishing. Allow 5-10 min for DNS propagation.
`,

	'dns-security://guides/record-types': `# Supported DNS Record Types

This server queries the following DNS record types via Cloudflare DNS-over-HTTPS:

| Type   | Code | Purpose |
|--------|------|---------|
| A      | 1    | IPv4 address records |
| AAAA   | 28   | IPv6 address records |
| CNAME  | 5    | Canonical name aliases |
| MX     | 15   | Mail exchange servers |
| TXT    | 16   | Text records (SPF, DMARC, DKIM, MTA-STS) |
| NS     | 2    | Name server delegation |
| SOA    | 6    | Start of authority |
| CAA    | 257  | Certificate authority authorization |
| TLSA   | 52   | TLS authentication (DANE) |
| DNSKEY | 48   | DNSSEC public keys |
| DS     | 43   | DNSSEC delegation signer |
| RRSIG  | 46   | DNSSEC resource record signatures |

All queries use the JSON wire format (\`application/dns-json\`) via \`https://cloudflare-dns.com/dns-query\`.
`,
};

/**
 * Handle the MCP resources/list method.
 * Returns all available resource descriptors.
 */
export function handleResourcesList(): { resources: McpResource[] } {
	return { resources: RESOURCES };
}

/**
 * Handle the MCP resources/read method.
 * Returns the content of a specific resource by URI.
 */
export function handleResourcesRead(params: Record<string, unknown>): {
	contents: McpResourceContent[];
} {
	const uri = params.uri;
	if (typeof uri !== 'string') {
		throw new Error('Missing required parameter: uri');
	}
	const content = RESOURCE_CONTENT[uri];
	if (!content) {
		throw new Error(`Resource not found: ${uri}`);
	}
	const resource = RESOURCES.find((r) => r.uri === uri);
	return {
		contents: [
			{
				uri,
				mimeType: resource?.mimeType ?? 'text/plain',
				text: content,
			},
		],
	};
}
