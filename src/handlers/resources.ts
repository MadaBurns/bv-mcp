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
];

/** Resource content keyed by URI */
const RESOURCE_CONTENT: Record<string, string> = {
	'dns-security://guides/security-checks': `# DNS Security Checks

The Blackveil DNS scanner evaluates **57+ checks** grouped into 20 categories.

This MCP server exposes 22 tools that cover the core checks in each category and returns findings compatible with Blackveil DNS scoring.

## Coverage by Tier

| Category | Total Scanner Checks | Free Tier (MCP/Core) | Premium Platform |
|---|---:|---|---|
| SPF | 8 | Core SPF policy and syntax checks | Advanced include-chain and sender-path analytics |
| DMARC | 10 | Core policy, pct, reporting checks, URI validation, alignment modes | Alignment depth, subdomain inheritance, reporting quality analytics |
| DKIM | 9 | Selector discovery, RSA key strength validation, v= tag checks | Selector entropy, rotation heuristics, key-age and drift analytics |
| DNSSEC | 6 | AD validation and signed-zone baseline | Chain-of-trust and rollover posture analytics |
| SSL/TLS | 8 | Certificate availability and baseline validity checks | Protocol/cipher depth, PKI posture, renewal-risk analytics |
| MTA-STS | 5 | TXT policy presence and basic policy retrieval checks | Policy hardening and reporting-depth analytics |
| NS | 4 | Delegation, diversity, and resiliency baseline checks | Infrastructure concentration and availability analytics |
| CAA | 4 | CAA presence and issuer-allowlist baseline checks | Issuance surface modeling and mis-issuance risk analytics |
| MX | 4 | MX presence, routing quality, and outbound provider inference | Mail routing posture and provider analytics |
| Subdomain Takeover | 2 | Dangling CNAME detection across known subdomains | Expanded asset discovery and takeover surface analytics |
| HTTP Security | 7 | CSP, X-Frame-Options, COOP, CORP, Permissions-Policy checks | Header depth analytics |
| DANE | 3 | TLSA record validation for MX and HTTPS | Certificate pinning posture |
| Shadow Domains | 1 | Alternate-TLD email spoofing risk detection | Extended TLD coverage |
| TXT Hygiene | 1 | Stale verifications, SaaS exposure mapping | Shadow IT discovery |
| MX Reputation | 1 | DNSBL and PTR/FCrDNS validation | Deliverability analytics |
| SRV | 1 | Service footprint discovery via SRV records | Protocol exposure analytics |
| Zone Hygiene | 1 | SOA consistency and sensitive subdomain detection | Infrastructure exposure |
| BIMI | 1 | Record presence, logo URL, VMC | Brand indicator compliance |
| TLS-RPT | 1 | Record presence, reporting URI | Reporting depth |
| Lookalikes | 1 | Typosquat detection, DNS + MX probing | Expanded permutation strategies |

> Total checks: **57+** across 20 categories.

## Categories and Tool Mapping

## SPF (Sender Policy Framework)
Tool: \`check_spf\`  
Validates SPF TXT records to reduce spoofing risk. Includes presence, mechanism quality, lookup pressure, and policy strictness checks.

## DMARC (Domain-based Message Authentication)
Tool: \`check_dmarc\`  
Checks \`_dmarc\` policy posture including enforcement mode, reporting URIs (rua=/ruf=), alignment modes (adkim=/aspf=), subdomain policy, and third-party aggregator detection. Validates URI format and identifies known aggregator services.

## DKIM (DomainKeys Identified Mail)
Tool: \`check_dkim\`  
Probes common selectors under \`_domainkey\` and validates key records. Includes RSA key strength validation (512/1024/2048/4096-bit detection via base64 length heuristic), v=DKIM1 tag validation, and comprehensive selector discovery across major providers.

## DNSSEC (DNS Security Extensions)
Tool: \`check_dnssec\`  
Verifies DNSSEC validation state and signed-response posture for the queried domain.

## SSL/TLS Certificate
Tool: \`check_ssl\`  
Checks HTTPS certificate presence and baseline certificate health.

## MTA-STS (Mail Transfer Agent Strict Transport Security)
Tool: \`check_mta_sts\`  
Validates \`_mta-sts\` policy publication and retrieval for secure SMTP transport.

## NS (Name Server) Configuration
Tool: \`check_ns\`  
Analyzes delegation resilience and provider diversity indicators.

## CAA (Certificate Authority Authorization)
Tool: \`check_caa\`
Checks CA authorization posture and issuance restriction baseline.

## MX (Mail Exchange)
Tool: \`check_mx\`
Validates presence and quality of MX records for a domain, including outbound email provider detection.

## Subdomain Takeover Detection
Tool: internal to \`scan_domain\` (not directly callable)
Scans known subdomains for dangling CNAME records pointing to unresolved third-party services.

## HTTP Security Headers
Tool: \`check_http_security\`
Audits HTTP response headers for XSS, clickjacking, and data leakage protections.

## DANE (DNS-Based Authentication of Named Entities)
Tool: \`check_dane\`
Verifies TLSA records for certificate pinning on MX and HTTPS endpoints.

## Shadow Domains
Tool: \`check_shadow_domains\`
Discovers alternate-TLD variants with active infrastructure and assesses email spoofing risk.

## TXT Record Hygiene
Tool: \`check_txt_hygiene\`
Audits TXT records for stale service verifications, SaaS exposure, and cross-domain trust delegations.

## MX Reputation
Tool: \`check_mx_reputation\`
Checks mail server reputation via DNSBL lookups and validates reverse DNS consistency.

## SRV Service Discovery
Tool: \`check_srv\`
Probes SRV records to map the DNS-visible service footprint.

## Zone Hygiene
Tool: \`check_zone_hygiene\`
Audits SOA serial propagation and detects sensitive subdomains exposed in public DNS.

## Composite Tools

- \`scan_domain\`: Runs 14 checks in parallel and produces an overall score + grade.
- \`explain_finding\`: Provides plain-language context and remediation guidance for individual findings.
- \`compare_baseline\`: Compares a domain against minimum acceptable security standards.
`,

	'dns-security://guides/scoring': `# Scoring Methodology

This server uses scanner-aligned scoring for the overlapping controls currently implemented by MCP tools.

## Importance Weights (Scanner-Aligned)
Overall score is based on importance points per category, not a flat average:

| Category | Importance Points |
|---|---:|
| SPF | 19 |
| DMARC | 22 |
| DKIM | 10 |
| DNSSEC | 3 |
| SSL/TLS | 8 |
| MTA-STS | 3 |
| NS | 3 |
| CAA | 2 |
| Subdomain Takeover | 2 |
| MX | 0 (informational) |

Additional bonus: up to **+5** points for strong combined email-auth posture.

## Per-Category Penalties
Each category starts at 100 and penalties are applied per finding severity:

| Severity | Penalty |
|----------|---------|
| Critical | -40 pts |
| High     | -25 pts |
| Medium   | -15 pts |
| Low      | -5 pts  |
| Info     | 0 pts   |

## Missing-Control Handling
For categories where a required control is missing (for example, "No DMARC record found"), effective contribution can be treated as zeroed in overall scoring.

## Critical-Finding Adjustment
If any **verified**-confidence **critical** finding exists in the scan, an additional **-15 overall points** adjustment is applied.
This ensures verified critical risks materially impact final grades even when they occur in low-importance categories.

## Grading Scale
The overall weighted score maps to a letter grade:
- **A+**: 90+
- **A**: 85-89
- **B+**: 80-84
- **B**: 75-79
- **C+**: 70-74
- **C**: 65-69
- **D+**: 60-64
- **D**: 55-59
- **E**: 50-54
- **F**: <50
`,

	'dns-security://guides/agent-workflows': `# Agent Workflow Guide

Recommended tool usage patterns for common DNS security tasks.

## Decision Tree: What Tool Should I Use?

| User Intent | Recommended Tools | Notes |
|---|---|---|
| "Is my domain secure?" / "Audit my domain" | \`scan_domain\` | Start here — runs 14 checks in parallel, returns score + grade + prioritized findings |
| "Can someone spoof my email?" / "Email spoofing risk" | \`check_spf\` → \`check_dmarc\` → \`check_dkim\` | The email authentication triad — check all three for a complete picture |
| "Are there phishing lookalikes?" / "Brand impersonation risk" | \`check_lookalikes\` + \`check_shadow_domains\` | Standalone checks — not in scan_domain due to query volume |
| "Is my DNS infrastructure solid?" | \`check_ns\` + \`check_zone_hygiene\` + \`check_dnssec\` | Infrastructure resilience + zone consistency + tamper protection |
| "Are my web security headers OK?" | \`check_http_security\` + \`check_ssl\` + \`check_caa\` | Web security posture: headers + certificate + CA authorization |
| "Is our email transport encrypted?" | \`check_mta_sts\` + \`check_tlsrpt\` + \`check_dane\` | TLS enforcement + failure reporting + certificate pinning |
| "Do we meet compliance requirements?" | \`compare_baseline\` | Pass policy minimums as baseline — returns specific violations |
| "What does this finding mean?" | \`explain_finding\` | Plain-language explanation with remediation steps |
| "What services are published in DNS?" | \`check_srv\` + \`check_txt_hygiene\` | SRV records + TXT verification records map service footprint |
| "Are our mail servers blacklisted?" | \`check_mx_reputation\` | DNSBL checks + reverse DNS validation |

## Common Workflows

### Full Security Audit
1. \`scan_domain\` — get overall score and all findings
2. \`explain_finding\` — for each critical/high finding, get remediation guidance
3. Summarize with prioritized action plan

### Email Authentication Hardening
1. \`check_spf\` — validate SPF record and trust surface
2. \`check_dmarc\` — check enforcement level (none → quarantine → reject)
3. \`check_dkim\` — verify key presence and strength
4. \`check_mta_sts\` — ensure transport encryption
5. \`explain_finding\` — remediation for any failures

### Brand Protection Assessment
1. \`check_lookalikes\` — find registered typosquat domains
2. \`check_shadow_domains\` — find alternate-TLD variants lacking email auth
3. \`scan_domain\` — baseline security of the primary domain

### CI/CD Policy Enforcement
Use \`compare_baseline\` with policy requirements:
\`\`\`json
{
  "grade": "B",
  "require_spf": true,
  "require_dmarc_enforce": true,
  "require_dkim": true,
  "max_critical_findings": 0
}
\`\`\`
Returns pass/fail with specific violations — ideal for automated gates.

## Tips
- \`scan_domain\` caches results for 5 minutes — subsequent individual checks on the same domain return cached data
- \`check_lookalikes\` and \`check_shadow_domains\` are rate-limited (20/day unauthenticated) — use judiciously
- All checks are passive and read-only — safe to run against any domain
- Use the \`profile\` parameter on \`scan_domain\` for non-mail domains (web_only, non_mail) to get more relevant scoring
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
