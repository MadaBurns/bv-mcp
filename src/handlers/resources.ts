// SPDX-License-Identifier: BUSL-1.1

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
];

/** Resource content keyed by URI */
const RESOURCE_CONTENT: Record<string, string> = {
	'dns-security://guides/security-checks': `# DNS Security Checks

The Blackveil DNS scanner evaluates **50+ checks** grouped into 13 categories.

This MCP server exposes tools that cover the core checks in each category and returns findings compatible with Blackveil DNS scoring.

## Coverage by Tier

| Category | Total Scanner Checks | Free Tier (MCP/Core) | Premium Platform |
|---|---:|---|---|
| SPF | 8 | Core SPF policy and syntax checks, trust surface analysis | Advanced include-chain and sender-path analytics |
| DMARC | 10 | Core policy, pct, reporting checks, URI validation, alignment modes | Alignment depth, subdomain inheritance, reporting quality analytics |
| DKIM | 9 | Selector discovery, RSA key strength validation, v= tag checks | Selector entropy, rotation heuristics, key-age and drift analytics |
| DNSSEC | 6 | AD validation and signed-zone baseline | Chain-of-trust and rollover posture analytics |
| SSL/TLS | 8 | Certificate availability and baseline validity checks | Protocol/cipher depth, PKI posture, renewal-risk analytics |
| MTA-STS | 5 | TXT policy presence and basic policy retrieval checks | Policy hardening and reporting-depth analytics |
| NS | 4 | Delegation, diversity, and resiliency baseline checks | Infrastructure concentration and availability analytics |
| CAA | 4 | CAA presence and issuer-allowlist baseline checks | Issuance surface modeling and mis-issuance risk analytics |
| MX | 4 | MX presence, routing quality, and outbound provider inference | Mail routing posture and provider analytics |
| Subdomain Takeover | 2 | Dangling CNAME detection across known subdomains | Expanded asset discovery and takeover surface analytics |
| BIMI | 1 | Brand logo publication and VMC validation | - |
| TLS-RPT | 1 | SMTP TLS failure reporting configuration | - |
| Lookalikes | 1 | Typosquat/lookalike domain detection (standalone) | - |

> Total checks: **50+** across all categories.

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

## BIMI (Brand Indicators for Message Identification)
Tool: \`check_bimi\`
Validates BIMI TXT records at \`default._bimi.<domain>\`. Checks logo URL format (HTTPS, SVG Tiny PS) and VMC authority evidence. Part of \`scan_domain\`.

## TLS-RPT (SMTP TLS Reporting)
Tool: \`check_tlsrpt\`
Validates TLS-RPT records at \`_smtp._tls.<domain>\` per RFC 8460. Checks reporting URI configuration. Part of \`scan_domain\`.

## Lookalike Domain Detection
Tool: \`check_lookalikes\`
Generates typosquat/lookalike domain permutations and checks for active DNS/mail infrastructure. Standalone tool — not part of \`scan_domain\` due to query volume.

## SPF Trust Surface Analysis
Part of \`check_spf\`. Identifies when SPF \`include:\` directives delegate sending authority to multi-tenant SaaS platforms (Google Workspace, Microsoft 365, SendGrid, etc.), widening the spoofing attack surface.

## Composite Tools

- \`scan_domain\`: Runs all 12 checks and produces an overall score + grade.
- \`explain_finding\`: Provides plain-language context and remediation guidance for individual findings.
`,

	'dns-security://guides/scoring': `# Scoring Methodology

This server uses scanner-aligned scoring for the overlapping controls currently implemented by MCP tools.

## Importance Weights (Default: mail_enabled)
Overall score is based on importance points per category, not a flat average:

| Category | Importance Points |
|---|---:|
| DMARC | 22 |
| DKIM | 16 |
| SPF | 10 |
| SSL/TLS | 5 |
| Subdomain Takeover | 3 |
| DNSSEC | 2 |
| MTA-STS | 2 |
| MX | 2 |
| TLS-RPT | 1 |
| NS | 0 (informational) |
| CAA | 0 (informational) |
| BIMI | 0 (informational) |
| Lookalikes | 0 (informational) |

Scored total: **63** (+ up to 8 email bonus = 71 max denominator).

## Scoring Profiles
Weights adapt based on domain purpose. Pass \`profile\` to \`scan_domain\` to override:

- **mail_enabled** (default): Weights above. Email bonus eligible.
- **enterprise_mail**: Email auth elevated (DMARC:24, DKIM:18, SPF:12), MTA-STS/TLS-RPT/BIMI boosted.
- **non_mail**: Email auth near-zero, SSL:8, DNSSEC:5, SubdomainTakeover:5, CAA:3. No email bonus.
- **web_only**: SSL:12, CAA:5, DNSSEC:5, SubdomainTakeover:5. No email bonus.
- **minimal**: Weights spread evenly. No email bonus.

Auto-detection reports the detected profile but uses default weights (Phase 1).

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

## Critical Gap Ceiling
Domains missing foundational controls are capped at **64** (D+). Critical categories vary by profile:
- mail_enabled/enterprise_mail: SPF, DMARC, DKIM, SSL, DNSSEC, Subdomain Takeover
- non_mail/web_only/minimal: SSL, DNSSEC, Subdomain Takeover

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
