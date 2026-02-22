/**
 * MCP Resources handler for the DNS Security MCP Server.
 * Exposes static documentation resources about security checks,
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
    uri: "dns-security://guides/security-checks",
    name: "DNS Security Checks Guide",
    description:
      "Overview of all DNS security checks performed by this server, including SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, and CAA.",
    mimeType: "text/markdown",
  },
  {
    uri: "dns-security://guides/scoring",
    name: "Scoring Methodology",
    description:
      "How DNS security scores and grades are calculated, including category weights and severity penalties.",
    mimeType: "text/markdown",
  },
  {
    uri: "dns-security://guides/record-types",
    name: "Supported DNS Record Types",
    description:
      "List of DNS record types queried by this server and their purpose in security analysis.",
    mimeType: "text/markdown",
  },
];

/** Resource content keyed by URI */
const RESOURCE_CONTENT: Record<string, string> = {
  "dns-security://guides/security-checks": `# DNS Security Checks

This server performs 8 categories of DNS security checks:

## SPF (Sender Policy Framework)
Validates SPF TXT records to prevent email spoofing. Checks for valid syntax, appropriate mechanisms, and proper use of \`~all\` or \`-all\`.

## DMARC (Domain-based Message Authentication)
Checks \`_dmarc\` TXT records for proper DMARC policy configuration. Validates the \`p=\` tag (none/quarantine/reject) and reporting addresses.

## DKIM (DomainKeys Identified Mail)
Queries common DKIM selectors under \`_domainkey\` to verify DKIM signing is configured. Checks for valid key records.

## DNSSEC (DNS Security Extensions)
Verifies DNSSEC validation by checking the AD (Authenticated Data) flag in DNS responses. Ensures DNS responses are cryptographically signed.

## SSL/TLS Certificate
Checks SSL/TLS certificate validity and configuration for the domain.

## MTA-STS (Mail Transfer Agent Strict Transport Security)
Validates \`_mta-sts\` TXT records to ensure email transport security policies are in place.

## NS (Name Server) Configuration
Analyzes name server configuration for redundancy, diversity, and proper delegation.

## CAA (Certificate Authority Authorization)
Checks CAA DNS records that restrict which certificate authorities can issue certificates for the domain.
`,

  "dns-security://guides/scoring": `# Scoring Methodology

## Category Weights
Each security check category contributes to the overall score with the following weights:

| Category | Weight |
|----------|--------|
| SPF      | 15%    |
| DMARC    | 15%    |
| DKIM     | 15%    |
| DNSSEC   | 15%    |
| SSL/TLS  | 15%    |
| MTA-STS  | 5%     |
| NS       | 10%    |
| CAA      | 10%    |

## Severity Penalties
Findings reduce the category score based on severity:

| Severity | Penalty |
|----------|---------|
| Critical | -40 pts |
| High     | -25 pts |
| Medium   | -15 pts |
| Low      | -5 pts  |
| Info     | 0 pts   |

## Grading Scale
The overall weighted score maps to a letter grade:
- **A+**: 95-100 | **A**: 90-94 | **A-**: 85-89
- **B+**: 80-84 | **B**: 75-79 | **B-**: 70-74
- **C+**: 65-69 | **C**: 60-64 | **C-**: 55-59
- **D+**: 50-54 | **D**: 45-49 | **D-**: 40-44
- **F**: Below 40

Each category starts at 100 points and deductions are applied per finding.
`,

  "dns-security://guides/record-types": `# Supported DNS Record Types

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
  if (typeof uri !== "string") {
    throw new Error("Missing required parameter: uri");
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
        mimeType: resource?.mimeType ?? "text/plain",
        text: content,
      },
    ],
  };
}

