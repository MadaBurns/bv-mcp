# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in BLACKVEIL Scanner, **do not open a public issue**. Instead, please report it privately:

**Email:** [security@blackveilsecurity.com](mailto:security@blackveilsecurity.com)

Include the following in your report:

- A description of the vulnerability and its potential impact
- Steps to reproduce, including any relevant request payloads or configurations
- The affected component (e.g., `src/lib/sanitize.ts`, `src/tools/check-spf.ts`)
- Your suggested severity (Critical, High, Medium, Low)

**Response timeline:**

- **Acknowledgement** within 48 hours of receipt
- **Initial assessment** within 5 business days
- **Resolution or mitigation** coordinated with you before public disclosure

## Scope

### In Scope

- Vulnerabilities in the BLACKVEIL Scanner MCP server code (this repository)
- SSRF bypasses in domain validation or DNS resolution
- Authentication or authorization bypasses
- Input validation flaws (e.g., domain sanitization, JSON-RPC parsing)
- Rate limiting bypasses
- Information disclosure through error messages or logs
- Injection attacks via crafted domain names or tool parameters

### Out of Scope

- Cloudflare Workers infrastructure, KV, or network-level issues (report to [Cloudflare](https://www.cloudflare.com/disclosure/))
- Third-party dependencies with their own security policies (report upstream)
- Social engineering or phishing attacks
- Denial of service via normal rate-limited usage
- Issues in the frozen `/bv-dns-security-mcp/` distribution (report separately if applicable)

## Disclosure Policy

BLACKVEIL Security follows a **coordinated disclosure** process:

1. You report the vulnerability privately via email.
2. We acknowledge receipt and begin investigation.
3. We work with you to understand the issue and develop a fix.
4. We release the fix and publish a security advisory.
5. You may publish your findings after the fix is released.

We ask that you allow up to **90 days** from the initial report before public disclosure, to ensure adequate time for a fix to be developed, tested, and deployed.

We will credit reporters in the security advisory unless you prefer to remain anonymous.

## Contact

- **Security reports:** [security@blackveilsecurity.com](mailto:security@blackveilsecurity.com)
- **General inquiries:** [https://blackveilsecurity.com](https://blackveilsecurity.com)
