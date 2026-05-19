# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| < 2.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Blackveil DNS, **do not open a public issue**. Instead, please report it privately:

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

- Vulnerabilities in the Blackveil DNS MCP server code (this repository)
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


## Disclosure Policy

BLACKVEIL Security follows a **coordinated disclosure** process:

1. You report the vulnerability privately via email.
2. We acknowledge receipt and begin investigation.
3. We work with you to understand the issue and develop a fix.
4. We release the fix and publish a security advisory.
5. You may publish your findings after the fix is released.

We ask that you allow up to **90 days** from the initial report before public disclosure, to ensure adequate time for a fix to be developed, tested, and deployed.

We will credit reporters in the security advisory unless you prefer to remain anonymous.

## Exposure Response

If a credential, real customer data, internal infrastructure detail, generated report, or proprietary planning artifact reaches GitHub:

1. Rotate affected credentials and revoke exposed tokens before cleanup work begins.
2. Remove the data from the current tree, then rewrite Git history for every affected branch or tag.
3. Open a GitHub Support request to purge cached views, pull request refs, and other retained PR refs that history rewriting cannot remove.
4. Identify forks made after the exposure and ask fork owners to delete or rewrite the affected fork history.
5. Treat generated PDFs, reports, CSC outputs, tenant SQL, and `.dev/` material as sensitive even when they contain partial or test-looking data.
6. Document the incident privately, including rotation evidence, rewritten refs, GitHub Support ticket links, and fork remediation status.

## Contact

- **Security reports:** [security@blackveilsecurity.com](mailto:security@blackveilsecurity.com)
- **General inquiries:** [https://blackveilsecurity.com](https://blackveilsecurity.com)
