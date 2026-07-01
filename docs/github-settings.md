# GitHub repository settings

These settings must be configured manually in the GitHub web UI.

## Repository description

Set to: `Source-available DNS & email security scanner for MCP clients. 81 MCP tools for SPF, DMARC, DKIM, DNSSEC, SSL/TLS, brand audit, authoritative DNS infrastructure, and more.`

## Repository topics

Add these topics: `mcp`, `dns-security`, `email-security`, `spf`, `dmarc`, `dkim`, `dnssec`, `cloudflare-workers`, `security-scanner`, `model-context-protocol`

## Social preview image

Upload a 1280x640 social card image. Suggested design:
- Dark background (#0D1117 or similar)
- "Blackveil DNS" in large white text
- Tagline: "DNS & email security scanner for MCP"
- Score badge mockup showing "A+ 95/100"
- BLACKVEIL Security logo if available

## Secret Scanning

Enable GitHub secret scanning and push protection for all branches. Push protection must block commits containing supported provider secrets before they reach the remote.

Configure custom secret patterns for Blackveil key shapes, private Wrangler config, PEM private key headers, tenant/customer markers, and internal hostnames. Custom patterns should redact matches in alerts and should never include real production sample values.

## Branch Protection

Protect `main` and require pull requests before merge. Require status checks for `Security`, `Repo Hygiene`, the main test workflow, `npm run audit:repo-safety`, and `npm run audit:oss-safety`.

Require branches to be up to date before merge, block force pushes, block branch deletion, and require administrator enforcement unless a documented emergency change is approved.

## Required Checks

The required checks must include gitleaks, the repo safety scanner, OSS fixture safety, npm publish surface audit, and BUSL positioning audit. Do not make workflow edits that remove these gates without replacing them with an equivalent required check.

The paid `MadaBurns/blackveil-dns-action` workflow is intentionally disabled as `.github/workflows/dns-security.yml.disabled`. Do not re-enable it for push, pull request, or scheduled CI/CD unless an operator explicitly accepts the billing surface.

## Exposure Cleanup

If sensitive data is pushed, rotate affected secrets first, rewrite the affected refs, and contact GitHub Support to purge cached views and PR refs. Ask fork owners to delete or rewrite affected forks because upstream history cleanup does not remediate fork copies.
