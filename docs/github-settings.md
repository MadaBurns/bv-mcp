# GitHub repository settings

These settings must be configured manually in the GitHub web UI.

## Repository description

Set to: `Source-available DNS & email security scanner for MCP clients. 76 MCP tools for SPF, DMARC, DKIM, DNSSEC, SSL/TLS, brand audit, authoritative DNS infrastructure, and more.`

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

## CI cost posture

No workflow may introduce a billing surface — a self-hosted runner, a paid marketplace action, or any paid GitHub feature — without explicit operator approval of that specific surface. If the cost of a feature is unclear, leave it disabled rather than enabling it to find out.

This is machine-enforced, not just documented: `test/audits/workflow-cost.audit.test.ts` (via `scripts/ci/check-workflow-cost.mjs`, part of `npm run audit:oss-safety`) fails CI on any self-hosted runner or paid marketplace action. Rationale and the full posture live in `docs/ci-cost-posture.md`.

The paid `MadaBurns/blackveil-dns-action` was removed and **replaced** by `.github/workflows/dns-security.yml`, which runs a $0 dogfood scan of blackveilsecurity.com using this repo's own built scanner (`scripts/ci/dogfood-scan.mjs`, minimum grade B, advisory — not a required check). Do not reintroduce the paid action; extend the dogfood scan instead.

## Exposure Cleanup

If sensitive data is pushed, rotate affected secrets first, rewrite the affected refs, and contact GitHub Support to purge cached views and PR refs. Ask fork owners to delete or rewrite affected forks because upstream history cleanup does not remediate fork copies.
