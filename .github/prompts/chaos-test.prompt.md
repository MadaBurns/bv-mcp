---
description: Run chaos tests against the production MCP endpoint and scan domains to validate deployment health.
name: Chaos Test Production
argument-hint: "Optional: domains to scan (comma-separated), e.g. google.com, cloudflare.com"
agent: agent
---
Validate the production deployment at `https://dns-mcp.blackveilsecurity.com/mcp`.

## Steps

1. **Run the chaos test script** covering all 9 MCP client types:
   ```bash
   python3 scripts/chaos/chaos-test-clients.py
   ```
   Report pass/fail count, total time, and any failures with details.

2. **Scan domains** against production to verify tool output:
   - If domains are provided: scan those
   - If not provided: scan `google.com`, `cloudflare.com`, `github.com`, `apple.com`, `stripe.com`
   - For each domain, create an MCP session, call `scan_domain`, report score/grade/profile
   - Verify structured JSON is present in the response (`STRUCTURED_RESULT` block)

3. **Summarize results** in a table:
   | Domain | Score | Grade | Profile | Structured JSON |
   |--------|-------|-------|---------|-----------------|

4. If any chaos test fails or scan returns errors, investigate and report the issue.

## Environment

- Requires `BV_API_KEY` environment variable for authenticated scans (optional — unauthenticated runs partial tests)
- Python venv at `.venv/` should be activated for chaos test
- Node.js required for domain scanning

## Reference

- Chaos test script: `scripts/chaos/chaos-test-clients.py`
- Production endpoint: `https://dns-mcp.blackveilsecurity.com/mcp`
