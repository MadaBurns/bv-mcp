# Coverage and Limitations

This document defines the current functional scope of `bv-mcp`.

## Callable MCP Tools

`tools/list` exposes the following callable tools:

- `check_mx`
- `check_spf`
- `check_dmarc`
- `check_dkim`
- `check_dnssec`
- `check_ssl`
- `check_mta_sts`
- `check_ns`
- `check_caa`
- `check_bimi`
- `check_tlsrpt`
- `check_lookalikes`
- `scan_domain`
- `compare_baseline`
- `explain_finding`

## Internal Checks Executed by `scan_domain`

`scan_domain` additionally executes:

- `subdomain_takeover` (internal check, not separately callable)

## In-Scope Areas

- DNS and email authentication posture
- Transport and certificate hygiene
- Delegation and issuance controls
- Weighted scoring for remediation prioritization

## Out-of-Scope Areas

- Generic web application penetration testing
- Host/network vulnerability scanning
- Third-party dependency analysis (SCA)
- Full SAST/DAST application coverage

## Testing Evidence

- Test framework: Vitest in Cloudflare Workers runtime
- DNS behavior is mocked in tests (no live DNS dependency)
- Coverage reports are produced via Istanbul

Run tests with:

```bash
npm test
```
