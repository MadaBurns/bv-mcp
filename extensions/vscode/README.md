# Blackveil DNS — MCP Security Scanner

**44 DNS & email security tools** for GitHub Copilot Chat. No install, no API key — just ask Copilot to scan any domain.

![Blackveil DNS](https://raw.githubusercontent.com/MadaBurns/bv-mcp/main/assets/bv-logo-full.png)

## Quick Start

1. Install this extension
2. Open GitHub Copilot Chat (`Ctrl+Shift+I` / `Cmd+Shift+I`)
3. Ask: **"scan example.com"**

That's it. All 44 tools are available instantly.

## What You Get

- **80+ checks across 20 categories** — SPF, DMARC, DKIM, DNSSEC, SSL/TLS, MTA-STS, NS, CAA, MX, BIMI, TLS-RPT, subdomain takeover, lookalike domains, HTTP security headers, DANE, shadow domains, TXT hygiene, MX reputation, SRV, zone hygiene
- **Maturity staging** — Stage 0–4 classification (Unprotected → Hardened)
- **Trust surface analysis** — detects shared SaaS platforms and cross-references DMARC enforcement
- **Guided remediation** — provider-aware fix plans, record generators, fix validation
- **Supply chain mapping** — full third-party dependency graph from DNS signals
- **Attack path simulation** — enumerated spoofing, takeover, and hijack paths
- **Compliance mapping** — NIST 800-177, PCI DSS 4.0, SOC 2, CIS Controls

## Tools (44)

| Email Auth | Infrastructure | Brand & Threats | Intelligence |
|---|---|---|---|
| `check_spf` | `check_dnssec` | `check_bimi` | `get_benchmark` |
| `check_dmarc` | `check_ns` | `check_tlsrpt` | `get_provider_insights` |
| `check_dkim` | `check_caa` | `check_lookalikes` | `assess_spoofability` |
| `check_mta_sts` | `check_ssl` | `check_shadow_domains` | `map_supply_chain` |
| `check_mx` | `check_http_security` | | `resolve_spf_chain` |
| `check_mx_reputation` | `check_dane` | **DNS Hygiene** | `discover_subdomains` |
| `check_subdomailing` | `check_dane_https` | `check_txt_hygiene` | `map_compliance` |
| | `check_svcb_https` | | `simulate_attack_paths` |
| **Meta** | `check_srv` | **Remediation** | `analyze_drift` |
| `scan_domain` | `check_zone_hygiene` | `generate_fix_plan` | `check_resolver_consistency` |
| `batch_scan` | | `generate_spf_record` | |
| `compare_domains` | | `generate_dmarc_record` | |
| `compare_baseline` | | `generate_dkim_config` | |
| `explain_finding` | | `generate_mta_sts_policy` | |
| | | `generate_rollout_plan` | |
| | | `validate_fix` | |

## Example Prompts

- `scan anthropic.com` — full security scan with maturity staging
- `check the SPF record for github.com` — individual check
- `compare google.com vs microsoft.com` — head-to-head comparison
- `generate a DMARC record for my-startup.com` — ready-to-publish DNS records
- `simulate attack paths for example.com` — threat modeling from DNS posture
- `map compliance for my-company.com` — NIST/PCI/SOC2/CIS mapping

## Configuration

### Free Tier (default)

No API key needed. 75 scans/day, 200 checks/day, 50 req/min.

### With API Key

Add to your VS Code settings or `.vscode/mcp.json`:

```json
{
  "servers": {
    "blackveil-dns": {
      "type": "http",
      "url": "https://dns-mcp.blackveilsecurity.com/mcp",
      "headers": {
        "Authorization": "Bearer ${input:bv-api-key}"
      }
    }
  },
  "inputs": [
    {
      "id": "bv-api-key",
      "type": "promptString",
      "description": "Blackveil DNS API key",
      "password": true
    }
  ]
}
```

## Requirements

- VS Code 1.99+ with GitHub Copilot Chat
- Internet connection (checks run via hosted Cloudflare Worker)

## Privacy

All checks are **passive and read-only** — they query public DNS records via Cloudflare DNS-over-HTTPS. No authorization is required from the target domain. No data is stored beyond 5-minute result caching.

## Links

- [GitHub](https://github.com/MadaBurns/bv-mcp)
- [Documentation](https://github.com/MadaBurns/bv-mcp/blob/main/docs/client-setup.md)
- [Scoring Model](https://github.com/MadaBurns/bv-mcp/blob/main/docs/scoring.md)
- [Troubleshooting](https://github.com/MadaBurns/bv-mcp/blob/main/docs/troubleshooting.md)

## License

Business Source License 1.1 (converts to MIT on 2030-03-17). See [LICENSE](https://github.com/MadaBurns/bv-mcp/blob/main/LICENSE).
