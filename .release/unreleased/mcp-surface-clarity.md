---
ref: mcp-surface-clarity
title: Clearer tool descriptions for picking the right tool and following async jobs
bump: patch
plugins: []
---

### Changed

- `check_mx_reputation` and `check_rbl` now describe what each actually queries. `check_mx_reputation` checks up to 3 MX hosts against SpamCop and Barracuda and verifies reverse DNS; it no longer names Spamhaus or SORBS, neither of which it queries, nor says `check_rbl` takes an IP. `check_rbl` says it takes a domain, resolves the MX hosts (or A records) to IPv4 addresses and queries 6 blocklists.
- `discover_brand_domains_start` says to pass the `auditId` it returns as `operationId` to `discover_brand_domains_status` and `discover_brand_domains_findings`.
- `explain_finding` says where its inputs come from (a finding from `scan_domain` or a `check_*` tool) and what it returns.
- `batch_scan`, `batch_scan_start`, `batch_scan_status` and `batch_scan_findings` name each other, the job states, owner scoping, the 7-day result window and what to put in `idempotency_key`.
- Every OSINT start tool names both `osint_investigation_status` and `osint_investigation_report`, and the OSINT and bucket-scan start tools say their handle is valid for 24 hours.
- `check_txt_hygiene`, `check_resolver_consistency` and `check_nsec_walkability` say when to use them and how they differ from their neighbours.
- The shared `format` parameter says `compact` gives less text. The shared `domain` and `force_refresh` descriptions and the scan suffix ("Part of scan_domain.") are shorter, and the bucket and OSINT pollers no longer repeat the watchlist rule that applies to their start tool, so the `tools/list` response stays inside its size budget (98,234 to 98,063 characters).
- Only description text changed: tool names, argument names and schemas, output schemas, annotations and results are the same.
