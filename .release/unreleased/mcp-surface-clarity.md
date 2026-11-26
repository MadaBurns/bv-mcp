---
ref: mcp-surface-clarity
title: Clearer tool descriptions for picking the right tool and following async jobs
bump: minor
plugins: []
---

### Added

- `tools/list` marks each paid-only tool with `_meta.paidOnly: true`, derived from the same set the paid-tier gate uses, so an agent on the free tier can tell before calling which tools it will be refused. The field is omitted on every other tool. Which tools are listed, the gate itself and its refusal text are unchanged.
- MCP protocol version `2025-11-25` is supported alongside `2025-06-18` and `2025-03-26`: `initialize` negotiates it when asked, a later request may carry it in `MCP-Protocol-Version`, and it gets the same `structuredContent`-only results as `2025-06-18`. It is now the latest version, so a client that omits `protocolVersion` or asks for an unsupported one is offered `2025-11-25` instead of `2025-06-18`. Nothing in the 2025-11-25 changelog requires behaviour this server lacks: it already answers a bad `Origin` with 403, returns tool-argument errors as `isError` results and sends `serverInfo.description`; tasks, icons, elicitation, sampling tools and SSE polling are optional or client-side.
- `resources/templates/list` returns an empty `resourceTemplates` list instead of "Method not found"; the server advertises the `resources` capability and has only fixed-URI resources.

### Changed

- The `initialize` instructions keep the starting tools and the read-only disclosure, and now also explain the async pattern (start, poll the status tool with the returned handle, fetch the findings or report), that paid-only tools are marked `_meta.paidOnly` and `get_access_context` reports the caller's tier, that `format: "compact"` gives shorter text, and that results are cached unless `force_refresh` is set.
- A request rejected for an unsupported `MCP-Protocol-Version` header now gets an error that names the value received and the supported versions, carries both in `error.data`, and echoes the request id when the body is a single request. The HTTP status (400) and JSON-RPC code (`-32600`) are unchanged.
- `check_mx_reputation` and `check_rbl` now describe what each actually queries. `check_mx_reputation` checks up to 3 MX hosts against SpamCop and Barracuda and verifies reverse DNS; it no longer names Spamhaus or SORBS, neither of which it queries, nor says `check_rbl` takes an IP. `check_rbl` says it takes a domain, resolves the MX hosts (or A records) to IPv4 addresses and queries 6 blocklists.
- `discover_brand_domains_start` says to pass the `auditId` it returns as `operationId` to `discover_brand_domains_status` and `discover_brand_domains_findings`.
- `explain_finding` says where its inputs come from (a finding from `scan_domain` or a `check_*` tool) and what it returns.
- `batch_scan`, `batch_scan_start`, `batch_scan_status` and `batch_scan_findings` name each other, the job states, owner scoping, the 7-day result window and what to put in `idempotency_key`.
- Every OSINT start tool names both `osint_investigation_status` and `osint_investigation_report`, and the OSINT and bucket-scan start tools say their handle is valid for 24 hours.
- `check_txt_hygiene`, `check_resolver_consistency` and `check_nsec_walkability` say when to use them and how they differ from their neighbours.
- The shared `format` parameter says `compact` gives less text. The shared `domain` and `force_refresh` descriptions and the scan suffix ("Part of scan_domain.") are shorter, and the bucket and OSINT pollers no longer repeat the watchlist rule that applies to their start tool, so the `tools/list` response stays inside its unchanged size budget (98,234 characters before; 98,479 with the descriptions and the `paidOnly` flags, against a ceiling of 98,500).
- Only description text changed: tool names, argument names and schemas, output schemas, annotations and results are the same.
