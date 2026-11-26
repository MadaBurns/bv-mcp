// SPDX-License-Identifier: BUSL-1.1

/**
 * The MCP `instructions` string returned at `initialize`. This is one of the
 * few channels that actually reaches the model's tool-selection context (unlike
 * `_meta`, which a client surfaces only if it implements filtering), so it is
 * the source of truth for the curated "starter set".
 *
 * The tools flagged `recommended: true` in TOOL_DEFS MUST each be named here —
 * enforced by test/tool-recommended-meta.spec.ts so the `_meta.recommended`
 * wire flag can never drift from the prose the model is actually shown. If the
 * starter set grows, expand BOTH this string and the flags together.
 *
 * It also names the `_meta.paidOnly` wire key (test/tool-paid-only-meta.spec.ts
 * pins that), the async start/poll/fetch pattern, `format` and the cache. Keep
 * those sentences true to the code they describe: GATED_PAID_ONLY_TOOLS and
 * FORCE_REFRESH_DAILY_LIMIT in src/lib/config.ts, resolveToolOutputFormat in
 * src/handlers/tool-output.ts and the TTLs in src/lib/cache.ts and the registry.
 */
export const SERVER_INSTRUCTIONS =
	"DNS and email security scanner. Use scan_domain for comprehensive audits (score, grade, findings). Use individual check_* tools for targeted investigation. Use explain_finding for remediation guidance. Use compare_baseline for policy enforcement. Checks are read-only and never modify a target. Most are passive lookups; check_authoritative_dns_infra and check_root_server_set query authoritative and root nameservers directly over TCP/53, and for authenticated callers check_authoritative_dns_infra also tests whether a domain's nameservers refuse a zone transfer (no zone data is retrieved). " +
	'Long jobs run asynchronously: a *_start tool returns a handle at once (jobId, auditId, scanId or investigationId); pass it to the matching *_status tool until the job completes, then fetch the results with the findings or report tool that the start tool names. ' +
	'Some tools, mainly multi-domain, brand-discovery and reconnaissance tools, need a paid tier (developer or above): tools/list marks each with _meta.paidOnly, and an anonymous, free or agent-tier caller gets a 401 or 403 from them. get_access_context reports your own tier. ' +
	'format: "compact" returns shorter text and is the default for interactive clients; "full" returns everything. ' +
	'Most results are cached for a few minutes and some slower lookups for up to an hour; set force_refresh to rescan, which is limited per day on the free tier.';
