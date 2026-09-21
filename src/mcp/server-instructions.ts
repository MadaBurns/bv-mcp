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
 */
export const SERVER_INSTRUCTIONS =
	"DNS and email security scanner. Use scan_domain for comprehensive audits (score, grade, findings). Use individual check_* tools for targeted investigation. Use explain_finding for remediation guidance. Use compare_baseline for policy enforcement. Checks are read-only and never modify a target. All but one are passive lookups; check_authoritative_dns_infra additionally queries a domain's nameservers directly and, for authenticated callers, tests whether they refuse a zone transfer (no zone data is retrieved).";
