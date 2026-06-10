# Design: Agent-Chat Caller Principal + Tool Allowlist (bv-mcp side)

**Status:** Implemented · **Date:** 2026-06-10 · **Change class:** A (public contract — new internal caller class)
**Companion spec:** `bv-web-prod` `docs/superpowers/specs/2026-06-10-agentic-chat-integration-design.md` (the consuming side)

## Why this exists

bv-web-prod is adding a customer-facing AI chat agent that calls bv-mcp tools as its
execution backend, over the existing `/internal/tools/*` service-binding path. Today that
path is reached with `BV_WEB_INTERNAL_KEY`, which grants **ungated access to all tools** —
including `query_signins` / `query_ual` (M365 identity telemetry), `osint_*`, and
`scan_buckets_*`. An LLM is choosing the tool name and arguments on the other side.

The bv-web gateway enforces a 13-tool read-only allowlist in-process, but that is a single
in-process check one typo/routing-bug away from putting LLM-controlled arguments on
offensive or identity tooling. This design adds a **second, independent gate on the bv-mcp
side**, keyed to a distinct agent principal, so the trust boundary is enforced in both
workers (defense-in-depth) and audit-tested here where the tool SSOT already lives.

This is the "build bv-mcp first" half of a two-repo feature: the trust boundary must exist
before bv-web calls it.

## Scope

In scope (this repo):
1. A distinct caller principal for the agent path.
2. A server-side allowlist of exactly the 13 read-only tools the agent may call.
3. Enforcement that rejects anything else (and any non-read-only tool) with a 403-style error.
4. An exact-set audit test (reusing the existing allowlist-audit machinery).

Out of scope: the agent loop, prompt, history, domain-scoping, UI — all bv-web-prod.

## The 13 allowlisted tools

All read-only / passive, all present in `TOOL_DEFS`:

```
scan_domain, check_spf, check_dkim, check_dmarc, check_dnssec, check_ssl,
check_mx, check_mta_sts, check_caa, check_http_security,
explain_finding, compare_baseline, get_benchmark
```

Invariant: every member must have `readOnlyHint === true` (or equivalently not be in the
mutating set) — the audit asserts this so a future rename/annotation change can't silently
admit a mutating tool.

## Caller principal

**Decision needed at implementation:** two viable mechanisms —

- **(A) Header assertion** — bv-web sends `X-BV-Caller: agent-chat` on the internal request
  (alongside the existing bearer). bv-mcp's internal layer reads it and applies the agent
  allowlist. Simplest; the header is only trustable *because* it rides the authenticated
  internal binding (no public listener), same trust model the path already relies on.
- **(B) Separate key** — a dedicated `BV_AGENT_KEY` distinct from `BV_WEB_INTERNAL_KEY`,
  so rotating/revoking the agent path doesn't touch the general internal credential. Stronger
  isolation; more secret-management surface.

Recommendation: **(A) for v1** (header assertion), structured so swapping to (B) later is a
localized change. Rationale: the internal path already trusts the binding; the win we need
now is the *tool allowlist*, and (A) delivers it without new secret plumbing. Revisit (B) if
the agent path ever needs independent revocation.

## Enforcement point

In `src/internal.ts`, at the `/internal/tools/call` (and `/internal/tools/batch`) handler:
after auth + body parse, if the request carries the agent-caller signal, validate the
requested tool name against `AGENT_ALLOWED_TOOLS` **before** dispatch to `handleToolsCall`.
Reject with the internal error shape (mirror the existing 4xx pattern in that file) and a
sanitized message (`Invalid tool for caller`). Non-agent internal callers are unaffected.

`AGENT_ALLOWED_TOOLS` is a new exported `Set<string>` SSOT (co-located with the other
internal allowlists, e.g. near `ALLOWED_BATCH_ARGS` / the gated-tools sets).

## Result-format note (informs bv-web, documented here for the contract)

`?format=structured` on `/internal/tools/call` returns raw `CheckResult` JSON **only** for
the `check_*` cohort. The four non-`CheckResult` tools in the allowlist — `scan_domain`,
`explain_finding`, `compare_baseline`, `get_benchmark` (members of `NON_CHECK_RESULT_TOOLS`)
— fall through to MCP-framed `content` blocks even with `format=structured` (see
`test/internal.spec.ts`). bv-web's gateway requests `format=compact` for those four and reads
the text content. No change required here; recorded so the contract is explicit.

## Quota / analytics note

The internal path bypasses per-tool quotas, paid gating, and the distinct-domain cap by
design (bv-web owns entitlement). Agent traffic will therefore not be quota-limited by
bv-mcp, and analytics rows for these calls currently record `authTier: undefined` /
`keyHash: undefined`. **Optional follow-up (not v1-blocking):** stamp an `authTier:'agent'`
or a caller dimension on internal-path analytics so agent volume is attributable. Tracked,
not required for the trust-boundary change.

## Testing

- `test/audits/agent-tool-allowlist.audit.test.ts` (new): assert `AGENT_ALLOWED_TOOLS` is
  exactly the 13 names, every member exists in `TOOL_DEFS`, and every member is read-only.
  Exact-set guard (fails CI if anyone adds/removes a tool without a deliberate edit) — same
  pattern as `gated-tools-ssot.audit.test.ts`.
- `test/internal.spec.ts` additions: agent-caller request for an allowlisted tool succeeds;
  agent-caller request for a non-allowlisted tool (e.g. `query_signins`, `scan_buckets_start`)
  is rejected; non-agent internal caller is unaffected.

## Rollout / coupling

Ship this **before** bv-web-prod starts calling the agent path, so the second gate exists at
launch. Because it adds a recognized caller class to a public-ish contract, it's Change-class
A: changelog entry + a note in the companion bv-web spec. No version-bump-only surfaces are
touched beyond the new audit (which trips the count? no — it's a test, not a tool).
```