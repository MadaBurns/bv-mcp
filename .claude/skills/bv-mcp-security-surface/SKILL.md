---
name: bv-mcp-security-surface
description: Use when touching bv-mcp's request-security surface — SSRF and safeFetch, the six auth tiers and BV_API_KEY/JWT resolution, rate limits and per-tier daily quotas, paid-only tool gating, the distinct-domain cap, sessions, the /internal/* route capabilities and their bearer keys, OAuth plan→tier mapping, client-visible error wording, MCP protocol-version handling, or fuzzing detection. Symptoms — an unexpected 401/403/404/405/429/503 from /mcp or /internal, a client that connected yesterday and 400s today, a new error string reaching users as a generic fallback, "which key does this internal route want", owner tier silently downgraded to partner, or adding a tool that must be paid-only.
---

# bv-mcp Security Surface

Everything a request passes through before a tool runs. `CLAUDE.md` carries only
the pointer; this is the detail. For *bindings* and their failure semantics see
**bv-mcp-operations**; for who may merge/deploy see **fleet-change-control**.

## SSRF

Blocked IPs/TLDs live in `lib/config.ts`, enforced by `lib/sanitize.ts`. Every
domain input goes through `validateDomain()` + `sanitizeDomain()` **after** Zod.
All outbound fetches use `redirect: 'manual'`.

⚠️ **Attacker-controlled URLs MUST use `safeFetch`** (`lib/safe-fetch.ts`) — BIMI
`l=`/`a=`, redirect targets, anything whose host came from a scanned record. A
fetch to an already-validated hostname may use raw `fetch` with manual redirects.
The distinction is where the hostname came from, not how the URL is spelled.

## Auth: six tiers

`free`, `agent`, `developer`, `enterprise`, `partner`, `owner`.

- Static `BV_API_KEY`, compared constant-time (XOR). Token read from
  `Authorization: Bearer`, then `?api_key=` (a Smithery fallback).
- ⚠️ **Owner tier is IP-gated**: client IP ∉ `OWNER_ALLOW_IPS` → silently
  downgraded to `partner`, *including on the OAuth JWT path*. A custom domain in
  front of the Worker masks the IP, so an owner key can present as partner for
  reasons that have nothing to do with the key. Test against the workers.dev URL.
- JWT tiers are limited to `JwtIssuableTierSchema` (`owner|developer|enterprise`)
  — `partner`/`agent` over JWT → 401.
- The JWT path returns a `keyHash`, so quota and concurrency key on the
  **credential**, not the IP (3.15.1).

**Paid OAuth tiers** (bv-web plan → tier claim → limits), resolved in
`src/oauth/entitlements.ts` via the bv-web binding:

| bv-web plan | tier | scans/day | concurrent |
|---|---|---|---|
| free / starter | (none) | 50 | 3 |
| pro / business / MCP Developer | `developer` | 500 | 10 |
| enterprise / MCP Enterprise | `enterprise` | 10,000 | 25 |

`agent` (200/day, 5) is reachable **only** via bv-web `validate-key`. Static
`BV_API_KEY` → `owner`, subject to the IP gate above.

## Rate limits and quotas

- Unauthenticated: **50/min, 300/hr per IP**; only `tools/call` counts.
- Authenticated bypasses the per-IP limit but pays per-tier daily quotas.
- Per-tool: `FREE_TOOL_DAILY_LIMITS` (`check_mx_reputation` 5/day + 60-min cache).
- Global cap `GLOBAL_DAILY_TOOL_LIMIT` 500k/day via the `QuotaCoordinator` DO.
- **Distinct-domain cap**: unauthenticated per-IP distinct domains/day
  (`FREE_DISTINCT_DOMAIN_DAILY_LIMIT`, currently 12; KV best-effort, **fail-open**)
  → HTTP **429** + `x-quota-*` headers.

**Paid-only tools**: offensive / recon / multi-domain tools listed in
`GATED_PAID_ONLY_TOOLS` (`lib/config.ts`) are developer+ only —
free/unauth/agent get HTTP **403** `UPGRADE_REQUIRED` (`-32003`). OSINT and
bucket pollers stay free. The SSOT is audited by
`gated-tools-ssot.audit.test.ts`, so adding a tool to the list without updating
the audit's expectations fails the build.

⚠️ Free-tier paid-gating and the distinct-domain cap are **public-`/mcp` only**.
The internal path bypasses both — bv-web enforces paid entitlement before it
forwards.

## Request envelope

- **Body**: 10 KB on `/mcp`.
- **IP source**: `cf-connecting-ip` **only**. Never `x-forwarded-for` — it is
  client-settable, and reading it is how an attacker picks their own rate-limit
  bucket.
- **Origin**: MCP-compliant rejection of unauthorized browser `Origin`;
  `ALLOWED_ORIGINS` is configurable.

## Sessions

Idle TTL 2h sliding, KV + in-memory dual-write. Missing session → **400**;
expired → **404**. Creation limited to 30/min per IP. IDs are exactly 64
lowercase hex. `DELETE /mcp` accepts the `Mcp-Session-Id` **header only**.
`SESSION_CREATE_BY_IP` is LRU-capped at 5000; `LEGACY_STREAMS` at 500.

## `/internal/*` route capabilities

The route family is guarded by `cf-connecting-ip` **presence**
(`isPublicInternetRequest()`) — a request from the public internet gets **404**,
not 401, so the surface does not advertise itself.

Beyond that guard the capabilities are **distinct keys, not one shared secret**:

| Key | Capability |
|---|---|
| `BV_WEB_INTERNAL_KEY` | general web tools + analytics |
| `BV_MOBILE_INTERNAL_KEY` | scan-only mobile calls |
| `BV_MCP_TENANT_KEY` | tenant orchestration |
| `BV_MCP_TOOL_DELEGATION_KEY` | web Brand Watch register/list/delete |
| `BV_MCP_WATCH_CLEANUP_KEY` | ops-only list/delete |
| `BV_MCP_OAUTH_MINT_KEY` | grants / trial issuance |
| `BV_MCP_OAUTH_REVOKE_KEY` | subject revocation |

- High-trust capabilities require **at least 32 UTF-8 bytes** and **fail closed
  on secret reuse** — two capabilities sharing a value is a startup failure, not
  a warning.
- **Missing** route credential → **503**. **Wrong** credential → **401**.
- ⚠️ The legacy `REQUIRE_INTERNAL_AUTH=false` escape hatch applies **only** to
  general tools/analytics. Tenant delegation/orchestration, OAuth/trial
  administration, and forensics/erasure always enforce their dedicated bearer.
- `X-Tenant` + `X-Auth-Tier` are accepted **only** with one of the two narrow
  tenant capabilities; the fleet web key is rejected for them.
- Mutating calls support durable `Idempotency-Key` replay protection.

## Client-visible error wording is an ALLOWLIST

`sanitizeErrorMessage()` (`lib/json-rpc.ts`) passes a message through only if it
starts with one of: `'Missing required'`, `'Invalid'`, `'Domain '`,
`'Resource not found'`, `'Rate limit exceeded'`. Anything else becomes a generic
fallback.

⚠️ So **a new client-visible error must start with one of those prefixes** or it
silently disappears into the fallback and the user learns nothing. This is the
usual reason a freshly added, carefully worded error message "doesn't show up".

Rate limiting specifically: HTTP **429** + JSON-RPC `-32029` in the body
(`useErrorEnvelope`), `retry-after` set. **Every** rate-limit/quota path in
`mcp/execute.ts` returns `httpStatus: 429` — asserted by `test/index.spec.ts`.

## Protocol-version handling — two channels, OPPOSITE postures

1. `initialize` params `protocolVersion` — **LENIENT**. Negotiated, never
   rejected.
2. The `MCP-Protocol-Version` **HTTP header** on post-init requests — **STRICT**.
   Unsupported → warn + **HTTP 400**. Absent → accepted. `initialize` exempt.
   (Verified live 2026-08-04.)

⚠️ **A client that suddenly 400s only after `initialize` has a header problem,
not a bug.** `SUPPORTED_PROTOCOL_VERSIONS` lives in `src/mcp/dispatch.ts`.

Related SSE gate: `GET /mcp` runs `acceptsSSE()` (`src/lib/sse.ts`) **before**
the session check, accepting `text/event-stream` or an RFC 9110 wildcard. A
non-SSE `Accept` → **405** + `Allow: GET, POST` (per MCP 2025-06-18 — **not**
406). Past the gate with no session → **400**. Legacy `GET /mcp/sse` behaves the
same.

## Fuzzing detection

Pattern-based over `unknown_tool`, `unknown_method`, `zod_arg`, `auth_fail`; a
15-min cron raises and resolves a webhook alert. Files: `lib/fuzzing-detector.ts`,
`lib/fuzzing-counter.ts`, `schemas/alerting.ts`, and `handleFuzzingScan` in
`scheduled.ts`. Thresholds are `FUZZ_THRESHOLDS` in `lib/config.ts` and are
audit-enforced.

## Red flags

- "My new error message shows as a generic failure" → it does not start with an
  allowlisted prefix.
- "The owner key behaves like partner" → the IP gate; you are probably going
  through the custom domain rather than workers.dev.
- "The client worked yesterday, now every call after initialize 400s" → the
  strict `MCP-Protocol-Version` header channel.
- "`/internal/...` returns 404 from my machine" → correct; that guard is
  `cf-connecting-ip` presence, and it is meant to look absent.
- "503 on an internal route" → the credential is **missing**, not wrong. 401 is
  wrong-credential.

## Provenance

Split out of `CLAUDE.md` 2026-09-11, verbatim, when that file was trimmed back to
pointers (it had reached 28,897 B / ~7.2k tokens loaded unconditionally in every
session). No content was dropped in the move. Per the fleet rule in
`cc-repo-operations` §7.1: depth belongs in a skill that loads on description
match, CLAUDE.md carries the pointer.
