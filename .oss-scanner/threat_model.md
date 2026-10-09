# Threat model for Anthropic OSS Scanner

Free text read by the scanner before it starts (see
<https://red.anthropic.com/oss-scanner/>). It is deliberately short; the
full STRIDE model with a tracked threat inventory lives in
`docs/threat-model/threat-model-20260611-112908/` and `SECURITY.md` carries the
disclosure policy. Dedupe findings against `3-findings.md` in that folder.

## What this project is and where untrusted input enters

Blackveil DNS is a DNS and email-security scanner shipped as a Cloudflare Worker
(Hono v4, TypeScript, no Node APIs at runtime). It exposes ~80 tools over the
Model Context Protocol (JSON-RPC 2.0 over Streamable HTTP) at a **public,
unauthenticated** endpoint, plus an OAuth 2.1 issuer for paid tiers, a
multi-tenant subsystem, and Worker-to-Worker "internal" routes.

Assume all of the following is attacker-controlled:

1. **Every byte of a request to `POST /mcp`, `GET /mcp`, `/mcp/sse`,
   `/oauth/*` and the root `/register`, `/authorize`, `/token` aliases** —
   anonymous internet clients, no account needed. Entry: `src/index.ts`, then
   `src/mcp/request.ts` → `src/mcp/execute.ts` → `src/handlers/tools.ts`.
2. **Everything a scanned domain answers with.** The scanner's whole job is to
   fetch and parse records from a domain the caller names. DNS answers (DoH
   JSON via `src/lib/dns.ts`), TXT policy records (SPF, DMARC, DKIM, BIMI,
   MTA-STS, TLS-RPT), CAA/TLSA/SVCB/HTTPS/SRV/PTR records, HTTP bodies fetched
   from the target (MTA-STS policy, BIMI SVG and VMC, `llms.txt`,
   `robots.txt`, security headers, agent-discovery files), RDAP/WHOIS JSON,
   and certificate-transparency data are all adversarial. Parsers live in
   `packages/dns-checks/src/checks/` (runtime-agnostic core) and
   `src/tools/check-*.ts` (Workers wrappers and orchestration).
3. **URLs discovered inside those records** (SPF `include:`/`redirect=`, BIMI
   `l=`/`a=`, MTA-STS `mx`, HTTP redirects). Any fetch whose host came from a
   scanned record must go through `src/lib/safe-fetch.ts`; direct `fetch` is
   only acceptable for a hostname that already passed `validateDomain()` +
   `sanitizeDomain()` in `src/lib/sanitize.ts`.
4. **OAuth dynamic-client-registration bodies and authorize/token parameters**
   (`src/oauth/`).
5. **Internal-route bodies** (`src/internal.ts`, `src/tenants/`). The caller is
   a trusted sibling Worker holding a per-capability bearer, but request bodies
   are still parsed with Zod and tenant scoping must hold.

## Components that matter most

In priority order:

- `src/lib/sanitize.ts`, `src/lib/config.ts` (blocked IPs/TLDs),
  `src/lib/safe-fetch.ts` — the SSRF boundary. The Worker runs with
  `global_fetch_strictly_public`, but a bypass that lets a scanned record steer
  a fetch to a private address, a service binding, or an arbitrary internal host
  is the top finding class.
- `src/lib/auth.ts`, `src/oauth/*`, `src/lib/session.ts` — the six auth tiers
  (`free`, `agent`, `developer`, `enterprise`, `partner`, `owner`), API-key
  constant-time compare, JWT issuance and revocation, the owner IP gate.
- `src/mcp/execute.ts`, `src/handlers/tools.ts`, `src/lib/rate-limiter.ts`,
  the `QuotaCoordinator` Durable Object — rate limits, per-tier daily quotas,
  the paid-only tool gate (`GATED_PAID_ONLY_TOOLS`), the internal-only gate
  (`INTERNAL_ONLY_TOOLS`), the distinct-domain cap. The policy chokepoint is
  `evaluateToolPolicy` in `src/lib/config.ts`.
- `src/internal.ts` and `src/tenants/` — capability-scoped bearers, tenant
  isolation in D1, idempotency replay protection.
- `packages/dns-checks/src/checks/*` and `src/tools/check-*.ts` — record
  parsers. Bugs here are reachable by anyone who can point the scanner at a
  domain they control.
- `src/lib/json-rpc.ts` (`sanitizeErrorMessage`) and `src/lib/log.ts` —
  information-disclosure boundary.
- `GET /reports/:auditId/:target` and the brand-audit pipeline
  (`src/tools/brand-audit*`, `src/queue/`) — stored, attacker-influenced
  content rendered later.

Lower priority but in scope: `src/scheduled.ts` (cron), `src/workers/`,
`crates/bv-wasm-core` (small wasm-bindgen crate; permissions are generated,
see `scripts/generate-wasm-permissions.ts`), `src/stdio.ts` and `src/cli.ts`.

## Out of scope

- Cloudflare platform behaviour (Workers runtime, KV, D1, R2, DO, the edge
  network). Report to Cloudflare.
- Sibling Workers that are not in this repository (bv-web, bv-recon,
  bv-tls-probe, bv-dns). They are modelled as external trust targets reached
  via service bindings; on a self-host those bindings are absent and the tools
  deliberately answer `unprovisioned`.
- Third-party dependencies, unless this code misuses them.
- `test/`, `scripts/`, `docs/`, `.github/`, `.githooks/`, `.worktrees/` — dev
  tooling and documentation, not shipped. Test fixtures contain fake keys and
  example domains on purpose.
- Denial of service that stays within the documented rate limits and quotas.
- Anything that only "works" because the container has no Cloudflare in front
  of it. In particular, **do not report that `/internal/*` is reachable without
  `cf-connecting-ip`**: that header is set by Cloudflare on every public
  request and its *absence* is the designed Worker-to-Worker signal
  (`isPublicInternetRequest` in `src/internal.ts`). The relevant question is
  whether the per-route bearers and tenant scoping hold once past that guard.

## How to exercise it

- Build: `npm ci && npm run build && npm run build:wasm`. The Dockerfile in this
  directory does this.
- Tests: `node scripts/vitest-filter-workerd.mjs run` runs Vitest **inside the
  Workers runtime** (`@cloudflare/vitest-plugin`). DNS and HTTP are mocked
  through `test/helpers/dns-mock.ts` (`setupFetchMock`, `txtResponse`,
  `nxdomainResponse`, `httpResponse`, ...), so a reproducer for a parser bug is
  a spec that feeds a crafted record through the mock and calls the tool via a
  dynamic import (`const { checkSpf } = await import('../src/tools/check-spf')`).
  Protocol-level reproducers can use `test/helpers/mcp-http-client.ts` against
  the Worker. Note that the audit sandbox has no network, so specs that reach
  real resolvers will fail there regardless of any bug.
- Request shape: `initialize` first (it returns an `Mcp-Session-Id`), then
  `tools/list` / `tools/call`. The strict `MCP-Protocol-Version` header check
  applies only after `initialize`.
- The stdio entrypoint (`dist/stdio.js` after `npm run build`) drives the same
  `executeMcpRequest` path without HTTP, auth, or rate limiting — useful for
  parser bugs, useless for auth or quota bugs.
- Conventions: `CLAUDE.md` and the skills under `.claude/skills/` (especially
  `bv-mcp-security-surface` and `bv-mcp-check-conventions`) describe the
  intended behaviour; where code and those documents disagree, the discrepancy
  itself is worth reporting.

## Severity rubric

- **Critical** — unauthenticated code execution or isolate escape; an SSRF
  bypass that reaches a private address, a service binding, or an attacker-
  chosen internal host from a scanned record or tool argument; an auth bypass
  that yields `owner` tier or any `/internal/*` capability from the public
  internet; disclosure of a binding secret or signing key.
- **High** — tier escalation (unauthenticated or `free`/`agent` reaching a
  paid-only tool, `partner` reaching `owner`); OAuth token forgery, PKCE or
  redirect-URI bypass, token issued to the wrong subject; cross-tenant read or
  write in `src/tenants/`; cross-principal access to recon, batch-scan, or
  brand-audit results by ID; a rate-limit or quota bypass that is not already
  listed below as deliberate; stored or reflected script injection in anything
  rendered to a browser (reports, badge, OAuth consent page); a parser bug that
  turns one request into unbounded fan-out (SPF include recursion, CNAME loops,
  unbounded TXT walks) beyond the per-check fetch budgets.
- **Medium** — DoS or amplification that exceeds the documented budgets but
  needs a crafted target domain (ReDoS in a record parser, catastrophic
  allocation); information disclosure beyond the error-message allowlist in
  `sanitizeErrorMessage`; cache poisoning that lets one domain's result be
  served for another; a fail-open path that is not documented as deliberate.
- **Low** — hardening gaps, missing headers, non-exploitable timing
  differences, logic bugs with no security consequence.

Scoring errors (a wrong grade, a mis-weighted category) are correctness bugs,
not vulnerabilities. Report them only if a scanned domain can *control* its own
score (for example, a record that makes a failing control look present).

## Known and deliberate — do not report

- The per-IP distinct-domain cap is KV best-effort and **fails open** by
  design; it is a cost control, not a security control.
- `?api_key=` is still accepted as a fallback for one legacy client; the reject
  switch (`REJECT_QUERY_API_KEY`) exists and is a deploy-config decision
  (FIND-01 in the June 2026 model).
- OAuth dynamic client registration is open, rate-limited, and tracked
  (FIND-05).
- Unauthenticated callers can scan domains they do not own. That is the
  product. The abuse controls are the paid-only gate on offensive/recon/
  multi-domain tools, the quotas, and the distinct-domain cap.
- Operator-only tool families (`identity_secops`, bv-recon-backed tools) answer
  `unprovisioned` without their binding; that is intended fail-soft behaviour,
  not a bug.
- `REQUIRE_INTERNAL_AUTH=false` is a documented legacy escape hatch limited to
  general internal tools and analytics; the high-trust capabilities ignore it.
- The 9-band internal grade scale versus the 6-band customer-facing scale, and
  an unsigned DNSSEC zone scoring 60 rather than 0, are scoring-model choices.
- Secrets are absent in the sandbox; code paths that read `env.*` and find
  nothing are expected to degrade, not to be reported as misconfiguration.

## Report format and patches

- One report per root cause, not per tool: most `check_*` tools share parsers
  in `packages/dns-checks`, so cite the shared file and list the tools that
  reach it.
- Cite `file:line` at the commit scanned, the untrusted input that reaches it,
  and the concrete request or record that triggers it.
- A reproducer as a Vitest spec using the helpers above is ideal. Name it by
  the pyramid-layer suffix the repo uses (`.spec.ts` for unit tests — these are
  **not** Playwright files — `.integration.test.ts`, `.audit.test.ts`,
  `.chaos.test.ts`).
- Patches: minimal and merge-ready where practical. Put fixes in
  `packages/dns-checks` when the logic is runtime-agnostic and keep its public
  API backward compatible. A `CheckResult` literal must include both
  `passed: boolean` and `findings: [] as Finding[]`. A new client-visible error
  must start with one of the `sanitizeErrorMessage` prefixes or it is replaced
  by a generic message. Formatting is Prettier (tabs, single quotes, 140 cols).
