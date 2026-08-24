# CLAUDE.md

Guidance for Claude Code working in this repo. This file carries the big picture and the gotchas that bite during ordinary tasks; depth lives in the repo skills (`.claude/skills/`): **bv-mcp-add-tool**, **bv-mcp-release**, **bv-mcp-scoring**, **bv-mcp-testing**, **bv-mcp-operations**.

## What is this?

Blackveil DNS — source-available DNS & email security scanner, built as a Cloudflare Worker.
76 public tools (81 registered in `TOOL_DEFS`; 5 internal-only via `INTERNAL_ONLY_TOOLS` — `map_csc_products` + the four `identity_secops` M365 tools, withdrawn 3.63.0) exposed via MCP Streamable HTTP (JSON-RPC 2.0) at `https://dns-mcp.blackveilsecurity.com/mcp`. Source of truth: `TOOL_DEFS` in `src/schemas/tool-definitions.ts`. `check_subdomain_takeover` is directly callable AND runs inside `scan_domain` (a `scanIncluded: false` special slot in `CHECK_DISPATCH`). Listed on the MCP Registry as `com.blackveilsecurity/dns`.

**Version sync is automatic** — `npm version <X.Y.Z>` runs a lifecycle hook that syncs `server.json` + the `CHANGELOG.md` heading and stages them. Do not hand-edit those, `SERVER_VERSION`, or `package-lock.json` versions. Full surface list + release flow: **`bv-mcp-release` skill** (and `bv-mcp-operations` → "Version-sync surfaces").

## Commands

```bash
npm ci
npm test                                    # Vitest in Workers runtime (via scripts/vitest-filter-workerd.mjs — strips pool-teardown noise)
npx vitest run test/check-spf.spec.ts       # Single spec
npm run build                               # tsup (npm pkg + stdio CLI)
npx wrangler dev                            # localhost:8787
npm run typecheck                           # tsc --noEmit
npm run lint[:fix]
npm run deploy:prod                         # Inject private bindings + deploy
npm run check:tool-surface                  # Verify advertised tool counts match TOOL_DEFS
npm run generate:tool-surface               # Rewrite them from the registry (run after adding/removing a tool)
git config core.hooksPath .githooks         # One-time hook setup
scripts/worktree-setup.sh                   # New worktree: verify Node 22, npm ci, build dns-checks
```

**Never symlink `node_modules`** into a new worktree — use `scripts/worktree-setup.sh` (or plain `npm ci`). A symlink resolves the `@blackveil/dns-checks` workspace package to the OTHER checkout's tree, so your tests silently validate code you did not write (how #576 reached `main`). A pre-commit gate + CI `symlink-portability` job now block staged/tracked symlinks. Incident detail: `bv-mcp-operations` skill.

## Tech

- **Runtime**: Cloudflare Workers — no Node.js APIs (`fetch`, `crypto`, Web only)
- **Framework**: Hono v4 · **TypeScript**: strict, ES2024, Bundler resolution, `isolatedModules`
- **Testing**: Vitest + `@cloudflare/vitest-pool-workers` (tests run inside Workers runtime)
- **Tooling Node**: 22+ (Wrangler 4.x hard-fails on <22)
- **Formatter**: Prettier (tabs, single quotes, semi, 140 width)
- **Package mgr**: npm

## Architecture

### Monorepo

npm workspace. Root = Cloudflare Worker. `packages/dns-checks` (`@blackveil/dns-checks`) is the runtime-agnostic core, published separately and consumed via npm.

**Entrypoints**: `src/index.ts` (Worker/Hono), `src/package.ts` (npm), `src/stdio.ts` (CLI), `src/internal.ts` (service binding), `src/scheduled.ts` (cron).

### Source layout (orientation only)

```
src/mcp/         — Protocol: execute, dispatch, request parsing, route gates
src/schemas/     — Zod schemas: primitives, tool-args + TOOL_SCHEMA_MAP, tool-definitions, json-rpc, internal, dns, session, auth
src/handlers/    — tools/list+call, resources, prompts, tool-args/-formatters
src/tools/       — check-*, scan-domain, scan/ helpers, discover-subdomains, map-*, analyze-drift, etc.
src/oauth/       — OAuth 2.1 issuer (discovery, register, authorize, token, JWT, KV storage)
src/tenants/     — Multi-tenant subsystem (production-live)
src/lib/         — scoring (model/engine/config), context-profiles, adaptive-weights, dns, sanitize, safe-fetch,
                   cache, session, rate-limiter, json-rpc, auth, analytics, client-detection, fuzzing-*, log,
                   db/schema (Drizzle)
test/            — Flat by source file. Pyramid layer = filename suffix (.spec.ts, .integration.test.ts,
                   .audit.test.ts, .contract.test.ts, .chaos.test.ts). Subdirs: helpers/, schemas/, oauth/,
                   audits/, contracts/, chaos/
packages/dns-checks/  — Runtime-agnostic core: scoring/ + checks/ + schemas/
```

### Layering

- **`packages/dns-checks/`**: runtime-agnostic core. No Cloudflare deps. Add here if logic could run outside Workers.
- **`src/tools/`**: MCP wrappers + orchestration needing Workers features (KV, DO, bindings). Depends on `@blackveil/dns-checks` via npm — keep backward compat.

Both publish together via the manual `npm publish` path (npm publish currently gated off — #719); `publish.yml` no longer carries publish jobs.

### Operator-only tool families

- **Recon tools** (11: `check_realtime_threat_feed`, `scan_buckets_*`, `osint_investigate_*`/`osint_investigation_*`) call bv-recon via the `BV_RECON` binding (`src/lib/recon-binding.ts`); fail-soft → `unprovisioned` on BSL self-hosts. Async tools use start → poll (`*_status`) → retrieve (`*_findings`/`*_report`). `cymru_asn`/`check_lookalikes`/`check_fast_flux` gain optional enrichment when bound.
- **M365 identity_secops tools** (4, withdrawn from the public catalog in 3.63.0, `INTERNAL_ONLY_TOOLS`, tenant reads fail-closed). ⚠️ The internal-only gate short-circuits BEFORE tier branching and shadows the `AUTH_REQUIRED_TOOLS` 401 path; deleting their `TOOL_DEFS` entries would delete the auth gate and seam contracts derived from them. Full detail: **`bv-mcp-operations` skill**.

### Request flow

- **Streamable HTTP**: `POST /mcp → Origin → Auth → Body → JSON-RPC validate → mcp/execute → handlers/tools → src/tools/check-* → lib/dns → DoH (empty → bv-dns → Google)`
- **Streamable HTTP SSE**: `GET /mcp` opens the notification stream. The `Accept`-gate (`acceptsSSE()` in `src/lib/sse.ts`) runs **before** the session check and accepts `text/event-stream` OR an RFC 9110 wildcard; a non-SSE `Accept` → **`405`** + `Allow: GET, POST` (per MCP 2025-06-18 — NOT 406). Past the gate with no session → `400`. Legacy `GET /mcp/sse` (deprecated) behaves the same.
- **Stdio**: `stdin → src/stdio → mcp/execute → handlers/tools → stdout`
- **Internal binding**: `POST /internal/tools/{call,batch} → guard (reject public) → handlers/tools → JSON (no MCP framing)`

### scan_domain orchestration

19 scan categories in parallel via `Promise.allSettled` (18 registered scan-included tools + internal `subdomain_takeover`). Cache keys: `cache:<domain>:check:<name>` + top-level `cache:<domain>`, 5 min TTL (`cacheTtlSeconds` override); `force_refresh` → `skipCache`. Timeouts: scan 15s preserves partial results; per-check 8s (`SCAN_TIMEOUT_MS` env-overridable, clamped [5s, 30s]).

- **Maturity staging**: `computeMaturityStage()` 0–4. The score cap reads the **displayed NIST 6-band** letter (`nistScoreToGrade`), never the internal 9-band (#640: grade D printed beside "Stage 4 — Hardened"). `indeterminate` is never capped; the capped label is worded by the same `ladderForProfile()` that produced the stage.
- **Subrequest ceiling**: a cold scan fans out ~20 subrequests/domain; the scanner-queue consumer measurably overran the paid 10,000/invocation ceiling at `max_batch_size: 100` (now 25 — do not raise without chunking). Full incident + Free-plan guidance: **`bv-mcp-operations` skill**.
- **Post-processing**: Non-mail (no MX) downgrades email-auth findings to `info` **only under inherited DMARC enforcement** — ⚠️ the parent `sp=`/`p=` `quarantine|reject` condition is LOAD-BEARING (#643: ungated it hands a clean pass to spoofable domains, +7 to +23 points on ~28.6% of domains). Apex domains never qualify — correct, not a gap. No-send (SPF `noSendPolicy`) downgrades DKIM/MTA-STS/BIMI missing-record findings to `info`; BIMI rewritten for non-mail domains.
- **Output**: prose + `structuredContent` (always) + a legacy `<!-- STRUCTURED_RESULT -->` comment that `stripRedundantStructuredComment()` (`src/mcp/dispatch.ts`) drops only for clients proven to read `structuredContent` — the `clientType` allowlist is the load-bearing safeguard. Full gating rules: **`bv-mcp-operations` skill**.

### Output format control

`format` param (`full` | `compact`), auto-detected from client type: interactive LLM → `compact`, else `full`. Resolution in `extractFormat(args)` (tool-args.ts) → explicit wins, else `resolveFormat()` from `clientType`.

## Conventions

- **Zod**: Centralized in `src/schemas/`. Tool `inputSchema` via `z.toJSONSchema()` (Zod v4). Runtime: `validateToolArgs()`. Use `.passthrough()` and `.transform().pipe()` for case-insensitive enum normalization.
- `createFinding()` + `buildCheckResult()` from `@blackveil/dns-checks/scoring` — never construct findings manually. `createFinding()` auto-sanitizes `detail`.
- **Before concluding a control is unimplemented, grep the whole package** — emission is not uniform: DMARC is the sole check that delegates to a classifier (`packages/dns-checks/src/scoring/classifiers/dmarc.ts`); every other check emits inline or via a sibling `*-analysis.ts`. Confirm with a category-wide grep of `createFinding(`/`buildCheckResult(` call sites, never file layout.
- `validateDomain()` + `sanitizeDomain()` from `lib/sanitize.ts` for all domain inputs (after Zod) — SSRF/blocklist.
- `mcpError()` / `mcpText()` from `handlers/tool-formatters.ts`.
- `cacheGet/Set/SetDeferred/runWithCache` from `lib/cache.ts`. `cacheSetDeferred` wraps in `ctx.waitUntil()`.
- **Mutating-tool request-dedup**: `handleToolsCall` wraps mutating `*_start`/`register_*` tools in `withRequestDedup` (`lib/request-dedup.ts`, ~90s KV window keyed `sha256(principal + tool + canonicalArgs)`). Set `MUTATING_DEDUP_TOOLS` derives from annotations; exact-set test `test/request-dedup-wiring.spec.ts`. Invariants: store-on-success only; key on `runtimeOptions.keyHash` ONLY — never fall back to `principalId`, whose `ipHash` would replay operation IDs cross-principal (fixed 3.15.1).
- JSDoc on exports; `import type { ... }` for type-only.
- Tool functions: `Promise<CheckResult>` + optional `dnsOptions?: QueryDnsOptions`. Follow `check-spf.ts`.
- **DNS-failure resilience**: directly-callable tools catch top-level DNS errors and return `buildDnsErrorResult(category, label, err)` (`lib/dns-error-result.ts`) — same shape as `safeCheck`: `checkStatus: 'error'` + `score: 0` + `partial: true` + a `high` finding with `errorKind: 'dns_error'`. The `checkStatus` shape (NOT `missingControl`) is what lets the transient-zero retry fire and scoring EXCLUDE the category; `partial: true` keeps it out of the 5-min cache.
- **Per-check fetch budgets (#641/#674)**: `createFetchBudget(budgetMs)` (`src/lib/fetch-budget.ts`) opens ONE deadline per check; `.wrap(fetchFn)` composes (never substitutes) each fetch with the remainder; absent `budgetMs` (direct calls) → identity. Budgeted checks: `ssl`, `http_security`, `mta_sts`, `subdomain_takeover`. ⚠️⚠️ **Budgeting a check is a CORRECTNESS change, not latency** — read what the check does when a fetch throws before wiring one: a cut probe must WITHHOLD its clean verdict (subdomain_takeover) or return the retryable `'error'` class (mta_sts), never record a confident finding for a probe never issued. ⚠️ A `fetch` wrapper does NOT cover service bindings (check_ssl's bv-tls-probe call needed `budget.signal()` separately). Where a check has its own total-budget `Promise.race`, arm it strictly BEHIND the fetch budget (`BUDGET_RACE_MARGIN_MS`). Full incident lore in the in-code comments at those sites.
- **Serial-DoH cost is a DIFFERENT defect — bounded parallelism, not a fetch budget** (`mapConcurrent` + a named per-check constant). ⚠️ `SCAN_DNS_CONCURRENCY = 12` is shared and zero-sum across 19 categories — keep pools at or below the width the check already used. ⚠️ **`spf`, `ns`, `caa` are NOT candidates**: `spf`'s and `subdomailing`'s mid-iteration caps make DFS ORDER load-bearing on scored findings (parallelizing = a scoring change; measured 90 → 60); pinned by `test/check-subdomailing-parity.spec.ts`.
- **`batch_scan`**: `budgetMs` default 25s, `concurrency` default 3, per-domain `Promise.race`. Exceeded → `error: 'batch_budget_exceeded'`.
- `check_mx` is **dynamically imported** in `handlers/tools.ts` (mock isolation).
- MCP server key `"blackveil-dns"` everywhere. `tools/call` accepts `scan` as alias for `scan_domain`. SSRF constants in `lib/config.ts`.
- **`CheckResult` literal**: include both `passed: boolean` AND `findings: [] as Finding[]` — bare `findings: []` infers `never[]` and breaks CI after dns-checks DTS rebuild.
- **`.spec.ts` in this repo** = Vitest unit/integration, NOT Playwright E2E. New mock-D1 integration files → `*.integration.test.ts`.

### Error surfacing

`sanitizeErrorMessage()` (`lib/json-rpc.ts`) allowlists prefixes: `'Missing required'`, `'Invalid'`, `'Domain '`, `'Resource not found'`, `'Rate limit exceeded'` — anything else → generic fallback; new client-visible errors must start with one. Rate limit: HTTP **429** + JSON-RPC `-32029` in the body (`useErrorEnvelope`), `retry-after` set; ALL rate-limit/quota paths in `mcp/execute.ts` return `httpStatus: 429` (asserted by `test/index.spec.ts`).

### Protocol-version handling

Two channels, **different postures**: (1) `initialize` params `protocolVersion` is LENIENT (negotiated, never rejected); (2) the `MCP-Protocol-Version` HTTP header on post-init requests is **STRICT** — unsupported → warn + **HTTP 400**, absent → accepted, `initialize` exempt (verified live 2026-08-04). A client's sudden post-init 400 is a header problem, not a bug. `SUPPORTED_PROTOCOL_VERSIONS` in `src/mcp/dispatch.ts`.

## Scoring

Three-tier model (`computeScanScore`): **Core 70%** (DMARC 16, DKIM 10, SPF 10, DNSSEC 10, SSL 8 in the representative `mail_enabled` profile — every core weight is per-profile), **Protective 20%**, **Hardening 10%** (bonus-only). Six profiles in `packages/dns-checks/src/scoring/profiles.ts`. Override via `SCORING_CONFIG` env (parsed by memoized `parseScoringConfigCached()`). `CATEGORY_DISPLAY_WEIGHTS` is display-only. Full rule set, incident evidence, corpus measurements, and the weight-change checklist: **`bv-mcp-scoring` skill**. Four traps restated because they bite during tasks that never mention "scoring":

- ⚠️ **Measuring DNSSEC across a corpus: test `dnssec > 60`, NEVER `> 0`.** An unsigned zone sits at exactly 60 (fixed `penaltyOverride: 40`, not a zeroing) — `> 0` reports ~95–100% adoption against a true single-digit rate. Read `recordPresent`/`controlPresent` instead.
- ⚠️ **`missingControl` = "we MEASURED and the control is absent"; `inconclusive` + `errorKind` = "the probe never reached the origin".** Never both on one finding — recording a blocked/cut probe as absence zeroes a category nobody measured.
- ⚠️ **`SCORING_CONFIG.coreWeights` is INERT on the scan path** (parses, validates, changes no score — was live in prod undetected for months). Express overrides as `profileWeights.<profile>` (per-profile!). Any weight change re-grades every customer: an operator decision.
- ⚠️ **`passed` = `score >= 50 && !hasMissingControl`** — "did not penalize", NOT "control exists". Three surfaces have misread it as a verdict.
- **Grades — TWO scales by role**: canonical 9-band `scoreToGrade` internal; customer-facing 6-band NIST via the ONE chokepoint `displayGradeFor` (`src/lib/ungraded-display.ts`), which returns `null` for ungraded scans (never fabricate an F).
- **Severity penalties**: C −40, H −25, M −15, L −5, Info 0.
- **Adaptive weights**: EMA per profile+provider via `ProfileAccumulator` DO, blended past `MATURITY_THRESHOLD = 200`; falls back to static.

## Security

- **SSRF**: blocked IPs/TLDs in `config.ts`, enforced by `sanitize.ts`. All outbound `redirect: 'manual'`. **Attacker-controlled URLs** (BIMI `l=`/`a=`, redirect targets) MUST use `safeFetch` (`lib/safe-fetch.ts`); fetches to already-validated hostnames may use raw `fetch` with manual redirects.
- **Auth**: static `BV_API_KEY` (constant-time XOR); token from `Authorization: Bearer`, then `?api_key=` (Smithery fallback). Six tiers: `free`, `agent`, `developer`, `enterprise`, `partner`, `owner`. Owner-tier IP gate: client IP ∉ `OWNER_ALLOW_IPS` → downgrade to `partner` (including OAuth JWT path). JWT tiers limited to `JwtIssuableTierSchema` (`owner|developer|enterprise`); the JWT path returns a `keyHash` so quota/concurrency key on the credential, not the IP (3.15.1).
- **Rate limits**: 50/min, 300/hr per IP (unauthenticated; only `tools/call` counts). Authenticated bypasses per-IP; per-tier daily quotas apply. Per-tool: `FREE_TOOL_DAILY_LIMITS` (`check_mx_reputation` 5/day + 60-min cache). Global cap `GLOBAL_DAILY_TOOL_LIMIT` 500k/day via `QuotaCoordinator` DO.
- **Paid-only tools**: offensive/recon/multi-domain (`GATED_PAID_ONLY_TOOLS` in `config.ts`) are developer+ only — free/unauth/agent → HTTP **403** `UPGRADE_REQUIRED` (-32003). OSINT/bucket pollers stay free. SSOT audited by `gated-tools-ssot.audit.test.ts`.
- **Distinct-domain cap**: unauthenticated per-IP distinct-domains/day (`FREE_DISTINCT_DOMAIN_DAILY_LIMIT`, currently 12, KV best-effort fail-open) → HTTP **429** + `x-quota-*` headers.
- **Body**: 10 KB on `/mcp`. **IP source**: `cf-connecting-ip` only (never `x-forwarded-for`). **Origin**: MCP-compliant rejection of unauthorized browser `Origin`; `ALLOWED_ORIGINS` configurable.
- **Sessions**: idle TTL 2h sliding, KV + in-memory dual-write. Missing → 400; expired → 404. Creation 30/min per IP. IDs exactly 64 lowercase hex. `DELETE /mcp` accepts `Mcp-Session-Id` header only. `SESSION_CREATE_BY_IP` LRU-capped 5000; `LEGACY_STREAMS` capped 500.
- **Paid OAuth tiers** (bv-web plan → tier claim → limits): free/starter → none (50 scans/day, 3 concurrent); pro/business/MCP Developer → `developer` (500/day, 10); enterprise/MCP Enterprise → `enterprise` (10,000/day, 25). Resolution in `src/oauth/entitlements.ts` via the bv-web binding; static `BV_API_KEY` → `owner` (IP-gated). `agent` (200/day, 5) reachable only via bv-web `validate-key`.
- **Internal routes**: `/internal/*` guarded by `cf-connecting-ip` presence (`isPublicInternetRequest()`); public → 404. Bearer gates: credential-minting routes (`/internal/trial-keys/*`, `/internal/oauth/grants`) are STRICT (503 if `BV_WEB_INTERNAL_KEY` unset; 401 on missing/wrong). `/internal/tools|analytics|tenants/*` use `internalLenientAuthGate` — despite the name **secure-by-default** (ACTIVE unless `REQUIRE_INTERNAL_AUTH=false`). `/internal/analytics/forensics` is STRICT-gated (decrypts client IP + PTR; writes a self-audit row to `mcp_access_log_audit` in `INTELLIGENCE_DB`); operator-only.
- **Fuzzing detection**: pattern-based (`unknown_tool`, `unknown_method`, `zod_arg`, `auth_fail`), 15-min cron → resolved alert webhook. Files: `lib/fuzzing-detector.ts`, `lib/fuzzing-counter.ts`, `schemas/alerting.ts`, `handleFuzzingScan` in `scheduled.ts`. Thresholds `FUZZ_THRESHOLDS` in `lib/config.ts` (audit-enforced).

## Adding a New Tool

**First decide: scored or standalone?** A **scored** check gets a `CheckCategory` and MUST be `scanIncluded: true` + wired into `scan_domain` — otherwise it sits in the scoring denominator at 0. A **standalone/intelligence** tool uses an out-of-union category label, `group: 'intelligence'`, no `tier`, `scanIncluded: false`. **Never ship "scored + `scanIncluded: false`".** Full annotated checklist: **`bv-mcp-add-tool` skill**.

## Testing

Patterns, DNS mocking, mock isolation, cache clearing, known flakes, and the Analytics-Engine string-assertion trap: **`bv-mcp-testing` skill**.

- Tests run **inside the Workers runtime**. `.spec.ts` here means Vitest, NOT Playwright.
- **Dynamic imports are required** inside test fns for mock isolation: `const { checkSpf } = await import('../src/tools/check-spf')`.

### Pre-commit (`.githooks/pre-commit`)

Five gates: (1) blocked paths (`docs/plans|code-review|superpowers/`, `.dev/`, `.dev.vars*`, `.worktrees/`, generated deploy configs, reports, PDFs, `*.env*`); (2) generated files (even with `git add -f`); (3) staged symlinks (default-deny, reads the staged index); (4) Gitleaks; (5) repo-safety scanner (same as the required `File hygiene check` CI gate). `--no-verify` only for reviewed false positives.

- ⚠️ **A four-part dotted standards citation trips BOTH secret scanners** (`N.N.N.N` scans as an IPv4). Reword to a spaced form (`§4.2.2 subsection 1`); do NOT widen the configs or `--no-verify`. Leave an in-file comment so nobody "tidies" it back.
- ⚠️ **40-hex action pins scan as phone numbers** — resolved by the `^\.github/workflows/` path allowlist in `.gitleaks.toml`'s `phone-number` rule (the intended mechanism; rationale in-file). `--no-verify` buys nothing: `Secret & PII scan` is required CI, so the PR blocks at merge instead. Do not quote offending digit-runs in prose — that re-trips the rule in whatever file you write.

## CI/CD & Deploy

- **Required checks are exactly four** (verified live 2026-08-23): `build-and-test`, `Secret & PII scan`, `Dependency audit`, `File hygiene check`. Everything else (`contract`, `fast-checks`, `typecheck-tests`, `dns-scan`, `registry-drift-check`) is advisory — a green-but-`BLOCKED` PR waits on one of the four.
- **Branch protection (SETTLED 2026-08-23)**: the four checks + `strict=true`, **NO required reviews** (deliberate — solo maintainer), `enforce_admins=true`, `required_conversation_resolution=true`, no force pushes. ⚠️ `PUT .../protection` is FULL-REPLACE — re-apply the whole canonical object, never a fragment. `mergeStateStatus: UNSTABLE` is mergeable once the required four pass.
- **Deploy**: `npm run deploy:prod` run by an operator is THE authoritative path. `deploy-prod.yml` is dispatch-only and disarmed by default (never deployed anything); the old tag-triggered/auto-deploy workflows are REMOVED. ⚠️ `npm run deploy:prod` does NOT deploy bv-infra-probe — deploy it explicitly (`npx wrangler deploy --config wrangler.infra-probe.jsonc`) when its source changes.
- `typecheck-tests` is a per-file **ratchet** (baseline `test/typecheck-baseline.json`; bank improvements with `-- --update`); `ci.yml`'s `fast-checks` typechecks `src/` only.
- Workflow inventory, histories, dogfood scan, workflow-cost guard, and the full deploy-mode narrative: **`bv-mcp-operations` skill**.

### Release (`publish.yml`)

Pre-bump locally before tagging (the `version-bump` job is a read-only gate). ⚠️ Deploy and publish are **operator-run** steps, not tag-triggered — a green Release run proves neither; verify live `serverInfo.version` + the registry with a cache-buster every time. 🚨 Run both shipping commands from a worktree pinned to the release commit. 🚨 Never let the ed25519 registry key reach stdout (`--private-key "$(cat mcp.hex)"`). Full flow + MCP Registry DNS auth: **`bv-mcp-release` skill**.

## Service Binding Integration

`/internal/tools/call` accepts `{ name, arguments }` → `{ content, isError? }`. `/internal/tools/batch` runs one tool across many domains (max 500, concurrency 1–50, 256 KB body). `?format=structured` returns the tool's **payload** under `result` per domain — raw `CheckResult` for `check_*` tools, `structuredContent` for `NON_CHECK_RESULT_TOOLS`. Cross-door parity asserted in `test/internal.spec.ts`.

| Layer                                                             | Public `/mcp` | Internal `/internal/*` |
| ----------------------------------------------------------------- | :-----------: | :--------------------: |
| CORS, Origin, Auth, Rate limiting, Sessions, JSON-RPC, Body limit |       ✓       |           —            |
| Tool execution, Caching, Analytics, SSRF                          |       ✓       |           ✓            |

Free-tier paid-gating (403) and the distinct-domain cap are public-`/mcp`-only — the internal path bypasses them; bv-web enforces paid entitlement before forwarding.

## Deployment

`npm run deploy:prod` runs `scripts/inject-private-config.cjs`, merging public `wrangler.jsonc` with ignored private overrides into generated `wrangler.production.jsonc` immediately before deploy.

**Mandate**: never hardcode prod endpoints/secrets/internal bindings in `wrangler.jsonc` — use private overrides. The inject script must enumerate every binding kind — silent drops have shipped misconfigured deploys.

## Bindings

Per-binding narratives (activation, failure semantics, incident history): **`bv-mcp-operations` skill** → "Binding notes".

| Binding | Type | Purpose |
| --- | --- | --- |
| `BV_API_KEY` | Secret | Static bearer auth → `owner` tier |
| `ENABLE_OAUTH` / `ENABLE_OWNER_OAUTH` | var | OAuth routes / owner consent page (operator only) |
| `OWNER_ALLOW_IPS` | var | IPs allowed for `owner`; mismatch → `partner` |
| `OAUTH_SIGNING_SECRET` | Secret | HS256 ≥32 bytes; required when `ENABLE_OAUTH=true` (503 until set) |
| `OAUTH_ISSUER` | var | Optional override; falls back to Host (set in prod vs Host spoofing) |
| `ALLOWED_ORIGINS` | var | Allowed Origins (CSV) |
| `RATE_LIMIT` / `SCAN_CACHE` / `SESSION_STORE` | KV | Required in prod |
| `QUOTA_COORDINATOR` / `PROFILE_ACCUMULATOR` | DO | Distributed rate limiting / adaptive weights (optional) |
| `MCP_ANALYTICS` | Analytics Engine | Telemetry (fail-open) |
| `MCP_ANALYTICS_QUEUE` | Queue | **Operator only.** Batched `mcp_access_log` writes (PTR + encrypt). Absent → inline fallback |
| `ANALYTICS_PII_LEVEL` / `ANALYTICS_RETENTION_DAYS` | var | Access-log PII depth (`coarse` default) / retention days (90, clamp 1–365) |
| `PROVIDER_SIGNATURES_URL` | var | Provider signatures source |
| `BV_DOH_ENDPOINT` / `BV_DOH_TOKEN` | Secret | Optional secondary DoH. ⚠️ Both Secrets, never `vars` |
| `CERTSPOTTER_TOKEN` | Secret | Cert Spotter CT auth. Fail-soft; raises rate limits ONLY (15s timeout stays — #735) |
| `BV_CERTSTREAM` | Service | CT logs: `/enumerate` + `/sans`; crt.sh fallback w/ jittered backoff |
| `BV_WHOIS` | Service | WHOIS/43 shim; optional, RDAP-only fallback |
| `BV_INFRA_GRAPH` / `BV_INTEL_GATEWAY` / `BV_ENTERPRISE` | Service | **Operator only.** Tier-1/2/0 `discovery_mode='tiered'` lookups; absent → classic sweep |
| `BV_RECON` / `BV_RECON_KEY` | Service / Secret | **Operator only.** bv-recon behind the recon tools; fail-soft → `unprovisioned` |
| `BV_TLS_PROBE` / `BV_TLS_PROBE_KEY` | Service / Secret | **Operator only.** Legacy-TLS detection for `check_ssl`; fail-soft |
| `BV_WEB` | Service | **Operator only.** OAuth consent proxy + M365 `m365Proxy`. ⚠️ IS declared in public `wrangler.jsonc` (audit-enforced) |
| `BV_WEB_INTERNAL_KEY` | Secret | Bearer for `BV_WEB` internal calls, M365 proxy auth, AND `resolveAlertWebhookUrl` |
| `BV_INFRA_PROBE` | Service | authoritative_dns_infra probe. ⚠️ NOT overlay-only; `deploy:prod` does NOT deploy it |
| `INTELLIGENCE_DB` | D1 | `mcp_access_log` store. Absent → access-log no-op |
| `BRAND_AUDIT_DB` / `BRAND_AUDIT_QUEUE` / `BRAND_AUDIT_PDF_QUEUE` / `BRAND_REPORTS` | D1/Queue/R2 | Async brand-audit state, job queues, PDF storage. Queues absent → `*_start` → `unprovisioned` |
| `BV_BROWSER_RENDERER` / `BV_BROWSER_RENDERER_KEY` | Service / Secret | **Operator only.** Brand-report PDF rendering |
| `KV_ENVELOPE_KEY` | Secret | AES-256 KV envelope encryption (FIND-17 — OAuth codes, trial keys) |
| `BRAND_AUDIT_DISCOVERY_MODE_DEFAULT` | var | **Operator only.** `"tiered"` flips the runtime default; unset → schema default `'classic'` |
| `SCORING_CONFIG` | var | JSON scoring overrides |
| `CF_ACCOUNT_ID` / `CF_ANALYTICS_TOKEN` | var / Secret | Alerting query auth |
| `ALERT_WEBHOOK_URL` + `ALERT_*` | var | Cron alerts. ⚠️ Latency has its OWN lane/window; `ALERT_WEBHOOK_URL` is the static fallback only |

## Analytics

Eight AE event indexes (`analytics.ts`): `mcp_request`, `tool_call`, `rate_limit`, `session`, `degradation`, `queue_batch`, `tail`, `quota_shard` — queried by `analytics-queries.ts` and wired into the 15-min cron (`scheduled.ts`: anomaly alerts + `handleFuzzingScan`). `mcp_access_log` (D1) is the faithful per-event store; in the current prod config the queue is unbound so the inline path (no PTR) is active. Blob layouts (append-only — keep in sync when adding dimensions), access-log gating, and client detection: **`bv-mcp-operations` skill**. Per-IP investigations belong in operator-only notes — hash IPs locally, never commit raw IPs or token-bearing analytics commands.

## False Positive Reduction

- **MX Reputation**: shared provider IPs (Google, M365) → DNSBL findings → `info`
- **Lookalikes**: shared NS with primary → `info` (defensive registration)
- **Shadow Domains**: shared NS (≥2 overlap) → severity downgrade with ownership signal
- **TXT Hygiene**: record accumulation tiered (25+ → medium, 15–24 → low); duplicate verifications consolidated
- **Non-mail SPF** (`check_mx`): no MX → verifies `v=spf1 -all`; missing SPF → medium, non-reject → low
- **Subdomain takeover severity**: dangling-CNAME targets embedding a provider-assigned random ID (ELB/CloudFront/API-Gateway) downgrade HIGH → MEDIUM (operational drift, not a reclaimable namespace) — `classifyTargetNamespace()` in `packages/dns-checks/src/checks/subdomain-takeover-analysis.ts`
