# CLAUDE.md

Guidance for Claude Code working in this repo.

## What is this?

Blackveil DNS — source-available DNS & email security scanner, built as a Cloudflare Worker.
78 tools exposed via MCP Streamable HTTP (JSON-RPC 2.0) at `https://dns-mcp.blackveilsecurity.com/mcp`. Source of truth: `TOOL_DEFS` in `src/schemas/tool-definitions.ts`. `check_subdomain_takeover` runs only inside `scan_domain`. Listed on the MCP Registry as `com.blackveilsecurity/dns`.

**Version sync** when bumping: `version` in `package.json` + `package-lock.json` (the source of truth — `SERVER_VERSION` in `src/lib/server-version.ts` auto-derives via `pkg.version`, do **not** hand-edit it), top-level `version` in `server.json` (currently **remotes-only — single `version` field**; the `packages[0].version` foot-gun only applies if an npm `packages` stanza is re-added), and the `[X.Y.Z]` heading in `CHANGELOG.md`.

## Commands

```bash
npm ci
npm test                                    # Vitest in Workers runtime
npx vitest run test/check-spf.spec.ts       # Single spec
npm run build                               # tsup (npm pkg + stdio CLI)
npx wrangler dev                            # localhost:8787
npm run typecheck                           # tsc --noEmit
npm run lint[:fix]
npm run deploy:prod                         # Inject private bindings + deploy
git config core.hooksPath .githooks         # One-time hook setup
```

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

Both publish together from `publish.yml` on version tags.

### Recon tools (operator-deploy only)

11 tools (`check_realtime_threat_feed`, `scan_buckets_start/status/findings`, `osint_investigate_domain/infrastructure/supply_chain/username/email_start`, `osint_investigation_status/report`) call bv-recon via the `BV_RECON` service binding (`src/lib/recon-binding.ts`). They degrade to `unprovisioned` on BSL self-hosts where the binding is absent — the fail-soft wrapper never throws. The async tools (`scan_buckets_start`, `osint_investigate_*_start`) use a start → poll pattern: start returns an ID, poll via `*_status`, retrieve via `*_findings`/`*_report`. `cymru_asn`, `check_lookalikes`, and `check_fast_flux` gain optional bv-recon enrichment when the binding is present.

### Request flow

- **Streamable HTTP**: `POST /mcp → Origin → Auth → Body → JSON-RPC validate → mcp/execute → handlers/tools → src/tools/check-* → lib/dns → DoH (empty → bv-dns → Google)`
- **Stdio**: `stdin → src/stdio → mcp/execute → handlers/tools → stdout`
- **Internal binding**: `POST /internal/tools/{call,batch} → guard (reject public) → handlers/tools → JSON (no MCP framing)`
- **Legacy SSE** (deprecated): `GET /mcp/sse` bootstrap; `POST /mcp/messages?sessionId=...`

### scan_domain orchestration

18 scan categories run in parallel via `Promise.allSettled`: 17 registered scan-included tools plus internal `subdomain_takeover`. Cache keys: `cache:<domain>:check:<name>` + top-level `cache:<domain>`. 5 min TTL (overridable via `cacheTtlSeconds`). `force_refresh` → `skipCache` in `runWithCache()`.

**Maturity staging**: `computeMaturityStage()` 0–4 (Unprotected → Hardened). Stage 3 doesn't require DKIM; Stage 4 hardening: CAA, DKIM-discovered, BIMI, DANE, MTA-STS strict. Score caps stage: F → ≤2, D/D+ → ≤3.

**Timeouts**: scan 12s preserves partial results; per-check 8s.

**Subrequest ceiling** (operating constraint, not a bug): a cold-cache `scan_domain` fans out ~20 subrequests/domain (18 categories, mostly DoH + 2 HTTPS); `/internal/tools/batch` can fan out to ~50×18. Cloudflare Workers caps subrequests per invocation at 50 (Free) / 1000 (Paid). BlackVeil production runs on a paid plan, so this is not a prod concern. BSL self-hosters on the Free plan should keep batch size / scan concurrency modest (cache hits don't count) or upgrade.

**Post-processing**:

- Non-mail (no MX): parent DMARC `sp=`/`p=` → downgrade email-auth findings to `info`
- No-send (SPF `noSendPolicy`): downgrade DKIM/MTA-STS/BIMI missing-record findings to `info`
- BIMI rewritten for non-mail domains

**Output**: human-readable text + (non-interactive clients only) `<!-- STRUCTURED_RESULT ... -->` JSON. Omitted for LLM IDE clients.

### Output format control

`format` param (`full` | `compact`). Auto-detected from client type: interactive LLM → `compact`, else `full`. Compact strips emoji icons, impact narratives, verbose sections. Resolution in `extractFormat(args)` (tool-args.ts) → explicit wins, else `resolveFormat()` from `clientType`.

## Conventions

- **Zod**: Centralized in `src/schemas/`. Tool `inputSchema` derived via `z.toJSONSchema()` (Zod v4). Runtime: `validateToolArgs()`. Use `.passthrough()` and `.transform().pipe()` for case-insensitive enum normalization.
- `createFinding()` + `buildCheckResult()` from `@blackveil/dns-checks/scoring` — never construct findings manually. `createFinding()` auto-sanitizes `detail`.
- `validateDomain()` + `sanitizeDomain()` from `lib/sanitize.ts` for all domain inputs (after Zod) — SSRF/blocklist.
- `mcpError()` / `mcpText()` from `handlers/tool-formatters.ts`.
- `cacheGet/Set/SetDeferred/runWithCache` from `lib/cache.ts`. `cacheSetDeferred` wraps in `ctx.waitUntil()`.
- JSDoc on exports; `import type { ... }` for type-only.
- Tool functions: `Promise<CheckResult>` + optional `dnsOptions?: QueryDnsOptions`. Follow `check-spf.ts`.
- **DNS-failure resilience**: tools called directly (not just via `scan_domain`'s `safeCheck`) should catch top-level DNS errors and return `missingControl: true` instead of throwing. `check-spf.ts` is the reference (`errorKind: 'timeout' | 'dns_error'`).
- **Total-budget caps**: tools with multiple sequential external fetches wrap in `Promise.race` vs `TOTAL_BUDGET_MS`. `check_http_security` = 10s.
- **`batch_scan`**: `budgetMs` default 25s, `concurrency` default 3, per-domain `Promise.race`. Exceeded → `error: 'batch_budget_exceeded'`.
- `check_mx` is **dynamically imported** in `handlers/tools.ts` (mock isolation).
- MCP server key `"blackveil-dns"` everywhere. `tools/call` accepts `scan` as alias for `scan_domain`. SSRF constants live in `lib/config.ts`.
- **`CheckResult` literal**: include both `passed: boolean` AND `findings: [] as Finding[]` — bare `findings: []` infers `never[]` and breaks CI after dns-checks DTS rebuild.
- **`.spec.ts` in this repo** = Vitest unit/integration, NOT Playwright E2E. For new mock-D1 integration files prefer `*.integration.test.ts`.

### Error surfacing

`sanitizeErrorMessage()` in `lib/json-rpc.ts` allowlists prefixes:

- `'Missing required'`, `'Invalid'`, `'Domain '`, `'Resource not found'`, `'Rate limit exceeded'`

Anything else → generic fallback. New client-visible errors must start with one of these. Rate limit: HTTP **429** + JSON-RPC `code: -32029` carried in the response body (`useErrorEnvelope`); `retry-after` header set. All rate-limit/quota paths in `mcp/execute.ts` return `httpStatus: 429` (per-IP minute/hour/day, per-tool daily, per-tier daily, global cap); asserted by `test/index.spec.ts`.

## Scoring

Three-tier model (`computeScanScore`). `CATEGORY_DISPLAY_WEIGHTS` is display-only.

**Core (70%)**: DMARC 16, DKIM 10, SPF 10, DNSSEC 10, SSL 8 (representative `mail_enabled` profile — every core weight is per-profile; e.g. DNSSEC 5–20, SSL 7–14 across the 6 profiles).
**Protective (20%)**: Subdomain Takeover 4, HTTP Security 3, MTA-STS 3, MX 2, CAA 2, NS 2, Lookalikes 2, Shadow Domains 2.
**Hardening (10%)**: DANE, BIMI, TLS-RPT, TXT Hygiene, MX Reputation, SRV, Zone Hygiene (~1.4 pts each, bonus-only).

Override via `SCORING_CONFIG` env (JSON; `weights`, `profileWeights`, `thresholds`, `grades`, `baselineFailureRates`). Parsed via `parseScoringConfigCached()` (memoized).

### Rules

- **Email bonus**: SPF ≥57, DKIM not deterministically missing, DMARC present → +5/+3/+2 by DMARC score.
- **SPF trust-surface**: shared-platform findings informational; elevated only when weak DMARC/relaxed alignment corroborates.
- **SPF `~all`**: downgraded to `info` when DMARC `p=quarantine|reject` (RFC 7489 §10.1). `pct=` parsed.
- **Confidence gate**: `scoreIndicatesMissingControl()` fires only for `deterministic`/`verified`. Heuristic DKIM "not found" doesn't zero category.
- **Provider-informed DKIM**: provider detected + probing empty → HIGH → MEDIUM.
- **Severity penalties**: C −40, H −25, M −15, L −5, Info 0.
- **`passed`**: `score >= 50 && !hasMissingControl`. Missing control → score zeroed. Checks using `missingControl: true`: CAA, HTTP Security, MTA-STS, MX, SVCB-HTTPS, NS, Zone Hygiene, BIMI, DANE, TLS-RPT. **DNSSEC deliberately does NOT** — per NIST SP 800-81r3, DNSSEC is a baseline integrity control in a defense-in-depth model: absence is a `high`-severity Core penalty (category → 60, via a fixed `penaltyOverride: 40` on the finding metadata that decouples the −40 deduction from the `high` severity label — see `computeCategoryScore`), not a category-zeroing missing control.
- **Grades**: A+ 92+, A 87–91, B+ 82–86, B 76–81, C+ 70–75, C 63–69, D+ 56–62, D 50–55, F <50.

### Profiles

Five: `mail_enabled` (default), `enterprise_mail`, `non_mail`, `web_only`, `minimal`. Defined in `packages/dns-checks/src/scoring/profiles.ts`. **Phase 1**: `auto` uses `mail_enabled` weights; explicit `profile` activates different weights + cache keys.

### Adaptive weights

EMA per profile+provider via `ProfileAccumulator` DO. Maturity-gated blending (`MATURITY_THRESHOLD = 200`). Falls back to static if DO unavailable. `PROFILE_ACCUMULATOR` threaded `index.ts → dispatch.ts → handlers/tools.ts → scanDomain()`. Telemetry sent via `waitUntil()`.

## Security

- **SSRF**: blocked IPs/TLDs in `config.ts`; enforced by `sanitize.ts`. All outbound `redirect: 'manual'`. **Attacker-controlled URLs** (BIMI `l=`/`a=`, redirect `Location:` targets the worker follows) MUST use `safeFetch` (`lib/safe-fetch.ts`). Fetches to URLs whose hostname is already validated (e.g. `https://${validatedDomain}/.well-known/...`) may use raw `fetch` with manual redirects.
- **Auth**: Static `BV_API_KEY` (constant-time XOR). Token from `Authorization: Bearer` first, then `?api_key=` (Smithery fallback). Six tiers: `free`, `agent`, `developer`, `enterprise`, `partner`, `owner`. Owner-tier IP gate: client IP must be in `OWNER_ALLOW_IPS` else downgrade to `partner` (including OAuth JWT path). OAuth JWT validates `claims.tier` against `JwtIssuableTierSchema = z.enum(['owner','developer','enterprise'])`.
- **Rate limits**: 50/min, 300/hr per IP (unauthenticated). Authenticated bypass per-IP; per-tier daily quotas apply. Only `tools/call` counts. `check_lookalikes`/`check_shadow_domains`: 20/day per IP + 60-min cache.
- **Per-tool quotas**: `FREE_TOOL_DAILY_LIMITS` in `config.ts`. Global cap `GLOBAL_DAILY_TOOL_LIMIT` 500k/day via `QuotaCoordinator` DO.
- **Body**: 10 KB on `/mcp`. **IP source**: `cf-connecting-ip` only (never `x-forwarded-for`).
- **Origin**: MCP-compliant rejection of unauthorized browser `Origin`; `ALLOWED_ORIGINS` configurable.

### Sessions

Idle TTL 2h, sliding refresh, KV + in-memory dual-write. Missing → 400; expired → 404. Creation rate-limited 30/min per IP. IDs: exactly 64 lowercase hex. `DELETE /mcp` accepts `Mcp-Session-Id` header only. `SESSION_CREATE_BY_IP` LRU-capped 5000; `LEGACY_STREAMS` capped 500.

### Paid OAuth tiers

bv-web plan → OAuth tier claim → bv-mcp limits:

| Plan                           | Tier       | Scans/day | Concurrent | Support         |
| ------------------------------ | ---------- | --------- | ---------- | --------------- |
| free / starter                 | (none)     | 50        | 3          | Community       |
| pro / business / MCP Developer | developer  | 500       | 10         | Business / 48h  |
| enterprise / MCP Enterprise    | enterprise | 10,000    | 25         | Enterprise / 4h |

Resolution in `src/oauth/entitlements.ts` via bv-web service binding `api/internal/mcp/oauth/authorize`. Mapping defined in bv-web `app/lib/services/mcp/oauth-entitlements.server.ts`. The local static `BV_API_KEY` resolves to `owner` tier (`src/lib/tier-auth.ts:246-253`), with the `OWNER_ALLOW_IPS` IP gate downgrading to `partner` when the client IP isn't allowlisted. The `agent` tier (200/day, 5 concurrent) is reachable only via the bv-web `validate-key` service binding, when bv-web returns that tier for a non-paying key.

### Internal routes

`/internal/*` guarded by `cf-connecting-ip` presence (`isPublicInternetRequest()` in `src/internal.ts`). Public requests → 404. Batch endpoint: tool names `/^[a-z_]+$/` max 30 chars, arg keys allowlisted. `/internal/tools/call` enforces 10 KB body limit pre-parse.

**Bearer auth (defense-in-depth)**:

- `/internal/trial-keys/*`, `/internal/oauth/grants` (credential-minting) → strict gate: 503 if `BV_WEB_INTERNAL_KEY` unset, 401 on missing/wrong bearer.
- `/internal/tools/*`, `/internal/analytics/*` → `internalLenientAuthGate`, opt-in via `REQUIRE_INTERNAL_AUTH=true`.

### Fuzzing detection

Pattern-based, emits `fuzzing_suspected` to `ALERT_WEBHOOK_URL` from 15-min cron. Patterns: `unknown_tool`, `unknown_method`, `zod_arg`, `auth_fail`. Files: `lib/fuzzing-detector.ts` (pure), `lib/fuzzing-counter.ts` (KV `RATE_LIMIT`, fail-soft), `schemas/alerting.ts`, `handleFuzzingScan` in `scheduled.ts`. Principal: `keyHash` (auth) or `ipHash` (FNV-1a `i_` prefix). Thresholds: `FUZZ_THRESHOLDS` in `lib/config.ts` (audit-enforced).

## Adding a New Tool

**First decide: scored or standalone?** A **scored** check gets a `CheckCategory` and MUST be `scanIncluded: true` + wired into `scan_domain` (else it sits in the scoring denominator at 0 and lowers every domain's score — the three-tier engine counts ALL `CATEGORY_TIERS` members). A **standalone/intelligence** tool (e.g. `check_dnssec_chain`) uses an out-of-union category label, `group: 'intelligence'`, no `tier`, `scanIncluded: false`, and skips all scoring steps. Never ship "scored + `scanIncluded: false`". See the `bv-mcp-add-tool` skill for the full annotated checklist.

1. `src/tools/check-<name>.ts` → async fn returning `CheckResult`
2. **Scored only:** add the member to `CheckCategory`, `CATEGORY_TIERS`, and `CATEGORY_DISPLAY_WEIGHTS` in `packages/dns-checks/src/types.ts` (NOT `model.ts` — that only re-exports)
3. **Scored only:** `IMPORTANCE_WEIGHTS` in `packages/dns-checks/src/scoring/engine.ts`
4. **Scored only:** `DEFAULT_SCORING_CONFIG` weights, profileWeights (**all 6**, incl. `authoritative_dns_infra`), baselineFailureRates in `config.ts`
5. **Scored only:** all 6 `PROFILE_WEIGHTS` in `packages/dns-checks/src/scoring/profiles.ts`
6. **Scored only — rebuild the package:** `npm -w packages/dns-checks run build` (Worker code + tests import the built `dist/`, not `src/`; skip this and the new category won't resolve)
7. Zod schema to `schemas/tool-args.ts` + `TOOL_SCHEMA_MAP`
8. Tool entry in `TOOL_DEFS` in `schemas/tool-definitions.ts` (`scanIncluded: true` auto-appends the scan_domain suffix)
9. `TOOL_REGISTRY` in `handlers/tools.ts` (import + cacheKey + execute)
10. `FREE_TOOL_DAILY_LIMITS` in `config.ts` (or `INTENTIONALLY_UNLIMITED_TOOLS` — `tool-quota-coverage` audit requires exactly one)
11. Explanation templates in `explain-finding-data.ts` (optional — no audit enforces it)
12. **If scored + in scan:** wire `scan-domain.ts` at 3 hardcoded places (`ALL_CHECK_CATEGORIES`, the `checkPromises`/`runCachedCheck` array, the `runCheckRetry()` switch) + the static import
13. `test/check-<name>.spec.ts` using `dns-mock` helper
14. Update README tools table
15. **No `domain` arg** (uses `domains[]`, `auditId`, etc.): handled via the schema's `domain` field / `toolRequiresDomain()`; covered by `test/audits/domain-required-ssot.audit.test.ts` — else every call returns "Missing required parameter: domain"
16. **New `ToolRuntimeOptions` field** for a binding: extend `BvMcpEnv` AND populate at all 3 construction sites in `src/index.ts` — else `ro.<field>` is undefined and the tool returns `{ unprovisioned: true }`
17. **Count surfaces** — bump `toHaveLength(N)` in 7 tool-count specs (`test/{tool-metadata,tool-schemas,handlers-tools,index,tool-output-schema,schemas/tool-args,schemas/tool-definitions}.spec.ts`); add to `SCAN_DOMAIN_TOOL_NAMES` **or** `NON_SCAN_TOOL_NAMES` in `tool-schemas.spec.ts` (exhaustive partition); bump the CheckResult count in `tool-output-schema.spec.ts` (NON_CHECK_RESULT tools also add to `NON_CHECK_RESULT_TOOLS`)
18. **Audits that fail in CI** — `server-json-tool-count` (server.json "N MCP tools"); `readme-tool-surface` (hardcoded `toBe(N)` + README + `docs/github-settings.md` + `extensions/vscode/{README.md,package.json}`, incl. the `check_*` count); `npm run generate:wasm-permissions` (generated Rust perms); `test/chaos/varied-domain-all-tools.chaos.test.ts` (case list = registry)
19. **Scored only** — bump `scoring-model.spec.ts` (`CATEGORY_TIERS` length + per-tier counts) and update the score snapshots in `scoring-profiles.spec.ts`; **both exist twice** (`packages/dns-checks/src/__tests__/scoring/` AND `test/`). If scanned, also bump the scan-category count in `test/scan-domain.spec.ts`

## Testing

- DNS mocked via `test/helpers/dns-mock.ts`: `setupFetchMock`, `mockTxtRecords`, `createDohResponse`, `mockFetchResponse`, `mockFetchError`
- Each spec: `restore()` in `afterEach`
- **Dynamic imports required** inside test fns for mock isolation: `const { checkSpf } = await import('../src/tools/check-spf')`
- Clear scan cache between cases: both `cache:<domain>:check:<name>` and `cache:<domain>`
- `tsconfig.json` `types` must be under `compilerOptions`
- Config: `vitest.config.mts` — 15s timeout, `isolatedStorage: false`
- TXT mocking: `mockTxtRecords()` adds quotes (pass unquoted); for backslash escaping, use `createDohResponse()` directly
- **Known flake**: full-suite (~3300 tests) ending with `workerd ... WebSocket peer disconnected` + ~10 "failures" is pool-teardown noise, not real. Re-run named specs in isolation to confirm.

### Pre-commit (`.githooks/pre-commit`)

Four gates: (1) blocked paths (`docs/plans/`, `docs/code-review/`, `docs/superpowers/`, `.dev/`, `.dev.vars*`, `.worktrees/`, generated deploy configs, reports, PDFs, `*.env*`); (2) generated files (`*.pyc`, `__pycache__/`, `worker-configuration.d.ts`, `*.wasm`, `*.sqlite`, `*.db`) even with `git add -f`; (3) Gitleaks secret/PII scan; (4) repo-safety scanner (`scripts/repo-safety/scan-sensitive-surface.mjs` via `policy.json` — forbidden paths, internal hostnames, hashed client domains, public IPs, real emails; same scanner the required `File hygiene check` CI gate runs). Public docs (`docs/client-setup.md`, `docs/scoring.md`) are committable when they use placeholders. Override with `--no-verify` only for reviewed false positives.

## CI/CD

Workflows: `ci.yml`, `ci-contract.yml` (Zod contracts, required), `security.yml` (Gitleaks + npm audit, required), `repo-hygiene.yml` (reusable, called by other repos), `deploy-hook.yml` (active deploy path), `publish.yml` (tagged-release pipeline), `triage-issues.yml`, `.gitleaks.toml`. `dns-security.yml.disabled` is intentionally disabled because it invokes the paid `MadaBurns/blackveil-dns-action` path.

**Branch protection** (verified 2026-05-22): required checks = `build-and-test`, `Secret & PII scan`, `Dependency audit`, `File hygiene check`. **1 approving review required** (`dismiss_stale_reviews=true`, `required_conversation_resolution=true`). **`enforce_admins=true`** — admin override is gated; `gh pr merge --admin` alone fails with "1 approving review required." Direct pushes to `main` are blocked; use the PR review path. **`dns-scan` is NOT required** and stays pending for hours; `mergeStateStatus: UNSTABLE` is mergeable once required checks and review are satisfied.

**Deploy mode**: manual via `npm run deploy:prod` using an authenticated local Wrangler session. `auto-deploy-main.yml` is disabled unless GitHub production secrets are deliberately configured.

### Release (`publish.yml`)

**Pre-bump locally before tagging** to avoid the workflow's auto-bump push being rejected by branch protection:

```bash
npm version <X.Y.Z> --no-git-tag-version --allow-same-version   # bumps package.json + lock; SERVER_VERSION auto-derives
# Update CHANGELOG.md ([X.Y.Z] heading) + server.json (top-level version — remotes-only, single field)
git commit -am "chore: bump version to <X.Y.Z>" && git push origin main
git tag v<X.Y.Z> && git push origin v<X.Y.Z>
```

Pipeline: validate → version-sync (no-op if pre-bumped) → npm publish (provenance) || Cloudflare deploy → MCP Registry → GH Release. Requires `NPM_TOKEN`, `CLOUDFLARE_API_TOKEN`, `MCP_REGISTRY_TOKEN` in `production` env — fail-fast if absent. `wrangler d1 execute --remote --file=-` does NOT accept stdin; pass a real path.

**Workflow secret-check audit** (`test/audits/workflow-secret-check.audit.test.ts`): every `[ -z "$*_TOKEN" ]` guard must `exit 1`; no warn-and-skip. Codifies v2.10.2–v2.10.6 silent prod-stale.

### Manual release fallback

When hosted release secrets are unavailable, ship locally with credentials from
the operator's secret manager. Do not commit `.npmrc`, registry tokens, DNS
publisher keys, or generated production config.

```bash
npm -w packages/dns-checks run build && npm run build
npm publish --access public
npm run deploy:prod
mcp-publisher publish
```

**`server.json` is currently remotes-only** — a single top-level `version` field (no `packages` stanza); sync just that field to the tag. (If an npm `packages` stanza is ever re-added, it reintroduces the two-field foot-gun — sync both then.)

Approve gated deploys through GitHub's protected environment UI or an
operator-only runbook.

### MCP Registry DNS auth

Namespace `com.blackveilsecurity/*` is gated by the MCP Registry DNS TXT
record. Keep the private publisher key in an approved secret manager and local
ignored env only; never commit it or paste it into workflow logs.

## Service Binding Integration

`/internal/tools/call` accepts `{ name, arguments }` → `{ content, isError? }`. `/internal/tools/batch` runs one tool across many domains (max 500, concurrency 1–50, 256 KB body). `?format=structured` returns raw `CheckResult` per domain.

| Layer                                                             | Public `/mcp` | Internal `/internal/*` |
| ----------------------------------------------------------------- | :-----------: | :--------------------: |
| CORS, Origin, Auth, Rate limiting, Sessions, JSON-RPC, Body limit |       ✓       |           —            |
| Tool execution, Caching, Analytics, SSRF                          |       ✓       |           ✓            |

## Deployment

`npm run deploy:prod` runs `scripts/inject-private-config.cjs`, merging public
`wrangler.jsonc` with ignored private deploy overrides into generated
`wrangler.production.jsonc` immediately before deploy.

**Mandate**: never hardcode prod endpoints/secrets/internal bindings in `wrangler.jsonc` — use private overrides. The inject script must enumerate every binding kind (vars, kv_namespaces, r2_buckets, services, durable_objects, queues, d1_databases, analytics_engine_datasets) — silent drops here have shipped misconfigured deploys.

## Bindings

| Binding                                                              | Type             | Purpose                                                                                                                                                                                                                                                           |
| -------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BV_API_KEY`                                                         | Secret           | Static bearer auth → `owner` tier                                                                                                                                                                                                                                 |
| `ENABLE_OAUTH`                                                       | var              | `true` to expose OAuth routes                                                                                                                                                                                                                                     |
| `ENABLE_OWNER_OAUTH`                                                 | var              | Owner consent page (operator deploys only)                                                                                                                                                                                                                        |
| `OWNER_ALLOW_IPS`                                                    | var              | IPs allowed for `owner`; mismatch → `partner`                                                                                                                                                                                                                     |
| `OAUTH_SIGNING_SECRET`                                               | Secret           | HS256 ≥32 bytes. Required when `ENABLE_OAUTH=true` (`oauthAvailability` gate returns 503 until set)                                                                                                                                                               |
| `OAUTH_ISSUER`                                                       | var              | Optional override; falls back to Host (set in prod against Host spoofing)                                                                                                                                                                                         |
| `ALLOWED_ORIGINS`                                                    | var              | Allowed Origins (CSV)                                                                                                                                                                                                                                             |
| `RATE_LIMIT` / `SCAN_CACHE` / `SESSION_STORE`                        | KV               | Required in prod                                                                                                                                                                                                                                                  |
| `QUOTA_COORDINATOR`                                                  | DO               | Distributed rate limiting                                                                                                                                                                                                                                         |
| `PROFILE_ACCUMULATOR`                                                | DO               | Adaptive weights (optional)                                                                                                                                                                                                                                       |
| `MCP_ANALYTICS`                                                      | Analytics Engine | Telemetry (fail-open)                                                                                                                                                                                                                                             |
| `PROVIDER_SIGNATURES_URL`                                            | var              | Provider signatures source                                                                                                                                                                                                                                        |
| `BV_DOH_ENDPOINT` / `BV_DOH_TOKEN`                                   | var / Secret     | Custom secondary DoH (`X-BV-Token`)                                                                                                                                                                                                                               |
| `BV_CERTSTREAM`                                                      | Service          | CT logs: `/enumerate` (discover_subdomains, scan) + `/sans` (brand SAN siblings). Direct-crt.sh fallback w/ jittered backoff                                                                                                                                      |
| `BV_WHOIS`                                                           | Service          | WHOIS/43 shim; optional, RDAP-only fallback. KV-cached IANA referrals                                                                                                                                                                                             |
| `BV_INFRA_GRAPH`                                                     | Service          | **Operator-deploy only.** Tier-1 infrastructure-graph lookup for `discovery_mode='tiered'`. Not packaged with the public distribution — wired via `.dev/wrangler.deploy.jsonc`. Absent → tiered pipeline falls back to classic sweep                              |
| `BV_INTEL_GATEWAY`                                                   | Service          | **Operator-deploy only.** Tier-2 declared-evidence lookups for `discovery_mode='tiered'`. Private BlackVeil binding; not in public `wrangler.jsonc`                                                                                                               |
| `BV_ENTERPRISE`                                                      | Service          | **Operator-deploy only.** Tier-0 portfolio + enterprise tenant data for `discovery_mode='tiered'`. Private BlackVeil binding; not in public `wrangler.jsonc`                                                                                                      |
| `BV_RECON`                                                           | Service          | **Operator-deploy only.** bv-recon OSINT/recon worker — powers the recon tools (`check_realtime_threat_feed`, `scan_buckets_*`, `osint_investigate_*`/`osint_investigation_*`) + optional enrichment of `cymru_asn`/`check_lookalikes`/`check_fast_flux`. Fail-soft when absent (tools return `unprovisioned`). Not in public `wrangler.jsonc`. |
| `BV_RECON_KEY`                                                       | Secret           | Bearer token for bv-recon's admin routes (= bv-recon `ADMIN_API_KEY` / its dedicated `BV_MCP_KEY`).                                                                                                                                                              |
| `BV_TLS_PROBE`                                                       | Service          | **Operator-deploy only.** bv-tls-probe worker — performs version-aware TLS handshakes so check_ssl / scan_domain can detect legacy TLS (1.0/1.1) and apply a High SSL penalty. Fail-soft when absent (no TLS-version finding, no score change). Not in public wrangler.jsonc. See src/lib/tls-probe-binding.ts. |
| `BV_TLS_PROBE_KEY`                                                   | Secret           | Bearer token for bv-tls-probe.                                                                                                                                                                                                                                    |
| `BRAND_AUDIT_DISCOVERY_MODE_DEFAULT`                                 | var              | **Operator-deploy only.** When set to `"tiered"` (the BlackVeil-production default), flips the runtime default for callers that omit `discovery_mode`. Unset on BSL self-hosts → public schema default `'classic'` wins. Set only in `.dev/wrangler.deploy.jsonc` |
| `SCORING_CONFIG`                                                     | var              | JSON scoring overrides                                                                                                                                                                                                                                            |
| `CF_ACCOUNT_ID` / `CF_ANALYTICS_TOKEN`                               | var / Secret     | Alerting query auth                                                                                                                                                                                                                                               |
| `ALERT_WEBHOOK_URL` / `ALERT_*_THRESHOLD` / `ALERT_LOOKBACK_MINUTES` | var              | Cron alerts                                                                                                                                                                                                                                                       |

## Analytics

Four event types: `mcp_request`, `tool_call`, `rate_limit`, `session`. Queries in `analytics-queries.ts`. Scheduled handler (`scheduled.ts`) every 15 min: anomaly alerts + `handleFuzzingScan`. Optional — requires `CF_ACCOUNT_ID` + `CF_ANALYTICS_TOKEN` + `ALERT_WEBHOOK_URL`.

**Blob layout** (keep in sync when adding dimensions):

- `mcp_request`: method, transport, status, auth-flag, jsonrpc-flag, country, clientType, authTier, sessionHash, keyHash, **ipHash** (blob11; FNV-1a `i_` prefix — lossy, equal IPs hash equally). Doubles: double1=durationMs, **double2=abs(jsonRpcErrorCode)** (0 when no error — codes are negative per spec, stored as magnitude since `sanitizeNumber` clamps <0)
- `tool_call`: toolName, status, isError, domainFingerprint, country, clientType, authTier, cacheStatus, keyHash, **ipHash** (blob10)
- `rate_limit`: limitType, toolName, country, authTier
- `session`: action, country, clientType, authTier, method, keyHash

Per-IP investigations belong in operator-only notes. Hash IPs locally and avoid
committing raw IPs or token-bearing analytics commands.

Client detection (`client-detection.ts`): `claude_mobile`, `claude_code`, `cursor`, `vscode`, `claude_desktop`, `windsurf`, `mcp_remote`, `blackveil_dns_action`, `bv_claude_dns_proxy`, `bv_load_test`, `unknown`. For analytics + format auto-detection, never security. `bv_load_test` matches `bv-{load,chaos,tranco}-{test,scan}` UAs — non-interactive.

## False Positive Reduction

- **MX Reputation**: shared provider IPs (Google, M365) → DNSBL findings → `info`
- **Lookalikes**: shared NS with primary → `info` (defensive registration)
- **Shadow Domains**: shared NS (≥2 overlap) → severity downgrade with ownership signal
- **TXT Hygiene**: record accumulation tiered (25+ → medium, 15–24 → low); duplicate verifications consolidated
- **Non-mail SPF** (`check_mx`): no MX → verifies `v=spf1 -all`; missing SPF → medium, non-reject → low
- **Subdomain takeover severity**: dangling-CNAME findings whose target hostname embeds a provider-assigned random ID (AWS ELB ID, CloudFront distribution ID, API Gateway ID) downgrade from HIGH to MEDIUM — those represent operational drift rather than active takeover vectors because the namespace label can't be deterministically reclaimed. Implemented in `classifyTargetNamespace()` in `packages/dns-checks/src/checks/subdomain-takeover-analysis.ts`.
