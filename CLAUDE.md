# CLAUDE.md

Guidance for Claude Code working in this repo.

**This file is deliberately lean.** It loads unconditionally in every session, so
it carries orientation, the gotchas that bite during tasks that never mention
the topic, and pointers. Depth lives in the repo skills (`.claude/skills/`),
which load on description match — see the routing table at the bottom. Before
adding a paragraph here, check the size (`wc -c CLAUDE.md`) and ask whether a
skill is the right home; it usually is. Trimmed 2026-09-11 from 28,897 B
(~7.2k tokens/session) back to pointers.

## What is this?

Blackveil DNS — source-available DNS & email security scanner, built as a
Cloudflare Worker.
79 public tools (84 registered in `TOOL_DEFS`; 5 internal-only via
`INTERNAL_ONLY_TOOLS` — `map_registrar_products` + the four `identity_secops`
M365 tools, withdrawn 3.63.0) exposed via MCP Streamable HTTP (JSON-RPC 2.0) at
`https://dns-mcp.blackveilsecurity.com/mcp`. Source of truth: `TOOL_DEFS` in
`src/schemas/tool-definitions.ts`. `check_subdomain_takeover` is directly
callable AND runs inside `scan_domain` (a `scanIncluded: false` special slot in
`CHECK_DISPATCH`). Listed on the MCP Registry as `com.blackveilsecurity/dns`.

⚠️ Those counts are audit-pinned (`test/audits/tool-surface-prose.audit.test.ts`
via `scripts/tool-surface-tokens.ts`) — do not hand-edit them; run
`npm run generate:tool-surface`.

**Version sync is automatic** — `npm version <X.Y.Z>` runs a lifecycle hook that
syncs `server.json` + the `CHANGELOG.md` heading and stages them. Do not
hand-edit those, `SERVER_VERSION`, or `package-lock.json` versions. Full surface
list + release flow: **`bv-mcp-release`**.

## Commands

```bash
npm ci
npm test                                    # Vitest in Workers runtime (via scripts/vitest-filter-workerd.mjs)
npx vitest run test/check-spf.spec.ts       # Single spec
npm run build                               # tsup (npm pkg + stdio CLI)
npx wrangler dev                            # localhost:8787
npm run typecheck                           # tsc --noEmit
npm run typecheck:tests                     # per-file ratchet (baseline test/typecheck-baseline.json)
npm run lint[:fix]
npm run deploy:prod                         # Inject private bindings + deploy (OPERATOR-run)
npm run check:tool-surface                  # Verify advertised tool counts match TOOL_DEFS
npm run generate:tool-surface               # Rewrite them from the registry (after adding/removing a tool)
npm run audit:oss-safety                    # The required "File hygiene check" gate
npm run audit:docs-surface                  # The doc-prose audits (ci-docs.yml)
git config core.hooksPath .githooks         # One-time hook setup
scripts/worktree-setup.sh                   # New worktree: verify Node 22, npm ci, build dns-checks
```

⚠️ **Never symlink `node_modules`** into a new worktree — use
`scripts/worktree-setup.sh` (or plain `npm ci`). A symlink resolves the
`@blackveil/dns-checks` workspace package to the OTHER checkout's tree, so your
tests silently validate code you did not write (how #576 reached `main`). A
pre-commit gate + a CI job now block staged/tracked symlinks. Incident detail:
**`bv-mcp-operations`**.

## Tech

- **Runtime**: Cloudflare Workers — no Node.js APIs (`fetch`, `crypto`, Web only)
- **Framework**: Hono v4 · **TypeScript**: strict, ES2024, Bundler resolution, `isolatedModules`
- **Testing**: Vitest + `@cloudflare/vitest-pool-workers` (tests run inside the Workers runtime)
- **Tooling Node**: 22+ (Wrangler 4.x hard-fails on <22)
- **Formatter**: Prettier (tabs, single quotes, semi, 140 width) · **Package mgr**: npm

## Architecture

npm workspace. Root = Cloudflare Worker. `packages/dns-checks`
(`@blackveil/dns-checks`) is the runtime-agnostic core, published separately and
consumed via npm.

**Entrypoints**: `src/index.ts` (Worker/Hono), `src/package.ts` (npm),
`src/stdio.ts` (CLI), `src/internal.ts` (service binding), `src/scheduled.ts`
(cron).

```
src/mcp/         — Protocol: execute, dispatch, request parsing, route gates
src/schemas/     — Zod: primitives, tool-args + TOOL_SCHEMA_MAP, tool-definitions, json-rpc, internal, dns, session, auth
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

**Layering — where new code goes**: `packages/dns-checks/` is the
runtime-agnostic core with no Cloudflare deps; put logic there if it could run
outside Workers. `src/tools/` holds MCP wrappers + orchestration needing Workers
features (KV, DO, bindings) and depends on `@blackveil/dns-checks` via npm —
**keep backward compat**. Both publish together via the manual `npm publish`
path (currently gated off — #719).

**Request flow**:

- **Streamable HTTP**: `POST /mcp → Origin → Auth → Body → JSON-RPC validate → mcp/execute → handlers/tools → src/tools/check-* → lib/dns → DoH (empty → bv-dns → Google)`
- **SSE**: `GET /mcp` opens the notification stream (gate details in **`bv-mcp-security-surface`**)
- **Stdio**: `stdin → src/stdio → mcp/execute → handlers/tools → stdout`
- **Internal binding**: `POST /internal/tools/{call,batch} → guard (reject public) → handlers/tools → JSON (no MCP framing)`

**Operator-only tool families**: 11 recon tools call bv-recon via the `BV_RECON`
binding and fail soft to `unprovisioned` on BSL self-hosts; 4 M365
`identity_secops` tools are `INTERNAL_ONLY_TOOLS`. ⚠️ The internal-only gate
short-circuits BEFORE tier branching and shadows the `AUTH_REQUIRED_TOOLS` 401
path — deleting their `TOOL_DEFS` entries would delete the auth gate and the
seam contracts derived from them. Both families: **`bv-mcp-operations`**.

`scan_domain` runs 19 categories in parallel, 15s scan / 8s per check, 5-min
cache. Orchestration, post-processing and the maturity ladder:
**`bv-mcp-check-conventions`**.

## Scoring

Three-tier model (`computeScanScore`): **Core 70%**, **Protective 20%**,
**Hardening 10%** (bonus-only), across six profiles in
`packages/dns-checks/src/scoring/profiles.ts`. Full rule set, incident evidence,
corpus measurements and the weight-change checklist: **`bv-mcp-scoring`**.

Five traps restated here because they bite during tasks that never mention
scoring:

- ⚠️ **Measuring DNSSEC across a corpus: test `dnssec > 60`, NEVER `> 0`.** An
  unsigned zone sits at exactly 60 (fixed `penaltyOverride: 40`, not a zeroing)
  — `> 0` reports ~95–100% adoption against a true single-digit rate. Read
  `recordPresent`/`controlPresent` instead.
- ⚠️ **`missingControl` = "we MEASURED and the control is absent"; `inconclusive`
  + `errorKind` = "the probe never reached the origin".** Never both on one
  finding — recording a blocked or cut probe as absence zeroes a category nobody
  measured.
- ⚠️ **`SCORING_CONFIG.coreWeights` is INERT on the scan path** (it parses,
  validates, and changes no score — it was live in prod undetected for months).
  Express overrides as `profileWeights.<profile>`. Any weight change re-grades
  every customer: an operator decision.
- ⚠️ **`passed` = `score >= 50 && !hasMissingControl`** — "did not penalize",
  NOT "control exists". Four surfaces have misread it as a verdict (#705 #706
  #725 #809).
- ⚠️ **Grades come in TWO scales by role**: the canonical 9-band `scoreToGrade`
  is internal; customer-facing is the 6-band NIST scale via the ONE chokepoint
  `displayGradeFor` (`src/lib/ungraded-display.ts`), which returns `null` for
  ungraded scans — never fabricate an F.

## Conventions, checks and security

Two skills carry what used to live here; load the matching one before editing:

- **`bv-mcp-check-conventions`** — writing or changing a check: `createFinding`
  / `buildCheckResult`, the abstention shape (`checkStatus`, not
  `missingControl`), per-check fetch budgets (⚠️ a correctness change, not a
  latency one), bounded parallelism for serial-DoH cost (⚠️ `spf`/`ns`/`caa` are
  NOT candidates — DFS order is load-bearing on scored findings), caching and
  mutating-tool dedup, `scan_domain` post-processing, and the false-positive
  downgrades.
- **`bv-mcp-security-surface`** — SSRF and `safeFetch`, the six auth tiers and
  the owner IP gate, rate limits and quotas, paid-only gating, sessions, the
  `/internal/*` capability keys, OAuth plan→tier mapping, the client-visible
  error **allowlist** (a new error must start with an allowlisted prefix or it
  vanishes into a generic fallback), and the two protocol-version channels with
  opposite postures.

Two conventions kept here because they cause confusing CI failures far from the
edit:

- ⚠️ **`CheckResult` literal**: include both `passed: boolean` AND
  `findings: [] as Finding[]` — a bare `findings: []` infers `never[]` and
  breaks CI after a dns-checks DTS rebuild.
- ⚠️ **`.spec.ts` here** = Vitest unit/integration, **NOT** Playwright E2E. New
  mock-D1 integration files → `*.integration.test.ts`.

## Adding a New Tool

**First decide: scored or standalone?** A **scored** check gets a
`CheckCategory` and MUST be `scanIncluded: true` + wired into `scan_domain` —
otherwise it sits in the scoring denominator at 0. A **standalone/intelligence**
tool uses an out-of-union category label, `group: 'intelligence'`, no `tier`,
`scanIncluded: false`. **Never ship "scored + `scanIncluded: false`".** Full
annotated checklist: **`bv-mcp-add-tool`**.

## Testing

Patterns, DNS mocking, mock isolation, cache clearing, known flakes, wall-clock
budgets in specs, and the Analytics-Engine string-assertion trap:
**`bv-mcp-testing`**.

- Tests run **inside the Workers runtime**.
- **Dynamic imports are required** inside test fns for mock isolation:
  `const { checkSpf } = await import('../src/tools/check-spf');`

### Pre-commit (`.githooks/pre-commit`)

Five gates: (1) blocked paths (`docs/plans|code-review|superpowers/`, `.dev/`,
`.dev.vars*`, `.worktrees/`, generated deploy configs, reports, PDFs, `*.env*`);
(2) generated files (even with `git add -f`); (3) staged symlinks
(default-deny); (4) Gitleaks; (5) the repo-safety scanner (same as the required
`File hygiene check` CI gate). `--no-verify` only for reviewed false positives.

- ⚠️ **A four-part dotted standards citation trips BOTH secret scanners**
  (`N.N.N.N` scans as an IPv4). Reword to a spaced form (`§4.2.2 subsection 1`);
  do NOT widen the configs or `--no-verify`. Leave an in-file comment so nobody
  "tidies" it back.
- ⚠️ **40-hex action pins scan as phone numbers** — resolved by the
  `^\.github/workflows/` path allowlist in `.gitleaks.toml`'s `phone-number`
  rule. `--no-verify` buys nothing: `Secret & PII scan` is required CI, so the
  PR blocks at merge instead. Do not quote offending digit-runs in prose — that
  re-trips the rule in whatever file you write.

## CI/CD & Deploy

- **Required checks are exactly four**: `build-and-test`, `Secret & PII scan`,
  `Dependency audit`, `File hygiene check`. Everything else (`contract`,
  `fast-checks`, `typecheck-tests`, `dns-scan`, `registry-drift-check`) is
  advisory — a green-but-`BLOCKED` PR waits on one of the four.
- **Branch protection (SETTLED 2026-08-23)**: those four + `strict=true`, **NO
  required reviews** (deliberate — solo maintainer), `enforce_admins=true`,
  `required_conversation_resolution=true`, no force pushes. ⚠️ `PUT
  .../protection` is FULL-REPLACE — re-apply the whole canonical object, never a
  fragment. `mergeStateStatus: UNSTABLE` is mergeable once the required four pass.
- ⚠️ **`build-and-test` is reported by TWO workflows**: `ci.yml` (the real
  suite) and `ci-docs.yml` (docs-only PRs, which `ci.yml`'s `paths-ignore`
  skips). Their path lists are exact complements — keep them that way. Both must
  pass on a mixed PR; GitHub has no "or" semantics for a required name.
- **Deploy**: `npm run deploy:prod` run by an operator is THE authoritative
  path. `deploy-prod.yml` is dispatch-only and disarmed by default. ⚠️
  `deploy:prod` does NOT deploy bv-infra-probe — deploy it explicitly when its
  source changes.
- `typecheck-tests` is a per-file **ratchet** (baseline
  `test/typecheck-baseline.json`; bank improvements with `-- --update`).

Workflow inventory, deploy-mode narrative, private-config injection, the
service-binding door and the subrequest ceiling: **`bv-mcp-operations`**.

⚠️ **Release**: deploy and publish are **operator-run**, not tag-triggered — a
green Release run proves neither. Verify live `serverInfo.version` + the registry
with a cache-buster every time. Full flow: **`bv-mcp-release`**.

## Skill routing

| Need | Skill |
|---|---|
| Adding / removing / renaming a tool; anything touching `TOOL_DEFS` or the tool count | `bv-mcp-add-tool` |
| Writing or changing a check: findings, abstention, fetch budgets, parallelism, caching, scan post-processing, false-positive downgrades | `bv-mcp-check-conventions` |
| Weights, profiles, grade thresholds, `passed`, corpus adoption statistics | `bv-mcp-scoring` |
| Tests: Workers pool, DNS mocking, mock isolation, flakes, wall clock in specs, AE SQL | `bv-mcp-testing` |
| SSRF, auth tiers, quotas, gating, sessions, `/internal/*` keys, error wording, protocol versions, fuzzing | `bv-mcp-security-surface` |
| Bindings, workflows, deploy modes, analytics, subrequest ceiling, service-binding door | `bv-mcp-operations` |
| Version bump, changelog, tags, MCP Registry publish | `bv-mcp-release` |

Fleet-wide concerns (change control, cross-repo seams, shell portability,
verification discipline) live in the global skills — see `~/.claude/CLAUDE.md`.
