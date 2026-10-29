# CLAUDE.md

Guidance for Claude Code working in this repo.

**This file is deliberately lean — keep it under 200 lines** (`wc -l
CLAUDE.md`). It carries orientation, the gotchas that bite during unrelated
tasks, and pointers; depth lives in `.claude/skills/` (routing table at the
bottom). Trimmed 2026-09-11 and again 2026-10-26.

## What is this?

Blackveil DNS — source-available DNS & email security scanner, built as a
Cloudflare Worker.
81 public tools (86 registered in `TOOL_DEFS`; 5 internal-only via
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

⚠️ **Never symlink `node_modules`** into a new worktree — it resolves
`@blackveil/dns-checks` to the OTHER checkout, so tests validate code you did
not write (#576). Use `scripts/worktree-setup.sh`. **`bv-mcp-operations`**.

## Tech

- **Runtime**: Cloudflare Workers — no Node.js APIs (`fetch`, `crypto`, Web only) · **Framework**: Hono v4 · **TypeScript**: strict, ES2024, Bundler, `isolatedModules`
- **Testing**: Vitest + `@cloudflare/vitest-plugin`, inside the Workers runtime · **Tooling Node**: 22+ (Wrangler 4.x hard-fails on <22)
- **Formatter**: Prettier (tabs, single quotes, semi, 140 width) · **Package mgr**: npm

## Architecture

npm workspace. Root = Cloudflare Worker. `packages/dns-checks`
(`@blackveil/dns-checks`) is the runtime-agnostic core, published separately and
consumed via npm. `packages/bv-whois` is the WHOIS-over-TCP/43-to-HTTPS shim
sidecar Worker for the RDAP fallback path, deployed via `npm run deploy:whois`.

**Entrypoints**: `src/index.ts` (Worker/Hono), `src/package.ts` (npm),
`src/stdio.ts` (CLI), `src/internal.ts` (service binding), `src/scheduled.ts`
(cron).

Directory map (`src/mcp`, `schemas`, `handlers`, `tools`, `oauth`, `tenants`,
`lib`, `test/`) and the four request flows (Streamable HTTP, SSE, stdio,
internal binding): **`bv-mcp-operations`** § Source layout and request flow.

**Layering — where new code goes**: `packages/dns-checks/` is the
runtime-agnostic core with no Cloudflare deps; put logic there if it could run
outside Workers. `src/tools/` holds MCP wrappers + orchestration needing Workers
features (KV, DO, bindings) and depends on `@blackveil/dns-checks` via npm —
**keep backward compat**. Both publish together via the manual `npm publish`
path (currently gated off — #719).

**Operator-only tool families** (11 `BV_RECON` recon tools; 4 M365
`INTERNAL_ONLY_TOOLS`): ⚠️ never delete their `TOOL_DEFS` entries — the auth
gate and seam contracts are derived from them. **`bv-mcp-operations`**.

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

- ⚠️ **DNSSEC across a corpus: test `dnssec > 60`, NEVER `> 0`** — an unsigned
  zone sits at exactly 60, so `> 0` reports ~95–100% adoption.
- ⚠️ **`missingControl` = measured and absent; `inconclusive` + `errorKind` =
  the probe never reached the origin.** Never both on one finding.
- ⚠️ **`SCORING_CONFIG.coreWeights` is INERT on the scan path** — use
  `profileWeights.<profile>`. Any weight change re-grades every customer.
- ⚠️ **`passed` = `score >= 50 && !hasMissingControl`** — "did not penalize",
  NOT "control exists" (misread four times: #705 #706 #725 #809).
- ⚠️ **Customer-facing grades go through `displayGradeFor`**
  (`src/lib/ungraded-display.ts`, 6-band NIST), which returns `null` for
  ungraded scans — never fabricate an F.

## Conventions, checks and security

Load **`bv-mcp-check-conventions`** before writing or changing a check, and
**`bv-mcp-security-surface`** before touching SSRF, auth, quotas or error text.
Two traps from them: a per-check fetch-budget change is a correctness change,
not a latency one; and a new client-visible error must start with an
allowlisted prefix or it vanishes into a generic fallback.

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
**`bv-mcp-testing`**. **Dynamic imports are required** inside test fns for mock
isolation: `const { checkSpf } = await import('../src/tools/check-spf');`

### Pre-commit (`.githooks/pre-commit`)

Five gates: blocked paths, generated files, staged symlinks, Gitleaks, and the
repo-safety scanner. `--no-verify` only for reviewed false positives. ⚠️ A
four-part dotted standards citation and 40-hex action pins trip the secret
scanners — reword, never widen the configs. The gate list and both traps:
**`bv-mcp-operations`** § Pre-commit gates.

## CI/CD & Deploy

- **Required checks are exactly four**: `build-and-test`, `Secret & PII scan`,
  `Dependency audit`, `File hygiene check`. Everything else (`contract`,
  `fast-checks`, `typecheck-tests`, `dogfood-scan`) is
  advisory — a green-but-`BLOCKED` PR waits on one of the four.
- **Branch protection (SETTLED 2026-08-23)**: those four + `strict=true`, **NO
  required reviews** (deliberate — solo maintainer), `enforce_admins=true`. ⚠️
  `PUT .../protection` is FULL-REPLACE — re-apply the whole canonical object.
- ⚠️ **`build-and-test` is reported by TWO workflows** (`ci.yml` and
  `ci-docs.yml`, exact path complements — keep them that way), and in `ci.yml`
  it is a same-name aggregator over `preflight` + `test-shard`; the job id and
  `name:` must stay `build-and-test`. Detail: **`bv-mcp-operations`**.
- **Deploy**: `npm run deploy:prod` run by an operator is THE authoritative
  path. `deploy-prod.yml` is dispatch-only and disarmed by default. ⚠️
  `deploy:prod` deploys the MCP Worker ONLY — the three sidecars ship via `npm run
  deploy:whois`, `deploy:infra-probe` and `deploy:ct-index`. Since #945 the
  `check:sidecar-freshness` gate runs early in both deploy chains and **BLOCKS**,
  fail-closed, when a sidecar's live deployment predates its source (override
  `BV_ALLOW_STALE_SIDECARS=1`).
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
| Reviewing and merging the open-PR backlog: required vs advisory checks, the same-name `build-and-test` hole, strict-serialization order, post-merge worktree/ticket hygiene | `bv-mcp-merge-queue` |
| Version bump, changelog, tags, MCP Registry publish | `bv-mcp-release` |

Fleet-wide concerns (change control, cross-repo seams, shell portability,
verification discipline) live in the global skills — see `~/.claude/CLAUDE.md`.
