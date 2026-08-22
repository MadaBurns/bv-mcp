---
name: bv-mcp-add-tool
description: "Use when adding, removing, or renaming an MCP tool in the bv-mcp / blackveil-dns repo — anything that touches TOOL_DEFS in src/schemas/tool-definitions.ts or changes the tool count. Symptoms: 'Missing required parameter: domain' on a new tool, toHaveLength(N) spec failures, a category-count or score-snapshot assertion failing, or an audit failing in CI after a tool change."
---

# Adding / Removing a bv-mcp Tool

A tool definition is **single-source-of-truth (SSOT) replicated across ~25 surfaces**. Miss one and CI fails — or worse, the tool ships half-wired and silently returns `unprovisioned` / `Missing required parameter: domain`. Work the checklist top to bottom, **rebuild `@blackveil/dns-checks` if you touched it**, then **run the full suite** (`npm test`) — many audits exist specifically to catch the surfaces a human forgets.

## Decide first: scored or not? (this determines the blast radius)

- **A scored check** gets a `CheckCategory` and participates in scoring. If scored, it **must** be `scanIncluded: true` and wired into `scan_domain` — otherwise it sits in the scoring denominator forever at 0 and **lowers every domain's score** (the three-tier engine counts ALL `CATEGORY_TIERS` members, run or not). Mirror `check_dane`: `group: 'infrastructure'`, `tier: 'hardening'`, `scanIncluded: true`.
- **A standalone / intelligence tool** (`check_dnssec_chain`, `check_nsec_walkability`, `check_fast_flux`) uses an **out-of-union category label** (NOT in the `CheckCategory` union), `group: 'intelligence'`, no `tier`, `scanIncluded: false`. It is NOT scored — skip every scoring surface below.

"Scored + `scanIncluded: false`" is the one combination to never ship.

## Checklist (create a TodoWrite item per line)

**The tool + scoring (scoring steps 2–6 are SCORED tools only):**
1. `src/tools/check-<name>.ts` — async fn returning `CheckResult`. Follow `check-spf.ts`; catch top-level DNS errors → return, never throw. (Hardening/bonus checks: absence is `info`, not `missingControl`.)
2. `packages/dns-checks/src/types.ts` — **NOT model.ts** (model.ts only re-exports). Add the member to the `CheckCategory` union, to `CATEGORY_TIERS` (core|protective|**hardening**), and to `CATEGORY_DISPLAY_WEIGHTS`.
3. `packages/dns-checks/src/scoring/engine.ts` — `IMPORTANCE_WEIGHTS`.
4. `packages/dns-checks/src/scoring/config.ts` — `DEFAULT_SCORING_CONFIG`: `weights`, **all 6** `profileWeights` rows (incl. `authoritative_dns_infra`), `baselineFailureRates`.
5. `packages/dns-checks/src/scoring/profiles.ts` — **all 6** `PROFILE_WEIGHTS` (mail_enabled, enterprise_mail, non_mail, web_only, minimal, **authoritative_dns_infra**).
6. **Rebuild dns-checks:** `npm -w packages/dns-checks run build`. Worker code + tests import the built `dist/`, not `src/` — without this, typecheck and tests won't see the new category and `createFinding('<cat>')` errors.
7. `src/schemas/tool-args.ts` — Zod schema + `TOOL_SCHEMA_MAP`.
8. `src/schemas/tool-definitions.ts` — `TOOL_DEFS` entry (the SSOT). The `scanIncluded: true` flag auto-appends "Part of the scan_domain audit." to the description.
9. `src/handlers/tools.ts` — import + `TOOL_REGISTRY` (cacheKey + execute).
10. `src/lib/config.ts` — `FREE_TOOL_DAILY_LIMITS` (or add to `INTENTIONALLY_UNLIMITED_TOOLS` — the `tool-quota-coverage` audit requires exactly one).
11. `src/tools/explain-finding-data.ts` — optional (no audit enforces it): `CATEGORY_TO_CHECKTYPE` is a curated partial map; add a `CATEGORY_FALLBACK_IMPACT` entry for product completeness.
12. **If scored + in scan**: wire `src/tools/scan-domain.ts` at **3 hardcoded places** + the static import: `ALL_CHECK_CATEGORIES`, the `checkPromises` `runCachedCheck(...)` array, and the `runCheckRetry()` switch. (The `scanIncluded` flag in TOOL_DEFS does NOT drive runtime — scan-domain.ts is hardcoded.)
13. `test/check-<name>.spec.ts` using the `dns-mock` helper (see **bv-mcp-testing**).
14. **No `domain` arg** (uses `domains[]`, `auditId`, …)? The schema's `domain` field drives `toolRequiresDomain()`; a domain-less tool must be handled (see `test/audits/domain-required-ssot.audit.test.ts`) else calls return "Missing required parameter: domain".
15. **New `ToolRuntimeOptions` field for a binding?** Extend `BvMcpEnv` AND populate at all 3 construction sites in `src/index.ts` — else `ro.<field>` is undefined and the tool returns `{ unprovisioned: true }`.

**Count surface — ONE tripwire (everything else derives):**
- The tool count is hardcoded in exactly **one** place: bump `EXPECTED_TOOL_COUNT` in `test/audits/tool-count-ssot.audit.test.ts`. The 7 former count specs (`index`, `tool-metadata`, `tool-schemas`, `handlers-tools`, `tool-output-schema`, `schemas/tool-args`, `schemas/tool-definitions`) now assert against `TOOLS.length`/the registry — do **NOT** re-add a magic `toHaveLength(N)` to them.
- **CheckResult vs custom-shape:** a custom-shape (non-CheckResult) tool is added to **`NON_CHECK_RESULT_TOOLS` in `src/schemas/tool-definitions.ts`** (the exported SSOT set — it drives `outputSchema` population). A normal CheckResult tool needs no edit here and no count bump.
- **Scan membership:** if `scanIncluded`, add the tool to **`EXPECTED_SCAN_DOMAIN_TOOLS`** in `tool-schemas.spec.ts` (exact-set tripwire on the scoring-critical scan set). Non-scan tools need no edit — the partition is derived from `scanIncluded`.
- ⚠️ `handlers-prompts.spec.ts`'s `toHaveLength(7)` is the **prompts** count — leave it.

**Audits / surfaces NOT obvious from the code (these fail in CI):**
16. **Per-tool quota** — `tool-quota-coverage` + `tier-tool-daily-limits` + `public-quota-surface` audits (step 10).
17. **Advertised counts — DO NOT hand-edit.** Run **`npm run generate:tool-surface`**. It derives `PUBLIC_TOOL_COUNT` (`TOOLS.length − INTERNAL_ONLY_TOOLS.size`) and rewrites all 13 count tokens across `README.md`, `docs/github-settings.md`, `extensions/vscode/{README.md,package.json}`, `server.json` and `smithery.yaml`. Verify with `npm run check:tool-surface`. The token table is `scripts/tool-surface-tokens.ts`; if the generator reports a pattern that "did not match", the prose changed shape and the regex there needs updating — that is drift, not a no-op.
18. **`EXPECTED_TOOL_COUNT`** in `test/audits/tool-count-ssot.audit.test.ts` is the ONE count you still bump by hand. That is deliberate — it is the human-acknowledgement gate on a tool-surface change, and the generator is forbidden from touching it. Enforcement of the prose lives in `test/audits/tool-surface-prose.audit.test.ts` (inside the REQUIRED `build-and-test` job); `npm run check:tool-surface` also runs in the non-required `fast-checks` for a faster message.
19. **Generated Rust permissions** — run `npm run generate:wasm-permissions` (verified by `check:wasm-permissions` in CI).
20. **Chaos matrix** — `test/chaos/varied-domain-all-tools.chaos.test.ts` asserts its case list equals the registry; add a case.
21. **Scored tools only — dns-checks scoring specs (TWO copies each):** `scoring-model.spec.ts` asserts `CATEGORY_TIERS` length + the per-tier counts ("N hardening categories"); `scoring-profiles.spec.ts` has **score snapshots that shift** when you add a scored category. Both exist at `packages/dns-checks/src/__tests__/scoring/` **and** duplicated at `test/`. Update all four. Review the snapshot deltas — don't blind-bump (see **bv-mcp-scoring**).

## Verify

```bash
npm -w packages/dns-checks run build   # if you touched dns-checks (step 6)
npm run typecheck && npm run lint && npm test
```

The known full-suite flake (`workerd … WebSocket peer disconnected` / "Worker exited unexpectedly" at teardown, ~8 errors, 0 test failures) is **not** real — see **bv-mcp-testing**. Confirm by re-running any genuinely-failing spec in isolation.

## Red flags

- "It typechecks, so it's wired" → typecheck misses quota coverage, README/vscode drift, the chaos matrix, and the scoring-count invariants. Run the suite.
- "I edited the scoring src and the test still sees the old behavior" → you didn't rebuild dns-checks (step 6).
- "I'll just bump the red `toHaveLength`" → the **tool count** now lives in ONE tripwire (`tool-count-ssot.audit.test.ts`); the old per-spec `toHaveLength(N)` are gone (derived). But other surfaces still need edits: the scan exact-set (`EXPECTED_SCAN_DOMAIN_TOOLS`), `NON_CHECK_RESULT_TOOLS` for custom-shape tools, the scoring-model counts, README/vscode/server.json prose, and the chaos matrix. Work the whole list.
- Adding a scored category as `scanIncluded: false` → lowers every domain's score. Make it `scanIncluded: true` or use an out-of-union label.
- `findings: []` bare → infers `never[]`, breaks CI after a dns-checks DTS rebuild. Use `findings: [] as Finding[]` + `passed: boolean`.

## Provenance

Moved here from the fleet-global `bv-cc` skills library (`~/.claude/skills/`) on 2026-08-03. It is bv-mcp-specific, so as a global skill its description competed for context in every session on every repo — including repos it can never apply to. Scoping it to this repo is the "scope skills to specific paths so they only activate in the relevant part" rule from Anthropic's large-codebase guidance.

Keep it here. If a fact in it turns out to be cross-repo (a seam bv-web-prod also depends on), the cross-repo half belongs in `fleet-architecture`, not back in the global library.
