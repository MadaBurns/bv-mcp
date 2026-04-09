---
description: Use when adding or modifying MCP tools, DNS checks, schemas, handlers, scan orchestration, or scoring-related findings in this repository.
name: MCP Tool Implementation
applyTo: src/tools/check-*.ts
---
# MCP Tool Implementation

- Validate and normalize all domain input with `validateDomain` and `sanitizeDomain` from `src/lib/sanitize.ts`.
- Build findings and results with `createFinding` and `buildCheckResult` from `src/lib/scoring.ts`.
- Do not manually construct finding objects.
- Keep public error messages client-safe and prefixed with approved safe prefixes such as `Missing required` or `Invalid`.
- Preserve Cloudflare Workers compatibility. Avoid Node-only runtime APIs.
- Return responses via `buildToolContent(text, structuredData, format)` from `src/handlers/tool-formatters.ts`. Full-format mode appends structured JSON automatically.
- Never hardcode secrets in tool code, tests, fixtures, scripts, or docs. Use env vars/secrets bindings only.

## Registration checklist for new tools

1. Create `src/tools/check-<name>.ts` → export async fn returning `CheckResult`
2. Add Zod schema to `src/schemas/tool-args.ts` (or use `BaseDomainArgs` if domain-only) + add to `TOOL_SCHEMA_MAP`
3. Add tool entry to `TOOL_DEFS` in `src/schemas/tool-definitions.ts` (name, description, schema, group, tier, scanIncluded)
4. Add to `TOOL_REGISTRY` in `src/handlers/tools.ts` (import + cacheKey + execute)
5. Add `CheckCategory` to union in `src/lib/scoring-model.ts` + `CATEGORY_DISPLAY_WEIGHTS`
6. Add to `IMPORTANCE_WEIGHTS` in `src/lib/scoring-engine.ts`
7. Add to `DEFAULT_SCORING_CONFIG` weights, profileWeights (all 5), baselineFailureRates in `scoring-config.ts`
8. Add to all 5 `PROFILE_WEIGHTS` maps in `context-profiles.ts`
9. Add to `FREE_TOOL_DAILY_LIMITS` in `config.ts`
10. Add explanation templates in `explain-finding-data.ts`
11. If part of `scan_domain`, add to parallel orchestration in `scan-domain.ts` (static import)
12. Add `test/check-<name>.spec.ts` using `dns-mock` helper pattern
13. Update README tools table

Note: `src/handlers/tool-schemas.ts` is a deprecated re-export shim. Import from `src/schemas/tool-definitions.ts` directly.

## Caching and force refresh

- Use `runWithCache` for tool and scan caching consistency.
- Respect key patterns:
  - `cache:<domain>`
  - `cache:<domain>:check:<name>`
  - `cache:<domain>:profile:<profile>`
- Ensure `force_refresh` propagates cache bypass.
- Per-tool cache TTL overrides via `cacheTtlSeconds` in `TOOL_REGISTRY` (e.g., `check_lookalikes: 3600`).

## Reference docs

- Architecture and conventions: [CLAUDE.md](../../CLAUDE.md)
- Contributor workflow: [CONTRIBUTING.md](../../CONTRIBUTING.md)
- Scoring details: [docs/scoring.md](../../docs/scoring.md)
- Client behavior and formats: [docs/client-setup.md](../../docs/client-setup.md)

## Secret handling checklist

- Use Worker secrets/bindings for production auth values.
- Keep local developer secrets in local-only files such as `.dev.vars` (gitignored).
- If a key is exposed, rotate immediately, update clients, and rerun secret scanning.
