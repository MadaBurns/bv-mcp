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

The maintained checklist is the numbered list in [CONTRIBUTING.md](../../CONTRIBUTING.md) ("Adding a New Tool"), and the
full annotated one, with every audit a new tool trips, is [`.claude/skills/bv-mcp-add-tool/SKILL.md`](../../.claude/skills/bv-mcp-add-tool/SKILL.md).
Key points that older copies of this list got wrong:

- `CheckCategory`, `CATEGORY_TIERS` and `CATEGORY_DISPLAY_WEIGHTS` live in `packages/dns-checks/src/types.ts` (`model.ts` only re-exports them).
- Weights go in all **6** `PROFILE_WEIGHTS` maps in `packages/dns-checks/src/scoring/profiles.ts`, the single source of weight values.
- A scored check joins `scan_domain` by adding one entry to `CHECK_DISPATCH` in `src/tools/scan-domain.ts`; `SCAN_CATEGORIES`, the fan-out and the retry switch derive from it.
- Bump `EXPECTED_TOOL_COUNT` in `test/audits/tool-count-ssot.audit.test.ts`, run `npm run generate:tool-surface`, and rebuild dns-checks (`npm -w packages/dns-checks run build`).

Note: tool schemas are defined in `src/schemas/tool-definitions.ts` (TOOL_DEFS); import `TOOLS` / `TOOL_SCHEMA_MAP` from there.

## Caching and force refresh

- Use `runWithCache` for tool and scan caching consistency.
- Build cache keys with `buildScanCacheKey` / `buildCheckCacheKey` (`src/lib/cache.ts`). They are versioned: `cache:v<serverVersion>-dc<dnsChecksVersion>:<domain>[:check:<name>|:profile:<profile>]`.
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
