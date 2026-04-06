---
description: Use when adding or modifying MCP tools, DNS checks, schemas, handlers, scan orchestration, or scoring-related findings in this repository.
name: MCP Tool Implementation
applyTo: src/tools/check-*.ts
---
# MCP Tool Implementation

- Validate and normalize all domain input with validateDomain and sanitizeDomain from src/lib/sanitize.ts.
- Build findings and results with createFinding and buildCheckResult from src/lib/scoring.ts.
- Do not manually construct finding objects.
- Keep public error messages client-safe and prefixed with approved safe prefixes such as Missing required or Invalid.
- Preserve Cloudflare Workers compatibility. Avoid Node-only runtime APIs.
- Keep output behavior compatible with format compact and format full.
- Never hardcode secrets in tool code, tests, fixtures, scripts, or docs. Use env vars/secrets bindings only.

## Registration checklist for new tools

- Add schema in src/handlers/tool-schemas.ts.
- Register handler in src/handlers/tools.ts.
- Add scoring and category wiring where required.
- If included in scan flow, add orchestration in src/tools/scan-domain.ts.
- Add or update tests under test/.
- Update user-facing docs and tool listings.

## Caching and force refresh

- Use runWithCache for tool and scan caching consistency.
- Respect key patterns:
  - cache:<domain>
  - cache:<domain>:check:<name>
  - cache:<domain>:profile:<profile>
- Ensure force_refresh propagates cache bypass.

## Reference docs

- Architecture and conventions: [CLAUDE.md](../../CLAUDE.md)
- Contributor workflow: [CONTRIBUTING.md](../../CONTRIBUTING.md)
- Scoring details: [docs/scoring.md](../../docs/scoring.md)
- Client behavior and formats: [docs/client-setup.md](../../docs/client-setup.md)

## Secret handling checklist

- Use Worker secrets/bindings for production auth values.
- Keep local developer secrets in local-only files such as `.dev.vars` (gitignored).
- If a key is exposed, rotate immediately, update clients, and rerun secret scanning.
