# Security and Observability

Canonical reference for runtime security behavior, request handling, and observability in `bv-mcp`.

## Security Controls

- Input validation: Domain inputs are sanitized and validated before checks run.
- SSRF protections: Internal/reserved targets and known unsafe patterns are blocked.
- Authentication: Optional bearer token via `BV_API_KEY`.
- Error sanitization: Unknown internal errors are not exposed directly to clients.
- Runtime constraints: Cloudflare Workers only (Web APIs, no Node.js APIs).

## Authentication Model

- When `BV_API_KEY` is unset/empty, `/mcp` runs in open mode.
- When `BV_API_KEY` is configured, `/mcp` requires `Authorization: Bearer <token>`.
- Invalid/missing bearer token returns HTTP `401`.
- `/health` remains unauthenticated.

## Rate Limiting

Canonical implementation lives in `src/lib/rate-limiter.ts`.

- Per-IP limit: `10` requests/minute and `100` requests/hour.
- Enforcement backend: KV when bound; in-memory fallback when KV is unavailable.
- Scope: `tools/call` traffic is counted.
- Protocol methods (`initialize`, `tools/list`, `resources/*`, `ping`, `notifications/*`) are not counted.
- Authenticated requests (valid bearer token) bypass rate limiting.

## Request and Session Safety

- Maximum request body size on `/mcp`: `10 KB`.
- Client IP source: `cf-connecting-ip`.
- Session storage supports KV-backed state with in-memory fallback.
- Session idle timeout is enforced with sliding refresh.

## Logging and Observability

Structured JSON events are emitted for request lifecycle, tool calls, and failures.

Common fields include:

- Timestamp
- Request ID
- Client IP
- Tool name
- Domain
- Result/grade/status
- Severity
- Duration (ms)
- User agent

## Data Flow and Privacy

- DNS lookups are performed against Cloudflare DoH (`cloudflare-dns.com/dns-query`).
- The service does not call arbitrary third-party endpoints for scan logic.
- Optional provider detection signatures may be loaded from a deployment-configured URL (`PROVIDER_SIGNATURES_URL`) for `check_mx` and `scan_domain` inference.
- When configured signature fetch fails, detection falls back to stale cache (if available) and then built-in signatures.
- External log export is optional and deployment-controlled.

## Canonical Code References

- `src/lib/sanitize.ts`
- `src/lib/config.ts`
- `src/lib/auth.ts`
- `src/lib/rate-limiter.ts`
- `src/lib/log.ts`
- `src/lib/session.ts`
- `src/index.ts`
