# Security and Observability

Canonical reference for runtime security behavior, request handling, and observability in `bv-mcp`.

## Security Controls

- Input validation: Domain inputs are sanitized and validated before checks run.
- IP literal blocking: IPv4 literals are rejected across standard and alternate numeric forms (short-form, octal, hex, dword, and dotted-numeric payloads).
- SSRF protections: Internal/reserved targets and known unsafe patterns are blocked.
- Authentication: Optional bearer token via `BV_API_KEY`.
- Error sanitization: Unknown internal errors are not exposed directly to clients.
- Runtime constraints: Cloudflare Workers only (Web APIs, no Node.js APIs).

Examples rejected by validation include `127.1`, `0177.0.0.1`, `8.8.8.8`, `0x8.0x8.0x8.0x8`, and `999.999.999.999`.

## Authentication Model

- When `BV_API_KEY` is unset/empty, `/mcp` runs in open mode.
- When `BV_API_KEY` is configured, `/mcp` requires `Authorization: Bearer <token>`.
- Invalid/missing bearer token returns HTTP `401`.
- `/health` remains unauthenticated.

## Rate Limiting

Canonical implementation lives in `src/lib/rate-limiter.ts`.

- Per-IP limit: `10` requests/minute and `100` requests/hour.
- Separate unauthenticated control-plane limit: `30` requests/minute and `300` requests/hour.
- Enforcement backend: KV when bound; in-memory fallback when KV is unavailable.
- KV-backed checks now serialize per-IP updates within an isolate to reduce local race amplification.
- Scope: `tools/call` traffic uses the stricter budget; protocol/session methods use the control-plane budget.
- Authenticated requests (valid bearer token) bypass rate limiting.

Note: KV counters remain fixed-window and are not globally atomic across isolates.

## Request and Session Safety

- Maximum request body size on `/mcp`: `10 KB`.
- Client IP source: `cf-connecting-ip`.
- Session storage supports KV-backed state with in-memory fallback.
- Session idle timeout is enforced with sliding refresh.
- Session refresh writes are coalesced to reduce repeated KV mutation pressure.
- Session creation is rate-limited per IP (`30` session creations/minute) for unauthenticated traffic, using KV when available.
- In-memory session fallback is bounded with least-recently-used eviction (`2000` max active sessions).

## Logging and Observability

Structured JSON events are emitted for request lifecycle, tool calls, and failures.
When configured, Cloudflare Analytics Engine also receives low-cardinality usage events.

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

Sensitive values such as bearer tokens, session identifiers, cookies, and raw request bodies are redacted before emission.

### Analytics Engine Usage Events

Optional binding: `MCP_ANALYTICS` (Analytics Engine dataset).

The worker emits two event families:

- `mcp_request`: one event per handled `/mcp` request (JSON or SSE response path)
- `tool_call`: one event for each tool execution in `tools/call`

Privacy notes:

- Tool-level events include a stable hashed domain identifier instead of raw domain values.
- Event payloads are fail-open; telemetry failures never affect MCP responses.

Suggested query fields:

- `indexes[0]`: event type (`mcp_request`, `tool_call`)
- Request attributes in blobs (`method`, `transport`, `status`, `auth-mode`, `jsonrpc-flag`)
- Tool attributes in blobs (`tool-name`, `status`, `error-flag`, `hashed-domain`)
- `doubles[0]`: duration in milliseconds

### Analytics Query Pack

Use these query patterns in Analytics Engine to build usage reporting:

- Request volume by method/transport:
	- Group `mcp_request` by `blobs[0]` (method) and `blobs[1]` (transport).
- Error rate over time:
	- Filter `mcp_request` where `blobs[2] = 'error'`, divide by total `mcp_request`.
- Latency tracking (p95):
	- Compute percentile from `doubles[0]` grouped by `blobs[0]` (method) for `mcp_request` or `blobs[0]` (tool name) for `tool_call`.
- Tool health ratio:
	- Group `tool_call` by `blobs[1]` (`pass`/`fail`/`error`).
- Auth split:
	- Group `mcp_request` by `blobs[3]` (`auth` vs `anon`).

### Analytics Runbook

1. Verify binding after deploy: deploy output should list `env.MCP_ANALYTICS`.
2. Verify runtime mode: check logs for category `analytics` with result `enabled` or `disabled`.
3. Verify ingestion: run one `initialize` and one `tools/call`, then confirm both `mcp_request` and `tool_call` events are present.
4. If events are missing:
	 - Confirm dataset binding exists in the active Wrangler config used for deployment.
	 - Confirm the worker version in production matches the latest deploy.
	 - Trigger fresh requests and re-check Analytics Engine after propagation delay.
5. Privacy check: confirm tool event blob value is hashed domain (`d_<hex>`), never a raw domain.

## Data Flow and Privacy

- DNS lookups are performed against Cloudflare DoH (`cloudflare-dns.com/dns-query`).
- The service does not call arbitrary third-party endpoints for scan logic.
- Optional provider detection signatures may be loaded from a deployment-configured URL (`PROVIDER_SIGNATURES_URL`) for `check_mx` and `scan_domain` inference.
- Runtime provider-signature sources must use HTTPS and are validated against a pinned SHA-256 digest (`PROVIDER_SIGNATURES_SHA256`).
- Deployments may further restrict runtime signature fetches to specific hosts with `PROVIDER_SIGNATURES_ALLOWED_HOSTS`.
- Runtime-loaded provider signatures are cached in-isolate for 5 minutes to reduce repeated fetch latency during active traffic.
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
