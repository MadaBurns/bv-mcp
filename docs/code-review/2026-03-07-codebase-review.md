# Code Review: Codebase

**Ready for Production**: Yes
**Critical Issues**: 0

## Remediation Status
- Reviewed findings from the initial audit have been remediated in the current codebase.
- Validation completed with `npm run typecheck` and `npm test`.
- Current status: no known outstanding issues from this review remain open.

## Priority 1 (Must Fix)
- Resolved: Unauthenticated control-plane traffic now uses a separate distributed budget and session refreshes are coalesced. Implemented in [src/index.ts](/Applications/Github/bv-mcp/src/index.ts#L278), [src/index.ts](/Applications/Github/bv-mcp/src/index.ts#L343), [src/index.ts](/Applications/Github/bv-mcp/src/index.ts#L585), [src/index.ts](/Applications/Github/bv-mcp/src/index.ts#L625), [src/lib/rate-limiter.ts](/Applications/Github/bv-mcp/src/lib/rate-limiter.ts#L158), and [src/lib/session.ts](/Applications/Github/bv-mcp/src/lib/session.ts#L198).

## Recommended Changes
- Resolved: Sensitive request and session data are redacted before logging. Implemented in [src/index.ts](/Applications/Github/bv-mcp/src/index.ts#L150), [src/index.ts](/Applications/Github/bv-mcp/src/index.ts#L245), [src/index.ts](/Applications/Github/bv-mcp/src/index.ts#L563), [src/lib/log.ts](/Applications/Github/bv-mcp/src/lib/log.ts#L22), and [src/lib/audit.ts](/Applications/Github/bv-mcp/src/lib/audit.ts#L30).
- Resolved: Runtime provider signatures now require HTTPS, support host allowlisting, and verify pinned SHA-256 content integrity. Implemented in [src/lib/provider-signatures.ts](/Applications/Github/bv-mcp/src/lib/provider-signatures.ts#L39), [src/lib/provider-signatures.ts](/Applications/Github/bv-mcp/src/lib/provider-signatures.ts#L193), [src/tools/check-mx.ts](/Applications/Github/bv-mcp/src/tools/check-mx.ts#L78), [src/tools/scan-domain.ts](/Applications/Github/bv-mcp/src/tools/scan-domain.ts#L100), and [docs/client-setup.md](/Applications/Github/bv-mcp/docs/client-setup.md#L131).

## Testing Gaps
- Added regression coverage for control-plane throttling, session refresh coalescing, log redaction, and provider-signature verification in [test/index.spec.ts](/Applications/Github/bv-mcp/test/index.spec.ts), [test/session.spec.ts](/Applications/Github/bv-mcp/test/session.spec.ts), [test/log.spec.ts](/Applications/Github/bv-mcp/test/log.spec.ts), [test/rate-limiter.spec.ts](/Applications/Github/bv-mcp/test/rate-limiter.spec.ts), and [test/provider-signatures.spec.ts](/Applications/Github/bv-mcp/test/provider-signatures.spec.ts).

## Detailed Findings

### High: Unmetered protocol and session traffic enables unauthenticated control-plane DoS

Status: resolved.

Only `tools/call` was previously protected by the distributed rate limiter, while protocol methods and session-oriented endpoints were exempt. The fix adds a separate control-plane rate limit and reduces session-store churn by coalescing refresh writes.

Validation: covered by [test/index.spec.ts](/Applications/Github/bv-mcp/test/index.spec.ts#L872), [test/rate-limiter.spec.ts](/Applications/Github/bv-mcp/test/rate-limiter.spec.ts#L278), and [test/session.spec.ts](/Applications/Github/bv-mcp/test/session.spec.ts#L46).

### Medium: Session tokens and raw client payloads are exposed to logs

Status: resolved.

The previous logging path could emit session identifiers and raw malformed request bodies. The fix sanitizes headers and nested log data before emission and audit logging now records only session presence.

Validation: covered by [test/index.spec.ts](/Applications/Github/bv-mcp/test/index.spec.ts#L332) and [test/log.spec.ts](/Applications/Github/bv-mcp/test/log.spec.ts#L8).

### Low: Runtime provider-signature loading lacks authenticity enforcement

Status: resolved.

Runtime provider-signature loading previously trusted configured remote JSON without authenticity checks. The fix requires HTTPS, optional hostname allowlisting, and a pinned SHA-256 digest before runtime data is accepted.

Validation: covered by [test/provider-signatures.spec.ts](/Applications/Github/bv-mcp/test/provider-signatures.spec.ts#L46).