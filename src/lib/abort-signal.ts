// SPDX-License-Identifier: BUSL-1.1

/**
 * Abort-signal composition helpers (R7 — abort, not just abandon, in-flight
 * subrequests on per-check/scan timeout).
 *
 * The raw-`fetch` checks (check-ssl, check-http-security) and the
 * `@blackveil/dns-checks` package functions they delegate to already apply
 * their OWN per-fetch `AbortSignal.timeout(...)`. To additionally let a
 * caller-level (scan-/per-check-level) timeout cancel those in-flight fetches
 * — instead of letting the orphaned subrequests keep draining the Cloudflare
 * Workers per-invocation subrequest budget — we compose the caller signal with
 * whatever signal the fetch `init` already carries via `AbortSignal.any`.
 *
 * Conservative by design: when no caller signal is supplied (every direct
 * `check_ssl` / `check_http_security` call, and every BSL self-host path that
 * doesn't opt in), these helpers are pure pass-throughs — the existing
 * timeout-only behaviour is byte-for-byte unchanged.
 */

/**
 * Compose a caller-supplied abort `signal` with a fetch `init.signal` that's
 * already present (e.g. the package's `AbortSignal.timeout`). Either source
 * aborting cancels the fetch.
 *
 * - No caller signal → returns `init` unchanged (pure pass-through).
 * - No pre-existing `init.signal` → attaches the caller signal alone.
 * - Both present → `AbortSignal.any([...])` (standard Web API, available in
 *   workerd) so the first to fire wins.
 */
export function composeSignal(init: RequestInit | undefined, callerSignal: AbortSignal | undefined): RequestInit | undefined {
	if (!callerSignal) return init;
	const existing = init?.signal ?? undefined;
	const combined = existing ? AbortSignal.any([existing, callerSignal]) : callerSignal;
	return { ...(init ?? {}), signal: combined };
}

/**
 * Wrap a `fetch`-compatible function so every call composes the caller signal
 * with the per-call `init.signal`. Returns the original `fetchFn` unchanged
 * when no caller signal is supplied (zero-overhead, behaviour-preserving).
 */
export function withAbortSignal<F extends (input: never, init?: RequestInit) => Promise<Response>>(
	fetchFn: F,
	callerSignal: AbortSignal | undefined,
): F {
	if (!callerSignal) return fetchFn;
	const wrapped = (input: Parameters<F>[0], init?: RequestInit) => fetchFn(input, composeSignal(init, callerSignal));
	return wrapped as F;
}
