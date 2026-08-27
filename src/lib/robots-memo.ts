// SPDX-License-Identifier: BUSL-1.1

import { ROBOTS_MAX_BODY_BYTES } from '@blackveil/dns-checks';
import { readBoundedOrNull } from './response-body';

/**
 * Per-scan robots.txt fetch memo (issue #641, recommendation 1).
 *
 * `withRobotsGate` (from `@blackveil/dns-checks`) memoizes the PARSED robots.txt
 * group per hostname, but only for the lifetime of the gated fetch function it
 * returns. `check-ssl.ts` builds a fresh gate on every invocation, so within one
 * `scan_domain` the `ssl` and `http_security` checks each paid their own
 * `https://<domain>/robots.txt` fetch — up to `ROBOTS_FETCH_TIMEOUT_MS` (3s) of
 * strictly sequential, blocking latency inside an 8s per-check budget. `ssl`'s
 * slow path is 3s (robots) + 4s (https) + 4s (http redirect probe) = 11s, i.e.
 * structurally incapable of finishing; removing a redundant robots fetch is the
 * cheapest 3s to remove because it changes nothing that is scored.
 *
 * This helper sits UNDERNEATH the gate rather than inside it: it wraps the
 * gate's own inner fetch and serves `/robots.txt` requests from a caller-owned
 * memo. Consequences, all deliberate:
 *
 * - **No `@blackveil/dns-checks` API change.** Each gate still parses and
 *   selects its own group (pure CPU, microseconds); only the network fetch is
 *   shared. So no package version bump and no bv-web-prod re-vendor.
 * - **Keyed by the full robots.txt URL**, so a memo can never serve domain A's
 *   robots.txt for domain B — the key IS the origin. Cross-domain contamination
 *   is impossible by construction, not by convention.
 * - **Lifetime is owned by the caller.** There is no module-level state here;
 *   `scan-domain.ts` creates one memo per `scanDomain()` invocation and lets it
 *   fall out of scope with the scan. A long-lived Worker isolate, and
 *   `/internal/tools/batch` fanning one tool across 500 domains, therefore never
 *   accumulate anything through this module.
 * - **Pass-through when no memo is supplied** (`withAbortSignal`'s convention):
 *   every direct `check_ssl` / `check_http_security` tool call, and every BSL
 *   self-host path that does not opt in, gets the original function object back
 *   and is byte-for-byte unchanged.
 *
 * ## Are failed robots.txt fetches memoized? Yes — deliberately.
 *
 * A fetch that throws (connection failure, or the gate's own 3s
 * `AbortSignal.timeout`) is recorded as a failure snapshot and replayed to
 * subsequent callers as an equivalent throw. That is NOT a cached
 * "allowed"/"disallowed" decision: the gate's own `catch` turns any failure into
 * `null` — "no applicable group" — which is its documented FAIL-OPEN default,
 * and is exactly what each check would independently have concluded. The memo
 * can therefore only ever replay fail-open; it can never manufacture a
 * `RobotsDisallowedError` that a live fetch would not have produced.
 *
 * The alternative — evicting failures so a later check retries — was rejected
 * on measurement, not taste: a host whose robots.txt stalls is precisely the
 * pathology this fixes, so retrying re-pays the full 3s per check and the fix
 * does nothing in the case that motivated it. Worse, it would make `ssl` itself
 * SLOWER: `checkSSL` fetches `https://` and then `http://` on the same host
 * through the same gate, so an evicted failure would be re-fetched a second time
 * inside one check. The persisted failure is bounded to a single scan (≤15s), so
 * a transient blip cannot outlive the request that observed it.
 */

/** A `fetch`-shaped function this helper can wrap. */
type MemoizableFetch = (input: string, init?: RequestInit) => Promise<Response>;

/**
 * The recorded outcome of one robots.txt fetch. Deliberately a plain value, not
 * a `Response`: a `Response` body can only be consumed once, so replaying one
 * would hand the second caller a locked/disturbed stream.
 */
type RobotsSnapshot =
	| { readonly ok: true; readonly status: number; readonly body: string }
	| { readonly ok: false; readonly name: string; readonly message: string };

/**
 * Opaque per-scan memo. Create with {@link createRobotsFetchMemo} and pass the
 * SAME instance to every check that should share robots.txt fetches.
 */
export interface RobotsFetchMemo {
	/** Keyed by the absolute robots.txt URL — the origin is part of the key. */
	readonly entries: Map<string, Promise<RobotsSnapshot>>;
}

/** Create an empty memo. One per scan; never share one across domains-as-a-batch. */
export function createRobotsFetchMemo(): RobotsFetchMemo {
	return { entries: new Map() };
}

/**
 * Statuses the Fetch spec forbids a body on — constructing `new Response(body, …)`
 * with one of these throws, so replay them body-less.
 */
const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);

/** Rebuild a fresh, independently-readable `Response` (or re-throw) from a snapshot. */
function replay(snapshot: RobotsSnapshot): Response {
	if (!snapshot.ok) {
		const error = new Error(snapshot.message);
		error.name = snapshot.name;
		throw error;
	}
	const body = snapshot.body === '' || NULL_BODY_STATUSES.has(snapshot.status) ? null : snapshot.body;
	return new Response(body, { status: snapshot.status });
}

/** Drain a body we are not going to hand on, without risking an unhandled rejection. */
function drain(response: Response): void {
	void response.body?.cancel().catch(() => undefined);
}

/**
 * Run the real fetch once and reduce it to a replayable snapshot.
 *
 * Mirrors the gate's own consumption exactly: a non-OK response has its body
 * cancelled and carries no text (the gate returns `null` without reading it), an
 * OK response is read only up to the shared robots.txt byte cap, and any throw
 * becomes a failure snapshot. A status
 * outside 200–599 cannot be reconstructed by the `Response` constructor, so it is
 * recorded as a failure — which the gate turns into the same `null` (fail-open)
 * that a non-OK status would have produced.
 */
async function snapshotRobotsFetch(run: () => Promise<Response>): Promise<RobotsSnapshot> {
	try {
		const response = await run();
		if (response.status < 200 || response.status > 599) {
			drain(response);
			return { ok: false, name: 'RobotsUnreplayableStatusError', message: `robots.txt response status ${response.status} is not replayable` };
		}
		if (!response.ok) {
			drain(response);
			return { ok: true, status: response.status, body: '' };
		}
		const body = response.body ? await readBoundedOrNull(response.body, ROBOTS_MAX_BODY_BYTES) : '';
		if (body === null) {
			return {
				ok: false,
				name: 'RobotsBodyReadError',
				message: 'robots.txt body exceeded the byte limit or could not be read',
			};
		}
		return { ok: true, status: response.status, body };
	} catch (err) {
		return {
			ok: false,
			name: err instanceof Error ? err.name : 'Error',
			message: err instanceof Error ? err.message : String(err),
		};
	}
}

/**
 * Wrap a fetch function so `/robots.txt` requests are fetched at most once per
 * URL for the memo's lifetime. Every other URL passes straight through
 * untouched.
 *
 * Returns `fetchFn` ITSELF when `memo` is undefined, so opting out costs nothing
 * and preserves referential identity.
 *
 * Note on abort signals: the first caller's `init` (including the gate's 3s
 * `AbortSignal.timeout` and any composed per-check signal) drives the single
 * shared fetch. A later caller awaiting it therefore inherits the first caller's
 * cancellation — bounded, because the gate's own 3s timeout is always part of
 * that composition, and harmless, because an aborted robots.txt fetch degrades
 * fail-open exactly as an independently-timed-out one would.
 */
export function withRobotsFetchMemo<F extends MemoizableFetch>(fetchFn: F, memo?: RobotsFetchMemo): F {
	if (!memo) return fetchFn;
	const wrapped = async (input: string, init?: RequestInit): Promise<Response> => {
		let key: string;
		try {
			const parsed = new URL(String(input));
			if (parsed.pathname !== '/robots.txt') return await fetchFn(input as Parameters<F>[0], init);
			key = parsed.href;
		} catch {
			// Not a parseable absolute URL (never produced by the gate) — do not memoize.
			return await fetchFn(input as Parameters<F>[0], init);
		}
		let pending = memo.entries.get(key);
		if (!pending) {
			pending = snapshotRobotsFetch(() => fetchFn(input as Parameters<F>[0], init));
			memo.entries.set(key, pending);
		}
		return replay(await pending);
	};
	return wrapped as F;
}
