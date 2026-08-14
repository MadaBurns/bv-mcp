// SPDX-License-Identifier: BUSL-1.1

/**
 * Per-check fetch budget (issue #641).
 *
 * A check that issues several SEQUENTIAL fetches, each with its own fixed
 * `AbortSignal.timeout`, can be structurally incapable of finishing inside the
 * budget its caller allows it. `check_ssl` was the measured case: the robots.txt
 * gate (3s) → `https://` (4s) → `http://` redirect probe (4s) sum to **11s inside
 * an 8s per-check budget**, so on any host where the first two legs run slow the
 * outer `safeCheck` killed the check mid-flight and `scan_domain` lost the whole
 * `ssl` category — 12 of 21 cold scans in the #641 investigation.
 *
 * Losing the category is the expensive part. The HTTPS/HSTS posture had usually
 * been measured successfully by then; only the last leg was outstanding. The
 * category still went to `null`, the score moved 3–4 points, and a warm re-run of
 * the same healthy domain produced a different grade — purely from cache state.
 *
 * This wrapper makes the overrun impossible by construction rather than by
 * arithmetic: every fetch is composed with a signal derived from what is LEFT of
 * the budget, so the last leg gets whatever the earlier ones did not spend. A
 * check now degrades by dropping its final, least-important probe instead of
 * losing everything it had already measured.
 *
 * Why not simply raise `PER_CHECK_TIMEOUT_MS`: the per-check budget is
 * load-bearing for the 15s whole-scan ceiling (19 categories fan out in
 * parallel), so raising it to cover the worst-case sum trades a lost category for
 * a lost scan. #641 rejected that explicitly.
 *
 * Conservative by design, like `withAbortSignal` next door: no budget → the
 * original `fetchFn` is returned unchanged, so every direct `check_ssl` call and
 * every BSL self-host path keeps byte-for-byte current behaviour.
 */

import { composeSignal } from './abort-signal';

/**
 * Below this much remaining budget a fetch is not worth issuing: it would consume
 * one of the Workers per-invocation subrequests and almost certainly abort before
 * a response head arrives. Rejecting instead of issuing keeps that subrequest for
 * a check that can still use it.
 */
const MIN_USEFUL_FETCH_MS = 200;

/**
 * ⚠️ Load-bearing wording. `@blackveil/dns-checks`'s `checkHttps` classifies a
 * thrown fetch by SUBSTRING — `err.message.includes('timeout') || .includes('abort')`
 * — to decide between `inconclusive: 'timeout'` and `'error'`. Budget exhaustion is
 * a timeout in every sense that matters to that decision, so the message contains
 * the literal token deliberately. Reword it and an exhausted budget starts being
 * reported as a connection error instead.
 *
 * Second, quieter constraint: this string starts with none of the prefixes
 * `sanitizeErrorMessage()` allowlists, so if a future adopter lets the rejection
 * PROPAGATE to a client rather than swallowing it (as `checkSSL` does), the caller
 * sees the generic fallback, not this text. Fine today; a trap for the next check
 * that adopts the budget and expects the message to survive.
 */
const BUDGET_EXHAUSTED_MESSAGE = 'Fetch budget exhausted before this request (timeout)';

/**
 * One deadline, shared by every external call a check makes.
 *
 * A check's outbound work is rarely all plain `fetch`: `check_ssl` also calls the
 * bv-tls-probe SERVICE BINDING, which bypasses `fetchFn` entirely and carries its
 * own fixed 8s timeout. Budgeting only the fetches would have left the paid/operator
 * path — the only deployment where that binding is bound — able to blow the 8s
 * per-check budget exactly as before, which is why this is a deadline object rather
 * than a lone fetch wrapper: everything that can spend time reads the same clock.
 */
export interface FetchBudget {
	/**
	 * Wrap a `fetch`-compatible function so each call is bounded by what remains.
	 * No budget → returns `fetchFn` unchanged (same reference).
	 */
	wrap<F extends (input: never, init?: RequestInit) => Promise<Response>>(fetchFn: F): F;
	/** Milliseconds left before the deadline; `Infinity` when there is no budget. */
	remainingMs(): number;
	/**
	 * Whether enough budget remains to be worth issuing another external call —
	 * the same predicate `wrap` applies, so callers that check it and callers that
	 * simply try cannot disagree about where the line sits.
	 */
	canIssueRequest(): boolean;
	/**
	 * A signal that aborts at the deadline, composed with `caller` when supplied.
	 * For non-`fetch` callees (service bindings) that accept a signal but enforce
	 * their own fixed timeout. No budget → returns `caller` untouched.
	 */
	signal(caller?: AbortSignal): AbortSignal | undefined;
}

/**
 * Open a budget. The clock starts NOW, so create it immediately before handing
 * anything to the check — the deadline has to cover work the check does not
 * control (notably the robots.txt fetch the gate performs inside the first call),
 * which is precisely the cost that pushed `check_ssl` over its budget.
 *
 * @param budgetMs - total wall-clock all external calls may collectively consume;
 *   `undefined` yields an inert budget that changes nothing
 */
export function createFetchBudget(budgetMs: number | undefined): FetchBudget {
	const startedAt = Date.now();
	const remainingMs = () => (budgetMs === undefined ? Infinity : budgetMs - (Date.now() - startedAt));
	const canIssueRequest = () => remainingMs() > MIN_USEFUL_FETCH_MS;
	return {
		remainingMs,
		canIssueRequest,
		wrap<F extends (input: never, init?: RequestInit) => Promise<Response>>(fetchFn: F): F {
			if (budgetMs === undefined) return fetchFn;
			const wrapped = (input: Parameters<F>[0], init?: RequestInit) => {
				if (!canIssueRequest()) {
					return Promise.reject(new Error(BUDGET_EXHAUSTED_MESSAGE));
				}
				// Composed, never substituted: the package's own per-fetch timeout still
				// applies, and whichever fires first wins. The budget can only ever make a
				// fetch SHORTER, so a check that already fits its budget is untouched.
				return fetchFn(input, composeSignal(init, AbortSignal.timeout(remainingMs())));
			};
			return wrapped as F;
		},
		signal(caller?: AbortSignal): AbortSignal | undefined {
			if (budgetMs === undefined) return caller;
			const deadline = AbortSignal.timeout(Math.max(1, remainingMs()));
			return caller ? AbortSignal.any([deadline, caller]) : deadline;
		},
	};
}

/**
 * Wrap a `fetch`-compatible function so each call is bounded by what remains of
 * `budgetMs`, measured from the moment this wrapper was CREATED.
 *
 * Convenience over {@link createFetchBudget} for checks whose only external work
 * is `fetch`. A check that ALSO calls a service binding must open the budget
 * itself, or that call escapes the deadline.
 *
 * @param fetchFn - the fetch to wrap (already gated/abort-composed as needed)
 * @param budgetMs - total wall-clock these fetches may collectively consume;
 *   `undefined` returns `fetchFn` unchanged
 */
export function withFetchBudget<F extends (input: never, init?: RequestInit) => Promise<Response>>(
	fetchFn: F,
	budgetMs: number | undefined,
): F {
	return createFetchBudget(budgetMs).wrap(fetchFn);
}

/**
 * The share of a per-check budget that may be spent on network fetches.
 *
 * The remainder covers the check's own non-fetch work — parsing robots groups,
 * building findings, scoring — plus enough slack that our own abort lands BEFORE
 * the outer `safeCheck` killer rather than racing it. Losing that race is the
 * whole failure being fixed: `safeCheck` firing first discards every finding the
 * check had already produced.
 */
export function fetchBudgetFor(perCheckTimeoutMs: number): number {
	return Math.max(1_000, perCheckTimeoutMs - 750);
}
