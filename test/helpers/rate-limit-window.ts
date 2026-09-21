// SPDX-License-Identifier: BUSL-1.1
/**
 * Pin the aligned rate-limit window a test's requests are counted into (#1072).
 *
 * WHY THIS EXISTS. `consumeOAuthRateLimit` derives its coordination key from an ALIGNED
 * window — `Math.floor(now / windowMs) * windowMs` (`src/oauth/rate-limit.ts:128-140`) — so
 * a burst that happens to span a wall-clock minute boundary is counted into TWO keys. The
 * request past the limit is then legitimately admitted, because in its own window it is only
 * the first or second request. That is correct fixed-window behaviour, and it is what made
 * the count-exact OAuth rate-limit specs flaky: the ASSERTION assumed one window, the limiter
 * never promised one. Exposure scales with burst duration over the window length, which is
 * why the same commit goes red under load and green in isolation.
 *
 * Two clocks decide the outcome, and this helper handles both:
 *
 *  - The CALLER's clock picks the window. `SELF.fetch` dispatches the Worker inside the test
 *    isolate, so spying on `Date.now` pins the window for the code under test as well
 *    (measured: advancing this pin by one window makes a blocked 11th registration return
 *    201 again, which cannot happen if the Worker reads a different clock).
 *  - The COORDINATOR's clock judges the window: `handleReserveBudget` refuses outright when
 *    `expiresAt <= Date.now()` (`src/lib/quota-coordinator.ts:1460-1463`). That Durable
 *    Object has its own real clock and this spy does not reach it. The pin therefore sits
 *    several windows in the FUTURE, so the window it names cannot expire against real time
 *    part-way through a burst however slow or contended the runner is.
 *
 * Pinning is the fix, not a retry or a sleep: with `Date.now` frozen there is no boundary
 * left to straddle, so the count-exact assertions become deterministic rather than likely.
 */
import { vi } from 'vitest';

/** The OAuth per-IP minute window, mirroring `REGISTER_MINUTE_WINDOW_SECONDS`. */
export const RATE_LIMIT_WINDOW_MS = 60_000;

/**
 * How far ahead of real time the pinned window sits. Five windows leaves at least five
 * real minutes before the coordinator would consider the window expired — orders of
 * magnitude more than a count-exact burst takes even on a saturated runner.
 */
const PIN_AHEAD_WINDOWS = 5;

/** One second into the window, so nothing sits exactly on a boundary. */
const OFFSET_INTO_WINDOW_MS = 1_000;

export interface PinnedRateLimitWindow {
	/** The frozen instant every `Date.now()` call now returns; pass it as `nowMs` where the API takes one. */
	readonly nowMs: number;
	/** Move the pin into the NEXT aligned window — used to reproduce a boundary crossing on demand. */
	advanceToNextWindow(): number;
}

/**
 * Freeze `Date.now` inside a single aligned rate-limit window, several windows in the future.
 * Restore it with `vi.restoreAllMocks()` in an `afterEach`.
 */
export function pinRateLimitWindow(windowMs: number = RATE_LIMIT_WINDOW_MS): PinnedRateLimitWindow {
	let pinned = (Math.floor(Date.now() / windowMs) + PIN_AHEAD_WINDOWS) * windowMs + OFFSET_INTO_WINDOW_MS;
	vi.spyOn(Date, 'now').mockImplementation(() => pinned);
	return {
		get nowMs(): number {
			return pinned;
		},
		advanceToNextWindow(): number {
			pinned = Math.floor(pinned / windowMs) * windowMs + windowMs + OFFSET_INTO_WINDOW_MS;
			return pinned;
		},
	};
}
