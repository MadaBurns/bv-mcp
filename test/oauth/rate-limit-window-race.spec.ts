// SPDX-License-Identifier: BUSL-1.1

/**
 * The OAuth rate limiter must not deny a principal whose window expired IN FLIGHT (#985).
 *
 * WHY THIS FILE EXISTS.
 * `consumeOAuthRateLimit` aligns its window on the caller's clock, but the coordinator is
 * what judges it: `handleReserveBudget` refuses outright when `expiresAt <= now`. A request
 * that computes its window a few milliseconds before a 60-second boundary therefore arrives
 * with a window that has already ended. The refusal reaches the endpoint as `exceeded: true`
 * with no `unavailable` — a 429 telling a caller who has spent NOTHING that it has made too
 * many requests.
 *
 * This is what made `test/oauth/token.spec.ts` flaky on a REQUIRED gate in a way that giving
 * each test its own bucket could not fix: the failing assertion sat inside a loop of 30 that
 * already used a unique IP, so bucket sharing was never the explanation for that instance.
 *
 * `nowMs` pins the window deterministically, so these tests reproduce on demand what CI hit
 * by luck.
 *
 * `nowMs` alone was not enough (#1072). Pinning it to the CURRENT window left `expiresAt`
 * somewhere in the next 60 real seconds, so on a loaded runner a long burst could outlive its
 * own pinned window: the coordinator then refuses mid-burst as expired, the retry recomputes
 * into the next window, and the count-exact assertions below see a counter that restarted.
 * `pinRateLimitWindow()` therefore pins BOTH clocks the code consults — it freezes `Date.now`
 * (which the retry path reads, `src/oauth/rate-limit.ts:127`) on a window several minutes
 * ahead of real time, so the coordinator cannot judge it expired part-way through. The cases
 * that are ABOUT an already-ended window keep using a real, genuinely past instant.
 */

import { env } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { consumeOAuthRateLimit } from '../../src/oauth/rate-limit';
import { pinRateLimitWindow } from '../helpers/rate-limit-window';

/** A fresh documentation-range address, so every case starts on an unused principal. */
function uniquePrincipal(): string {
	const words = new Uint16Array(4);
	crypto.getRandomValues(words);
	return `2001:db8:0:0:${Array.from(words, (word) => word.toString(16)).join(':')}`;
}

function limiterOptions(overrides: { principal: string; nowMs?: number }) {
	return {
		kv: env.SESSION_STORE,
		quotaCoordinator: env.QUOTA_COORDINATOR,
		coordinationScope: 'token',
		kvKey: `oauth:token-rl:${overrides.principal}`,
		principal: overrides.principal,
		limit: 30,
		windowSeconds: 60,
		...(overrides.nowMs === undefined ? {} : { nowMs: overrides.nowMs }),
	};
}

describe('OAuth rate limit — a window that expires in flight (#985)', () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('admits a fresh principal whose aligned window had already ended', async () => {
		const principal = uniquePrincipal();
		// One whole window in the past: `expiresAt` is behind real `Date.now()` by the time
		// the coordinator sees it. That is the boundary race, made deterministic.
		const expiredNowMs = Date.now() - 61_000;
		// The retry reads `Date.now()`; pin it so the window it recomputes cannot itself expire.
		pinRateLimitWindow();
		const result = await consumeOAuthRateLimit(limiterOptions({ principal, nowMs: expiredNowMs }));

		expect(result.exceeded, 'a principal that has spent nothing must not be rate limited').toBe(false);
		expect(result.retryAfterSeconds).toBe(0);
		// A 503 would be just as wrong as a 429 here: the coordinator answered.
		expect(result.unavailable).toBeUndefined();
	});

	it('still denies a principal that genuinely exhausted its budget', async () => {
		// The retry must not become a way around the limit: it recomputes the window, so a
		// caller inside ONE live window still gets exactly `limit` admissions.
		const principal = uniquePrincipal();
		const nowMs = pinRateLimitWindow().nowMs;
		const statuses: boolean[] = [];
		for (let i = 0; i < 31; i++) {
			const result = await consumeOAuthRateLimit(limiterOptions({ principal, nowMs }));
			statuses.push(result.exceeded);
		}

		expect(statuses.slice(0, 30).every((exceeded) => exceeded === false), 'first 30 admitted').toBe(true);
		expect(statuses[30], 'the 31st is denied').toBe(true);
	});

	it('charges the retry to the window the request actually landed in', async () => {
		// After the in-flight expiry the reservation belongs to the CURRENT window, so a
		// following request in that same window sees the retry's spend.
		const principal = uniquePrincipal();
		const expiredNowMs = Date.now() - 61_000;
		// Pinned BEFORE the expired-window call, so the retry lands in the same window the
		// follow-up burst uses — that shared window is what "the window it landed in" means.
		const now = pinRateLimitWindow().nowMs;
		await consumeOAuthRateLimit(limiterOptions({ principal, nowMs: expiredNowMs }));

		const results: boolean[] = [];
		for (let i = 0; i < 30; i++) {
			results.push((await consumeOAuthRateLimit(limiterOptions({ principal, nowMs: now }))).exceeded);
		}

		// 1 (the retry) + 29 admitted = 30; the 30th call in this loop is the 31st overall.
		expect(results.filter((exceeded) => exceeded === false)).toHaveLength(29);
		expect(results[29], 'the request past the limit is denied').toBe(true);
	});

	it('reports unavailable rather than 429 when the retry ALSO lands on an expired window (SQ-99)', async () => {
		// Extremely low reachability: this needs TWO consecutive window-boundary races — one on
		// the initial attempt and one on the immediate retry, which recomputes from `Date.now()`
		// specifically so it lands in a live window. A real double race isn't practically
		// reproducible from wall-clock timing, so the coordinator response is mocked directly.
		// If this retry's expired-window refusal reached the endpoint as plain `exceeded: true`,
		// it would 429 a principal that spent NOTHING — the exact defect #985/#1011 fixed for
		// attempt 0, just one retry later.
		const quotaCoordinator = await import('../../src/lib/quota-coordinator');
		vi.spyOn(quotaCoordinator, 'reserveBudgetWithCoordinator').mockResolvedValue({
			allowed: false,
			used: 0,
			remaining: 30,
			limit: 30,
		});

		const { consumeOAuthRateLimit: consume } = await import('../../src/oauth/rate-limit');
		const principal = uniquePrincipal();
		const result = await consume(limiterOptions({ principal, nowMs: Date.now() }));

		expect(result.unavailable, 'a principal that has spent nothing must not be 429ed').toBe(true);
		expect(result.exceeded).toBe(true);
	});
});
