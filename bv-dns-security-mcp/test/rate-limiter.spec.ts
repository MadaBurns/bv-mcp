import { describe, it, expect, vi, afterEach } from 'vitest';
import {
	checkRateLimit,
	getRateLimitStatus,
	resetRateLimit,
	resetAllRateLimits,
	type RateLimitResult,
} from '../src/lib/rate-limiter';

afterEach(() => {
	resetAllRateLimits();
	vi.restoreAllMocks();
});

describe('rate-limiter', () => {
	// -----------------------------------------------------------------------
	// In-memory rate limiting
	// -----------------------------------------------------------------------
	describe('in-memory rate limiting', () => {
		it('allows first request with correct remaining counts', async () => {
			const result = await checkRateLimit('1.2.3.4');
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(9);
			expect(result.hourRemaining).toBe(49);
		});

		it('decrements remaining counts on multiple requests', async () => {
			await checkRateLimit('1.2.3.4');
			await checkRateLimit('1.2.3.4');
			const result = await checkRateLimit('1.2.3.4');
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(7);
			expect(result.hourRemaining).toBe(47);
		});

		it('blocks 11th request within a minute', async () => {
			for (let i = 0; i < 10; i++) {
				const r = await checkRateLimit('1.2.3.4');
				expect(r.allowed).toBe(true);
			}
			const blocked = await checkRateLimit('1.2.3.4');
			expect(blocked.allowed).toBe(false);
			expect(blocked.minuteRemaining).toBe(0);
			expect(blocked.retryAfterMs).toBeGreaterThan(0);
		});

		it('blocks at hour limit after minute windows rotate', async () => {
			const baseTime = 1000000000000;
			let currentTime = baseTime;
			vi.spyOn(Date, 'now').mockImplementation(() => currentTime);

			// Send 10 requests per minute window across 5 windows = 50 total
			for (let window = 0; window < 5; window++) {
				currentTime = baseTime + window * 61_000; // advance past minute boundary
				for (let i = 0; i < 10; i++) {
					const r = await checkRateLimit('1.2.3.4');
					expect(r.allowed).toBe(true);
				}
			}

			// 51st request in a new minute window should be blocked by hour limit
			currentTime = baseTime + 5 * 61_000;
			const blocked = await checkRateLimit('1.2.3.4');
			expect(blocked.allowed).toBe(false);
			expect(blocked.hourRemaining).toBe(0);
			expect(blocked.retryAfterMs).toBeGreaterThan(0);
		});

		it('tracks different IPs independently', async () => {
			// Exhaust limit for IP A
			for (let i = 0; i < 10; i++) {
				await checkRateLimit('10.0.0.1');
			}
			const blockedA = await checkRateLimit('10.0.0.1');
			expect(blockedA.allowed).toBe(false);

			// IP B should still be allowed
			const resultB = await checkRateLimit('10.0.0.2');
			expect(resultB.allowed).toBe(true);
			expect(resultB.minuteRemaining).toBe(9);
		});

		it('resetRateLimit clears a single IP', async () => {
			for (let i = 0; i < 10; i++) {
				await checkRateLimit('1.2.3.4');
			}
			const blocked = await checkRateLimit('1.2.3.4');
			expect(blocked.allowed).toBe(false);

			resetRateLimit('1.2.3.4');

			const after = await checkRateLimit('1.2.3.4');
			expect(after.allowed).toBe(true);
			expect(after.minuteRemaining).toBe(9);
		});

		it('resetAllRateLimits clears all state', async () => {
			for (let i = 0; i < 10; i++) {
				await checkRateLimit('1.2.3.4');
			}
			await checkRateLimit('5.6.7.8');

			resetAllRateLimits();

			const resultA = await checkRateLimit('1.2.3.4');
			expect(resultA.allowed).toBe(true);
			expect(resultA.minuteRemaining).toBe(9);

			const resultB = await checkRateLimit('5.6.7.8');
			expect(resultB.allowed).toBe(true);
			expect(resultB.minuteRemaining).toBe(9);
		});
	});

	// -----------------------------------------------------------------------
	// getRateLimitStatus (read-only)
	// -----------------------------------------------------------------------
	describe('getRateLimitStatus', () => {
		it('returns status without consuming a request', async () => {
			await checkRateLimit('1.2.3.4'); // consume 1 request
			const status1 = getRateLimitStatus('1.2.3.4');
			const status2 = getRateLimitStatus('1.2.3.4');
			expect(status1.minuteRemaining).toBe(status2.minuteRemaining);
			expect(status1.hourRemaining).toBe(status2.hourRemaining);
		});

		it('returns full remaining for unknown IP', () => {
			const status = getRateLimitStatus('unknown-ip');
			expect(status.allowed).toBe(true);
			expect(status.minuteRemaining).toBe(10);
			expect(status.hourRemaining).toBe(50);
		});
	});
});
