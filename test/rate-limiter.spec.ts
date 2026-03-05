import { describe, it, expect, afterEach, vi } from 'vitest';
import { checkRateLimit, resetRateLimit, resetAllRateLimits, getRateLimitStatus } from '../src/lib/rate-limiter';

afterEach(() => {
	resetAllRateLimits();
	vi.restoreAllMocks();
});

describe('rate-limiter', () => {
	describe('in-memory rate limiting', () => {
		it('should allow first request with correct remaining counts', async () => {
			const result = await checkRateLimit('1.2.3.4');
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(9);
			expect(result.hourRemaining).toBe(99);
		});

		it('should decrement remaining counts on multiple requests', async () => {
			await checkRateLimit('1.2.3.4');
			await checkRateLimit('1.2.3.4');
			const result = await checkRateLimit('1.2.3.4');
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(7);
			expect(result.hourRemaining).toBe(97);
		});

		it('should block 11th request within a minute', async () => {
			for (let i = 0; i < 10; i++) {
				const r = await checkRateLimit('1.2.3.4');
				expect(r.allowed).toBe(true);
			}
			const blocked = await checkRateLimit('1.2.3.4');
			expect(blocked.allowed).toBe(false);
			expect(blocked.minuteRemaining).toBe(0);
			expect(blocked.retryAfterMs).toBeGreaterThan(0);
		});

		it('should block at hour limit after minute windows rotate', async () => {
			const baseTime = 1000000000000;
			let currentTime = baseTime;
			vi.spyOn(Date, 'now').mockImplementation(() => currentTime);
			for (let window = 0; window < 10; window++) {
				currentTime = baseTime + window * 61_000;
				for (let i = 0; i < 10; i++) {
					const r = await checkRateLimit('1.2.3.4');
					expect(r.allowed).toBe(true);
				}
			}
			currentTime = baseTime + 10 * 61_000;
			const blocked = await checkRateLimit('1.2.3.4');
			expect(blocked.allowed).toBe(false);
			expect(blocked.hourRemaining).toBe(0);
			expect(blocked.retryAfterMs).toBeGreaterThan(0);
		});

		it('tracks different IPs independently', async () => {
			for (let i = 0; i < 10; i++) {
				await checkRateLimit('10.0.0.1');
			}
			const blockedA = await checkRateLimit('10.0.0.1');
			expect(blockedA.allowed).toBe(false);

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
			expect(status.hourRemaining).toBe(100);
		});
	});

	// -----------------------------------------------------------------------
	// KV-backed rate limiting
	// -----------------------------------------------------------------------
	describe('KV-backed rate limiting', () => {
		function createMockKV(minuteVal: string | null = null, hourVal: string | null = null) {
			return {
				get: vi.fn().mockResolvedValueOnce(minuteVal).mockResolvedValueOnce(hourVal),
				put: vi.fn().mockResolvedValue(undefined),
			} as unknown as KVNamespace;
		}

		it('allows request when under limits', async () => {
			const kv = createMockKV('3', '20');
			const result = await checkRateLimit('1.2.3.4', kv);
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(6); // 10 - (3+1)
			expect(result.hourRemaining).toBe(79); // 100 - (20+1)
		});

		it('blocks at minute limit', async () => {
			const kv = createMockKV('10', '30');
			const result = await checkRateLimit('1.2.3.4', kv);
			expect(result.allowed).toBe(false);
			expect(result.minuteRemaining).toBe(0);
			expect(result.retryAfterMs).toBeGreaterThan(0);
		});

		it('blocks at hour limit', async () => {
			const kv = createMockKV('5', '100');
			const result = await checkRateLimit('1.2.3.4', kv);
			expect(result.allowed).toBe(false);
			expect(result.hourRemaining).toBe(0);
			expect(result.retryAfterMs).toBeGreaterThan(0);
		});

		it('increments and writes counters with required key format and expirationTtl', async () => {
			const kv = createMockKV('3', '20');
			await checkRateLimit('1.2.3.4', kv);

			expect(kv.put).toHaveBeenCalledTimes(2);

			const minutePutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[0];
			expect(minutePutCall[0]).toContain('rl:min:1.2.3.4:');
			expect(minutePutCall[1]).toBe('4');
			expect(minutePutCall[2]).toEqual({ expirationTtl: 60 });

			const hourPutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[1];
			expect(hourPutCall[0]).toContain('rl:hr:1.2.3.4:');
			expect(hourPutCall[1]).toBe('21');
			expect(hourPutCall[2]).toEqual({ expirationTtl: 3600 });
		});

		it('falls back to in-memory on KV error', async () => {
			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn(),
			} as unknown as KVNamespace;

			const result = await checkRateLimit('1.2.3.4', kv);
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(9);
		});

		it('reads counters as null for new IP and writes initial values', async () => {
			const kv = createMockKV(null, null);
			const result = await checkRateLimit('1.2.3.4', kv);
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(9); // 10 - 1
			expect(result.hourRemaining).toBe(99); // 100 - 1

			const minutePutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[0];
			expect(minutePutCall[1]).toBe('1');
			const hourPutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[1];
			expect(hourPutCall[1]).toBe('1');
		});

		it('serializes concurrent KV checks per IP to reduce local race bypass', async () => {
			const kvState = new Map<string, string>();
			const kv = {
				get: vi.fn(async (key: string) => kvState.get(key) ?? null),
				put: vi.fn(async (key: string, value: string) => {
					kvState.set(key, value);
				}),
			} as unknown as KVNamespace;

			const attempts = 20;
			const results = await Promise.all(
				Array.from({ length: attempts }, () => checkRateLimit('203.0.113.10', kv)),
			);

			const allowedCount = results.filter((r) => r.allowed).length;
			expect(allowedCount).toBe(10);
			expect(results.some((r) => !r.allowed)).toBe(true);
		});
	});

	// -----------------------------------------------------------------------
	// checkRateLimit router
	// -----------------------------------------------------------------------
	describe('checkRateLimit routing', () => {
		it('uses in-memory path without KV arg', async () => {
			const result = await checkRateLimit('1.2.3.4');
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(9);
		});

		it('uses KV path when KV arg provided', async () => {
			const kv = {
				get: vi.fn().mockResolvedValue(null),
				put: vi.fn().mockResolvedValue(undefined),
			} as unknown as KVNamespace;

			await checkRateLimit('1.2.3.4', kv);

			expect(kv.get).toHaveBeenCalled();
		});
	});
});
