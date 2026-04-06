import { describe, it, expect, afterEach, vi } from 'vitest';
import {
	checkControlPlaneRateLimit,
	checkRateLimit,
	checkToolDailyRateLimit,
	checkGlobalDailyLimit,
	resetRateLimit,
	resetAllRateLimits,
	resetGlobalDailyLimit,
	resetQuotaCoordinatorBreaker,
	acquireConcurrencySlot,
	releaseConcurrencySlot,
	resetConcurrencyLimits,
} from '../src/lib/rate-limiter';

afterEach(() => {
	resetAllRateLimits();
	resetGlobalDailyLimit();
	resetQuotaCoordinatorBreaker();
	resetConcurrencyLimits();
	vi.restoreAllMocks();
});

describe('rate-limiter', () => {
	describe('in-memory rate limiting', () => {
		it('should allow first request with correct remaining counts', async () => {
			const result = await checkRateLimit('1.2.3.4');
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(49);
			expect(result.hourRemaining).toBe(299);
		});

		it('should decrement remaining counts on multiple requests', async () => {
			await checkRateLimit('1.2.3.4');
			await checkRateLimit('1.2.3.4');
			const result = await checkRateLimit('1.2.3.4');
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(47);
			expect(result.hourRemaining).toBe(297);
		});

		it('should block 51st request within a minute', async () => {
			for (let i = 0; i < 50; i++) {
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
			// 50 per minute × ~7 windows = 350 > 300 hour limit
			for (let window = 0; window < 7; window++) {
				currentTime = baseTime + window * 61_000;
				for (let i = 0; i < 50; i++) {
					const r = await checkRateLimit('1.2.3.4');
					if (!r.allowed) break;
				}
			}
			currentTime = baseTime + 7 * 61_000;
			const blocked = await checkRateLimit('1.2.3.4');
			expect(blocked.allowed).toBe(false);
			expect(blocked.hourRemaining).toBe(0);
			expect(blocked.retryAfterMs).toBeGreaterThan(0);
		});

		it('tracks different IPs independently', async () => {
			for (let i = 0; i < 50; i++) {
				await checkRateLimit('10.0.0.1');
			}
			const blockedA = await checkRateLimit('10.0.0.1');
			expect(blockedA.allowed).toBe(false);

			const resultB = await checkRateLimit('10.0.0.2');
			expect(resultB.allowed).toBe(true);
			expect(resultB.minuteRemaining).toBe(49);
		});

		it('resetRateLimit clears a single IP', async () => {
			for (let i = 0; i < 50; i++) {
				await checkRateLimit('1.2.3.4');
			}
			const blocked = await checkRateLimit('1.2.3.4');
			expect(blocked.allowed).toBe(false);

			resetRateLimit('1.2.3.4');

			const after = await checkRateLimit('1.2.3.4');
			expect(after.allowed).toBe(true);
			expect(after.minuteRemaining).toBe(49);
		});

		it('resetAllRateLimits clears all state', async () => {
			for (let i = 0; i < 50; i++) {
				await checkRateLimit('1.2.3.4');
			}
			await checkRateLimit('5.6.7.8');

			resetAllRateLimits();

			const resultA = await checkRateLimit('1.2.3.4');
			expect(resultA.allowed).toBe(true);
			expect(resultA.minuteRemaining).toBe(49);

			const resultB = await checkRateLimit('5.6.7.8');
			expect(resultB.allowed).toBe(true);
			expect(resultB.minuteRemaining).toBe(49);
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
			expect(result.minuteRemaining).toBe(46); // 50 - (3+1)
			expect(result.hourRemaining).toBe(279); // 300 - (20+1)
		});

		it('blocks at minute limit', async () => {
			const kv = createMockKV('50', '100');
			const result = await checkRateLimit('1.2.3.4', kv);
			expect(result.allowed).toBe(false);
			expect(result.minuteRemaining).toBe(0);
			expect(result.retryAfterMs).toBeGreaterThan(0);
		});

		it('blocks at hour limit', async () => {
			const kv = createMockKV('5', '300');
			const result = await checkRateLimit('1.2.3.4', kv);
			expect(result.allowed).toBe(false);
			expect(result.hourRemaining).toBe(0);
			expect(result.retryAfterMs).toBeGreaterThan(0);
		});

		it('increments and writes counters with required key format and window-relative expirationTtl', async () => {
			const kv = createMockKV('3', '20');
			await checkRateLimit('1.2.3.4', kv);

			expect(kv.put).toHaveBeenCalledTimes(2);

			const minutePutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[0];
			expect(minutePutCall[0]).toContain('rl:min:1.2.3.4:');
			expect(minutePutCall[1]).toBe('4');
			// TTL is remaining time in window (1-60s for minute, 1-3600s for hour)
			const minuteTtl = minutePutCall[2].expirationTtl;
			expect(minuteTtl).toBeGreaterThanOrEqual(1);
			expect(minuteTtl).toBeLessThanOrEqual(60);

			const hourPutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[1];
			expect(hourPutCall[0]).toContain('rl:hr:1.2.3.4:');
			expect(hourPutCall[1]).toBe('21');
			const hourTtl = hourPutCall[2].expirationTtl;
			expect(hourTtl).toBeGreaterThanOrEqual(1);
			expect(hourTtl).toBeLessThanOrEqual(3600);
		});

		it('falls back to in-memory on KV error', async () => {
			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn(),
			} as unknown as KVNamespace;

			const result = await checkRateLimit('1.2.3.4', kv);
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(49);
		});

		it('reads counters as null for new IP and writes initial values', async () => {
			const kv = createMockKV(null, null);
			const result = await checkRateLimit('1.2.3.4', kv);
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(49); // 50 - 1
			expect(result.hourRemaining).toBe(299); // 300 - 1

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

			const attempts = 60;
			const results = await Promise.all(
				Array.from({ length: attempts }, () => checkRateLimit('203.0.113.10', kv)),
			);

			const allowedCount = results.filter((r) => r.allowed).length;
			expect(allowedCount).toBe(50);
			expect(results.some((r) => !r.allowed)).toBe(true);
		});
	});

	// -----------------------------------------------------------------------
	// Tool daily quotas
	// -----------------------------------------------------------------------
	describe('tool daily quotas', () => {
		it('allows requests until daily tool limit is reached (in-memory)', async () => {
			for (let i = 0; i < 5; i++) {
				const result = await checkToolDailyRateLimit('198.51.100.9', 'scan_domain', 5);
				expect(result.allowed).toBe(true);
			}

			const blocked = await checkToolDailyRateLimit('198.51.100.9', 'scan_domain', 5);
			expect(blocked.allowed).toBe(false);
			expect(blocked.remaining).toBe(0);
			expect(blocked.retryAfterMs).toBeGreaterThan(0);
		});

		it('uses separate counters per tool', async () => {
			for (let i = 0; i < 5; i++) {
				await checkToolDailyRateLimit('198.51.100.10', 'scan_domain', 5);
			}

			const scanBlocked = await checkToolDailyRateLimit('198.51.100.10', 'scan_domain', 5);
			expect(scanBlocked.allowed).toBe(false);

			const otherTool = await checkToolDailyRateLimit('198.51.100.10', 'check_spf', 100);
			expect(otherTool.allowed).toBe(true);
		});

		it('persists tool quota in KV when available', async () => {
			const kv = {
				get: vi.fn().mockResolvedValue('4'),
				put: vi.fn().mockResolvedValue(undefined),
			} as unknown as KVNamespace;

			const result = await checkToolDailyRateLimit('198.51.100.11', 'scan_domain', 5, kv);
			expect(result.allowed).toBe(true);
			expect(result.remaining).toBe(0);
			expect(kv.put).toHaveBeenCalledTimes(1);
			const putCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[0];
			expect(putCall[0]).toContain('rl:day:tool:scan_domain:198.51.100.11:');
			expect(putCall[1]).toBe('5');
			expect(putCall[2]).toEqual({ expirationTtl: 86400 });
		});

		it('falls back to in-memory when KV tool quota check fails', async () => {
			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn(),
			} as unknown as KVNamespace;

			const result = await checkToolDailyRateLimit('198.51.100.12', 'scan_domain', 5, kv);
			expect(result.allowed).toBe(true);
			expect(result.remaining).toBe(4);
		});
	});

	// -----------------------------------------------------------------------
	// checkRateLimit router
	// -----------------------------------------------------------------------
	describe('checkRateLimit routing', () => {
		it('uses in-memory path without KV arg', async () => {
			const result = await checkRateLimit('1.2.3.4');
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(49);
		});

		it('uses KV path when KV arg provided', async () => {
			const kv = {
				get: vi.fn().mockResolvedValue(null),
				put: vi.fn().mockResolvedValue(undefined),
			} as unknown as KVNamespace;

			await checkRateLimit('1.2.3.4', kv);

			expect(kv.get).toHaveBeenCalled();
		});

		it('tracks control-plane limits separately from tool limits', async () => {
			for (let i = 0; i < 50; i++) {
				await checkRateLimit('198.51.100.40');
			}

			const controlPlane = await checkControlPlaneRateLimit('198.51.100.40');
			expect(controlPlane.allowed).toBe(true);
			expect(controlPlane.minuteRemaining).toBe(59);
		});
	});

	// -----------------------------------------------------------------------
	// Circuit breaker for QuotaCoordinator DO
	// -----------------------------------------------------------------------
	describe('DO circuit breaker', () => {
		function createFailingDO(): DurableObjectNamespace {
			return {
				getByName: () => ({
					fetch: () => Promise.reject(new Error('DO unavailable')),
				}),
			} as unknown as DurableObjectNamespace;
		}

		it('falls back to in-memory after DO failure', async () => {
			const result = await checkRateLimit('10.0.0.1', undefined, createFailingDO());
			// Should still get a result via in-memory fallback
			expect(result.allowed).toBe(true);
		});

		it('opens circuit after 3 consecutive DO failures', async () => {
			const failingDO = createFailingDO();
			// Trigger 3 failures to open circuit
			for (let i = 0; i < 3; i++) {
				await checkRateLimit(`10.0.0.${i}`, undefined, failingDO);
			}
			// 4th call should not hit DO at all (circuit open), but still succeed via fallback
			const result = await checkRateLimit('10.0.0.99', undefined, failingDO);
			expect(result.allowed).toBe(true);
		});

		it('circuit breaker wraps global daily limit DO calls', async () => {
			const failingDO = createFailingDO();
			// Open the circuit with 3 failures
			for (let i = 0; i < 3; i++) {
				await checkGlobalDailyLimit(500_000, undefined, failingDO);
			}
			// Should fall through to in-memory without calling DO
			const result = await checkGlobalDailyLimit(500_000, undefined, failingDO);
			expect(result.allowed).toBe(true);
		});

		it('circuit breaker wraps tool daily limit DO calls', async () => {
			const failingDO = createFailingDO();
			for (let i = 0; i < 3; i++) {
				await checkToolDailyRateLimit('user1', 'check_spf', 200, undefined, failingDO);
			}
			const result = await checkToolDailyRateLimit('user1', 'check_spf', 200, undefined, failingDO);
			expect(result.allowed).toBe(true);
		});
	});

	// -----------------------------------------------------------------------
	// Per-tier concurrency limits
	// -----------------------------------------------------------------------
	describe('per-tier concurrency limits', () => {
		it('free tier: allows up to 3 concurrent executions', () => {
			const limit = 3;
			for (let i = 0; i < limit; i++) {
				const result = acquireConcurrencySlot('ip:1.2.3.4', limit);
				expect(result.allowed).toBe(true);
				expect(result.active).toBe(i + 1);
				expect(result.limit).toBe(limit);
			}
			const blocked = acquireConcurrencySlot('ip:1.2.3.4', limit);
			expect(blocked.allowed).toBe(false);
			expect(blocked.retryAfterMs).toBeGreaterThan(0);
			expect(blocked.active).toBe(limit);
		});

		it('agent tier: allows up to 5 concurrent executions', () => {
			const limit = 5;
			for (let i = 0; i < limit; i++) {
				expect(acquireConcurrencySlot('key:agent1', limit).allowed).toBe(true);
			}
			expect(acquireConcurrencySlot('key:agent1', limit).allowed).toBe(false);
		});

		it('developer tier: allows up to 10 concurrent executions', () => {
			const limit = 10;
			for (let i = 0; i < limit; i++) {
				expect(acquireConcurrencySlot('key:dev1', limit).allowed).toBe(true);
			}
			expect(acquireConcurrencySlot('key:dev1', limit).allowed).toBe(false);
		});

		it('enterprise tier: allows up to 25 concurrent executions', () => {
			const limit = 25;
			for (let i = 0; i < limit; i++) {
				expect(acquireConcurrencySlot('key:ent1', limit).allowed).toBe(true);
			}
			expect(acquireConcurrencySlot('key:ent1', limit).allowed).toBe(false);
		});

		it('partner tier: allows up to 50 concurrent executions', () => {
			const limit = 50;
			for (let i = 0; i < limit; i++) {
				expect(acquireConcurrencySlot('key:partner1', limit).allowed).toBe(true);
			}
			expect(acquireConcurrencySlot('key:partner1', limit).allowed).toBe(false);
		});

		it('owner tier: unlimited (Infinity limit)', () => {
			// Owner tier uses Infinity — execute.ts skips slot tracking
			// But if someone calls acquireConcurrencySlot with Infinity, it should always allow
			for (let i = 0; i < 100; i++) {
				expect(acquireConcurrencySlot('key:owner1', Infinity).allowed).toBe(true);
			}
		});

		it('returns JSON-RPC error -32029 semantics when at limit', () => {
			const limit = 3;
			for (let i = 0; i < limit; i++) {
				acquireConcurrencySlot('ip:blocked', limit);
			}
			const blocked = acquireConcurrencySlot('ip:blocked', limit);
			expect(blocked.allowed).toBe(false);
			expect(blocked.retryAfterMs).toBe(1000);
			expect(blocked.active).toBe(limit);
			expect(blocked.limit).toBe(limit);
		});

		it('concurrent count decrements on release (even after error)', () => {
			const limit = 3;
			// Fill all slots
			acquireConcurrencySlot('key:test', limit);
			acquireConcurrencySlot('key:test', limit);
			acquireConcurrencySlot('key:test', limit);
			expect(acquireConcurrencySlot('key:test', limit).allowed).toBe(false);

			// Release one slot (simulates finally block after error)
			releaseConcurrencySlot('key:test');
			const afterRelease = acquireConcurrencySlot('key:test', limit);
			expect(afterRelease.allowed).toBe(true);
			expect(afterRelease.active).toBe(3);
		});

		it('tracked per principal, not shared across principals', () => {
			const limit = 3;
			// Fill slots for principal A
			for (let i = 0; i < limit; i++) {
				acquireConcurrencySlot('key:A', limit);
			}
			expect(acquireConcurrencySlot('key:A', limit).allowed).toBe(false);

			// Principal B should still be allowed
			const resultB = acquireConcurrencySlot('key:B', limit);
			expect(resultB.allowed).toBe(true);
			expect(resultB.active).toBe(1);
		});
	});
});
