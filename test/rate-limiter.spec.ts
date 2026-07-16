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
	GLOBAL_CEILING_ISOLATE_FANOUT_ESTIMATE,
	denyBiasedGlobalCeiling,
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
			const result = await checkRateLimit('192.0.2.1');
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(49);
			expect(result.hourRemaining).toBe(299);
		});

		it('should decrement remaining counts on multiple requests', async () => {
			await checkRateLimit('192.0.2.1');
			await checkRateLimit('192.0.2.1');
			const result = await checkRateLimit('192.0.2.1');
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(47);
			expect(result.hourRemaining).toBe(297);
		});

		it('should block 51st request within a minute', async () => {
			for (let i = 0; i < 50; i++) {
				const r = await checkRateLimit('192.0.2.1');
				expect(r.allowed).toBe(true);
			}
			const blocked = await checkRateLimit('192.0.2.1');
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
					const r = await checkRateLimit('192.0.2.1');
					if (!r.allowed) break;
				}
			}
			currentTime = baseTime + 7 * 61_000;
			const blocked = await checkRateLimit('192.0.2.1');
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
				await checkRateLimit('192.0.2.1');
			}
			const blocked = await checkRateLimit('192.0.2.1');
			expect(blocked.allowed).toBe(false);

			resetRateLimit('192.0.2.1');

			const after = await checkRateLimit('192.0.2.1');
			expect(after.allowed).toBe(true);
			expect(after.minuteRemaining).toBe(49);
		});

		it('resetAllRateLimits clears all state', async () => {
			for (let i = 0; i < 50; i++) {
				await checkRateLimit('192.0.2.1');
			}
			await checkRateLimit('5.6.7.8');

			resetAllRateLimits();

			const resultA = await checkRateLimit('192.0.2.1');
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
			const result = await checkRateLimit('192.0.2.1', kv);
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(46); // 50 - (3+1)
			expect(result.hourRemaining).toBe(279); // 300 - (20+1)
		});

		it('blocks at minute limit', async () => {
			const kv = createMockKV('50', '100');
			const result = await checkRateLimit('192.0.2.1', kv);
			expect(result.allowed).toBe(false);
			expect(result.minuteRemaining).toBe(0);
			expect(result.retryAfterMs).toBeGreaterThan(0);
		});

		it('blocks at hour limit', async () => {
			const kv = createMockKV('5', '300');
			const result = await checkRateLimit('192.0.2.1', kv);
			expect(result.allowed).toBe(false);
			expect(result.hourRemaining).toBe(0);
			expect(result.retryAfterMs).toBeGreaterThan(0);
		});

		it('increments and writes counters with required key format and window-relative expirationTtl', async () => {
			const kv = createMockKV('3', '20');
			await checkRateLimit('192.0.2.1', kv);

			expect(kv.put).toHaveBeenCalledTimes(2);

			const minutePutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[0];
			expect(minutePutCall[0]).toContain('rl:min:192.0.2.1:');
			expect(minutePutCall[1]).toBe('4');
			// TTL is remaining time in window, clamped to KV's 60s minimum
			// (Cloudflare KV rejects expirationTtl < 60)
			const minuteTtl = minutePutCall[2].expirationTtl;
			expect(minuteTtl).toBe(60);

			const hourPutCall = (kv.put as ReturnType<typeof vi.fn>).mock.calls[1];
			expect(hourPutCall[0]).toContain('rl:hr:192.0.2.1:');
			expect(hourPutCall[1]).toBe('21');
			const hourTtl = hourPutCall[2].expirationTtl;
			expect(hourTtl).toBeGreaterThanOrEqual(60);
			expect(hourTtl).toBeLessThanOrEqual(3600);
		});

		it('falls back to in-memory on KV error', async () => {
			const kv = {
				get: vi.fn().mockRejectedValue(new Error('KV unavailable')),
				put: vi.fn(),
			} as unknown as KVNamespace;

			const result = await checkRateLimit('192.0.2.1', kv);
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(49);
		});

		it('reads counters as null for new IP and writes initial values', async () => {
			const kv = createMockKV(null, null);
			const result = await checkRateLimit('192.0.2.1', kv);
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
			const result = await checkRateLimit('192.0.2.1');
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(49);
		});

		it('uses KV path when KV arg provided', async () => {
			const kv = {
				get: vi.fn().mockResolvedValue(null),
				put: vi.fn().mockResolvedValue(undefined),
			} as unknown as KVNamespace;

			await checkRateLimit('192.0.2.1', kv);

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

		// Regression: owner tier passes Infinity; JSON.stringify(Infinity) === "null",
		// which the coordinator validator rejected as a non-finite number, returning 400
		// for ~97% of authenticated owner-tier tool calls (chaos run 2026-05-21).
		it('checkToolDailyRateLimit short-circuits unlimited (Infinity) without touching the DO', async () => {
			const fetchSpy = vi.fn();
			const trackedDO = {
				getByName: () => ({ fetch: fetchSpy }),
			} as unknown as DurableObjectNamespace;
			const result = await checkToolDailyRateLimit('owner-key', 'scan_domain', Infinity, undefined, trackedDO);
			expect(result.allowed).toBe(true);
			expect(result.limit).toBe(Infinity);
			expect(fetchSpy).not.toHaveBeenCalled();
		});

		it('checkGlobalDailyLimit short-circuits unlimited (Infinity) without touching the DO', async () => {
			const fetchSpy = vi.fn();
			const trackedDO = {
				getByName: () => ({ fetch: fetchSpy }),
			} as unknown as DurableObjectNamespace;
			const result = await checkGlobalDailyLimit(Infinity, undefined, trackedDO);
			expect(result.allowed).toBe(true);
			expect(result.limit).toBe(Infinity);
			expect(fetchSpy).not.toHaveBeenCalled();
		});

		// Security guard: TIER_TOOL_DAILY_LIMITS encodes "tier blocked" as 0
		// (e.g. agent + brand_audit_*). The Infinity short-circuit must not bleed
		// into limit=0 or it silently grants access to the blocked tier+tool combo.
		it('checkToolDailyRateLimit denies on first call when limit=0 (blocked tier)', async () => {
			const result = await checkToolDailyRateLimit('agent-key', 'brand_audit_single', 0);
			expect(result.allowed).toBe(false);
			expect(result.limit).toBe(0);
		});
	});

	// -----------------------------------------------------------------------
	// R9: global COST ceiling stays globally-enforced when the breaker opens.
	//
	// When the QuotaCoordinator DO breaker opens (3 failures), the authoritative
	// cross-isolate counter is gone. The per-isolate in-memory counter would let
	// the real global cap balloon to ~limit × isolate-count exactly under peak
	// load. So with the breaker OPEN we must (a) PREFER the globally-shared KV
	// counter over in-memory, (b) emit a degradation event so operators see the
	// guardrail is degraded, and (c) when in-memory is the only fallback, scale
	// its cap DOWN by the estimated isolate fan-out.
	// -----------------------------------------------------------------------
	describe('global cost ceiling — breaker-open fallback (R9)', () => {
		function createFailingDO(): DurableObjectNamespace {
			return {
				getByName: () => ({
					fetch: () => Promise.reject(new Error('DO unavailable')),
				}),
			} as unknown as DurableObjectNamespace;
		}

		function createMemoryKv(): { kv: KVNamespace; state: Map<string, string> } {
			const state = new Map<string, string>();
			const kv = {
				get: vi.fn(async (key: string) => state.get(key) ?? null),
				put: vi.fn(async (key: string, value: string) => {
					state.set(key, value);
				}),
			} as unknown as KVNamespace;
			return { kv, state };
		}

		function createDegradationSink() {
			const emitDegradationEvent = vi.fn();
			return { sink: { emitDegradationEvent }, emitDegradationEvent };
		}

		// Open the breaker by exhausting its failure threshold against the global cap.
		async function openBreaker(failingDO: DurableObjectNamespace): Promise<void> {
			for (let i = 0; i < 3; i++) {
				await checkGlobalDailyLimit(500_000, undefined, failingDO);
			}
		}

		it('prefers the shared KV counter (not in-memory) once the breaker is OPEN', async () => {
			const failingDO = createFailingDO();
			await openBreaker(failingDO);

			const { kv, state } = createMemoryKv();
			const { sink } = createDegradationSink();

			const result = await checkGlobalDailyLimit(500_000, kv, failingDO, sink);
			expect(result.allowed).toBe(true);

			// The shared `rl:global:day:*` key must have been written — proof the
			// globally-shared tier ran instead of the per-isolate counter.
			const globalKeys = [...state.keys()].filter((k) => k.startsWith('rl:global:day:'));
			expect(globalKeys.length).toBe(1);
			expect(state.get(globalKeys[0])).toBe('1');
		});

		it('emits exactly one cost_ceiling_degraded degradation event for the global cost ceiling when the breaker is OPEN', async () => {
			const failingDO = createFailingDO();
			await openBreaker(failingDO);

			const { kv } = createMemoryKv();
			const { sink, emitDegradationEvent } = createDegradationSink();

			await checkGlobalDailyLimit(500_000, kv, failingDO, sink);

			// Exactly one emit per affected request (no double-emit across the KV /
			// in-memory fallback tiers), carrying the alertable degradationType — NOT
			// the session-store `kv_fallback` member that queryBindingDegradation drops.
			expect(emitDegradationEvent).toHaveBeenCalledTimes(1);
			expect(emitDegradationEvent).toHaveBeenCalledWith({
				degradationType: 'cost_ceiling_degraded',
				component: 'global_cost_ceiling',
			});
		});

		it('does NOT emit a degradation event while the breaker is CLOSED (healthy DO)', async () => {
			// No prior failures → breaker CLOSED. A working DO serves the request.
			const workingDO = {
				getByName: () => ({
					fetch: async () =>
						new Response(JSON.stringify({ allowed: true, remaining: 499_999, limit: 500_000 }), {
							status: 200,
							headers: { 'content-type': 'application/json' },
						}),
				}),
			} as unknown as DurableObjectNamespace;
			const { sink, emitDegradationEvent } = createDegradationSink();

			await checkGlobalDailyLimit(500_000, undefined, workingDO, sink);
			expect(emitDegradationEvent).not.toHaveBeenCalled();
		});

		it('uses in-memory only as last resort and scales the cap DOWN by the isolate fan-out when the breaker is OPEN', async () => {
			const failingDO = createFailingDO();
			await openBreaker(failingDO);

			const { sink } = createDegradationSink();
			// No KV → forced onto the last-resort in-memory tier.
			const limit = 500_000;
			const expectedEffective = denyBiasedGlobalCeiling(limit);

			const result = await checkGlobalDailyLimit(limit, undefined, failingDO, sink);
			expect(result.allowed).toBe(true);
			// The reported limit reflects the DOWN-SCALED per-isolate budget, not the
			// full configured cap — proof the in-memory ceiling was reduced.
			expect(result.limit).toBe(expectedEffective);
			expect(result.limit).toBeLessThan(limit);
		});

		it('enforces the down-scaled in-memory cap (blocks once the per-isolate budget is exhausted)', async () => {
			const failingDO = createFailingDO();
			await openBreaker(failingDO);

			// openBreaker's 3rd call lands on (and increments) the in-memory counter
			// once the circuit opens — reset it so the tiny budget below is exact.
			resetGlobalDailyLimit();

			const { sink } = createDegradationSink();
			// Tiny limit so the scaled cap is small and exhaustible within a test.
			const limit = GLOBAL_CEILING_ISOLATE_FANOUT_ESTIMATE * 2; // → effective cap 2
			const effective = denyBiasedGlobalCeiling(limit);

			for (let i = 0; i < effective; i++) {
				const r = await checkGlobalDailyLimit(limit, undefined, failingDO, sink);
				expect(r.allowed).toBe(true);
			}
			const blocked = await checkGlobalDailyLimit(limit, undefined, failingDO, sink);
			expect(blocked.allowed).toBe(false);
			expect(blocked.remaining).toBe(0);
			expect(blocked.retryAfterMs).toBeGreaterThan(0);
		});

		it('does not down-scale or emit degradation on the in-memory path while the breaker is CLOSED (no DO wired)', async () => {
			const { sink, emitDegradationEvent } = createDegradationSink();
			const limit = 500_000;
			// No DO, no KV, breaker CLOSED → in-memory at the FULL configured cap.
			const result = await checkGlobalDailyLimit(limit, undefined, undefined, sink);
			expect(result.allowed).toBe(true);
			expect(result.limit).toBe(limit);
			expect(emitDegradationEvent).not.toHaveBeenCalled();
		});

		it('emits degradation only once per request even when KV throws and it falls through to in-memory', async () => {
			const failingDO = createFailingDO();
			await openBreaker(failingDO);

			const throwingKv = {
				get: vi.fn(async () => {
					throw new Error('KV down');
				}),
				put: vi.fn(async () => {
					throw new Error('KV down');
				}),
			} as unknown as KVNamespace;
			const { sink, emitDegradationEvent } = createDegradationSink();

			const result = await checkGlobalDailyLimit(500_000, throwingKv, failingDO, sink);
			expect(result.allowed).toBe(true);
			// Down-scaled in-memory cap (KV unusable) yet still exactly one emit.
			expect(result.limit).toBe(denyBiasedGlobalCeiling(500_000));
			expect(emitDegradationEvent).toHaveBeenCalledTimes(1);
			// Single emit carries the alertable type even when it crosses KV -> in-memory.
			expect(emitDegradationEvent).toHaveBeenCalledWith({
				degradationType: 'cost_ceiling_degraded',
				component: 'global_cost_ceiling',
			});
		});

		it('pins the deny-biased in-memory math: effectiveLimit = floor(limit / GLOBAL_CEILING_ISOLATE_FANOUT_ESTIMATE) (decision #6)', async () => {
			// The fan-out estimate is a pinned constant; assert it explicitly so a
			// silent retune trips this test (non-negotiable #4).
			expect(GLOBAL_CEILING_ISOLATE_FANOUT_ESTIMATE).toBe(50);

			// floor: 999 / 50 = 19.98 -> 19
			expect(denyBiasedGlobalCeiling(999)).toBe(19);
			// Decision #6 deny-bias: a cap BELOW the fan-out floors to 0 (deny-all) — the
			// OLD Math.max(1, …) floor that let 1-per-isolate through (overshoot) is gone.
			expect(denyBiasedGlobalCeiling(10)).toBe(0);

			// And the function actually applies it on the last-resort (no-DO, no-KV but
			// breaker OPEN) path.
			const failingDO = createFailingDO();
			await openBreaker(failingDO);
			resetGlobalDailyLimit();
			const { sink } = createDegradationSink();
			const limit = 999;
			const r = await checkGlobalDailyLimit(limit, undefined, failingDO, sink);
			expect(r.limit).toBe(denyBiasedGlobalCeiling(limit));
		});

		it('deny-bias invariant: FANOUT × effectiveLimit ≤ limit for every cap (aggregate can never overshoot)', () => {
			for (const limit of [0, 1, 10, 49, 50, 51, 99, 100, 999, 10_000, 500_000]) {
				const eff = denyBiasedGlobalCeiling(limit);
				expect(eff).toBeGreaterThanOrEqual(0);
				// The whole point of decision #6: the aggregate across up to FANOUT isolates
				// is bounded by the configured cap.
				expect(eff * GLOBAL_CEILING_ISOLATE_FANOUT_ESTIMATE).toBeLessThanOrEqual(limit);
			}
		});

		it('deny-bias: a cap smaller than the fan-out DENIES on the breaker-open last-resort path (never overshoots)', async () => {
			const failingDO = createFailingDO();
			await openBreaker(failingDO);
			// Clear the in-memory counter that openBreaker's 3rd (breaker-open) call touched.
			resetGlobalDailyLimit();

			const { sink } = createDegradationSink();
			const limit = 10; // < FANOUT(50) → effective 0 → deny-all
			expect(denyBiasedGlobalCeiling(limit)).toBe(0);

			// Every call on this isolate is denied; the per-isolate spend is 0, so the
			// aggregate across all isolates is 0 ≤ limit — biased to deny, never overshoot.
			for (let i = 0; i < 5; i++) {
				const r = await checkGlobalDailyLimit(limit, undefined, failingDO, sink);
				expect(r.allowed).toBe(false);
				expect(r.remaining).toBe(0);
				expect(r.limit).toBe(0);
			}
		});
	});

	// -----------------------------------------------------------------------
	// Per-tier concurrency limits
	// -----------------------------------------------------------------------
	describe('per-tier concurrency limits', () => {
		it('free tier: allows up to 3 concurrent executions', () => {
			const limit = 3;
			for (let i = 0; i < limit; i++) {
				const result = acquireConcurrencySlot('ip:192.0.2.1', limit);
				expect(result.allowed).toBe(true);
				expect(result.active).toBe(i + 1);
				expect(result.limit).toBe(limit);
			}
			const blocked = acquireConcurrencySlot('ip:192.0.2.1', limit);
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

describe('per-IP KV advisory lock', () => {
	it('under contention on same IP, advisory path activates (counter writes bounded)', async () => {
		let counterWrites = 0;
		const store = new Map<string, string>();
		const kv = {
			async get(key: string) { return store.get(key) ?? null; },
			async put(key: string, value: string) {
				if (key.startsWith('rl:min:')) counterWrites += 1;
				store.set(key, value);
			},
			async delete(key: string) { store.delete(key); },
		} as unknown as KVNamespace;

		const mod = await import('../src/lib/rate-limiter');
		expect(typeof (mod as { checkScopedRateLimitKVWithAdvisory?: unknown }).checkScopedRateLimitKVWithAdvisory).toBe('function');
		await Promise.all([
			mod.checkScopedRateLimitKVWithAdvisory!('1.1.1.1', 'tools', 50, 300, kv),
			mod.checkScopedRateLimitKVWithAdvisory!('1.1.1.1', 'tools', 50, 300, kv),
		]);
		expect(counterWrites).toBeGreaterThanOrEqual(1);
		expect(counterWrites).toBeLessThanOrEqual(2);
	});

	it('KV outage during advisory lock degrades without throwing', async () => {
		const kv = {
			async get() { throw new Error('KV down'); },
			async put() { throw new Error('KV down'); },
			async delete() { throw new Error('KV down'); },
		} as unknown as KVNamespace;

		const { checkScopedRateLimitKVWithAdvisory } = await import('../src/lib/rate-limiter');
		await expect(
			checkScopedRateLimitKVWithAdvisory!('2.2.2.2', 'tools', 50, 300, kv),
		).resolves.toBeDefined();
	});
});
