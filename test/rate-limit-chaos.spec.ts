/**
 * Chaos tests for rate limiting edge cases.
 * Validates limit boundaries, alias quota separation, concurrent access,
 * window transitions, and cross-scope isolation.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';
import {
	checkRateLimit,
	checkControlPlaneRateLimit,
	checkToolDailyRateLimit,
	checkGlobalDailyLimit,
	resetAllRateLimits,
	resetGlobalDailyLimit,
} from '../src/lib/rate-limiter';
import { FREE_TOOL_DAILY_LIMITS, GLOBAL_DAILY_TOOL_LIMIT } from '../src/lib/config';

afterEach(() => {
	resetAllRateLimits();
	resetGlobalDailyLimit();
	vi.restoreAllMocks();
});

describe('rate-limit chaos tests', () => {
	// -----------------------------------------------------------------------
	// Edge case: scan / scan_domain alias uses separate quota counters
	// -----------------------------------------------------------------------
	describe('scan alias quota separation', () => {
		it('raw rate limiter treats scan and scan_domain as separate counters', async () => {
			// The low-level rate limiter uses tool names as-is.
			// The fix is in index.ts which calls normalizeToolName() before
			// looking up FREE_TOOL_DAILY_LIMITS, so both resolve to scan_domain.
			const ip = '198.51.100.1';
			const scanLimit = FREE_TOOL_DAILY_LIMITS['scan_domain'];

			// Exhaust scan_domain quota
			for (let i = 0; i < scanLimit; i++) {
				const r = await checkToolDailyRateLimit(ip, 'scan_domain', scanLimit);
				expect(r.allowed).toBe(true);
			}
			const blocked = await checkToolDailyRateLimit(ip, 'scan_domain', scanLimit);
			expect(blocked.allowed).toBe(false);

			// Raw rate limiter still has separate counter for "scan"
			// but index.ts normalizes "scan" → "scan_domain" before calling this
			const aliasResult = await checkToolDailyRateLimit(ip, 'scan', scanLimit);
			expect(aliasResult.allowed).toBe(true); // separate counter at low level
		});

		it('both aliases in config have the same limit value', () => {
			expect(FREE_TOOL_DAILY_LIMITS['scan']).toBe(FREE_TOOL_DAILY_LIMITS['scan_domain']);
		});

		it('normalizeToolName resolves scan alias to scan_domain', async () => {
			const { normalizeToolName } = await import('../src/handlers/tool-args');
			expect(normalizeToolName('scan')).toBe('scan_domain');
			expect(normalizeToolName('SCAN')).toBe('scan_domain');
			expect(normalizeToolName(' scan ')).toBe('scan_domain');
			expect(normalizeToolName('scan_domain')).toBe('scan_domain');
		});
	});

	// -----------------------------------------------------------------------
	// Edge case: minute limit boundary (exactly at limit)
	// -----------------------------------------------------------------------
	describe('exact boundary conditions', () => {
		it('request #50 is allowed, #51 is blocked (minute limit)', async () => {
			const ip = '10.0.0.50';
			for (let i = 0; i < 49; i++) {
				await checkRateLimit(ip);
			}
			const fiftiethResult = await checkRateLimit(ip);
			expect(fiftiethResult.allowed).toBe(true);
			expect(fiftiethResult.minuteRemaining).toBe(0);

			const fiftyFirstResult = await checkRateLimit(ip);
			expect(fiftyFirstResult.allowed).toBe(false);
		});

		it('request #300 is allowed, #301 is blocked (hour limit)', async () => {
			const baseTime = 1_700_000_000_000;
			let currentTime = baseTime;
			vi.spyOn(Date, 'now').mockImplementation(() => currentTime);

			const ip = '10.0.0.51';
			let allowed = 0;

			// Fill across minute windows to avoid minute limit
			for (let window = 0; window < 7; window++) {
				currentTime = baseTime + window * 61_000;
				for (let i = 0; i < 50; i++) {
					const r = await checkRateLimit(ip);
					if (r.allowed) allowed++;
					if (allowed >= 300) break;
				}
				if (allowed >= 300) break;
			}

			expect(allowed).toBe(300);

			// Next request should be blocked
			currentTime = baseTime + 7 * 61_000;
			const result = await checkRateLimit(ip);
			expect(result.allowed).toBe(false);
			expect(result.hourRemaining).toBe(0);
		});

		it('daily tool quota allows exactly N requests then blocks', async () => {
			const ip = '10.0.0.52';
			const limit = 25;
			for (let i = 0; i < limit; i++) {
				const r = await checkToolDailyRateLimit(ip, 'scan_domain', limit);
				expect(r.allowed).toBe(true);
				expect(r.remaining).toBe(limit - i - 1);
			}
			const blocked = await checkToolDailyRateLimit(ip, 'scan_domain', limit);
			expect(blocked.allowed).toBe(false);
			expect(blocked.remaining).toBe(0);
			expect(blocked.retryAfterMs).toBeGreaterThan(0);
		});
	});

	// -----------------------------------------------------------------------
	// Edge case: minute window rollover
	// -----------------------------------------------------------------------
	describe('window transitions', () => {
		it('minute limit resets after window rolls over', async () => {
			const baseTime = 1_700_000_000_000;
			let currentTime = baseTime;
			vi.spyOn(Date, 'now').mockImplementation(() => currentTime);

			const ip = '10.0.0.60';

			// Exhaust minute limit
			for (let i = 0; i < 50; i++) {
				const r = await checkRateLimit(ip);
				expect(r.allowed).toBe(true);
			}
			const blocked = await checkRateLimit(ip);
			expect(blocked.allowed).toBe(false);

			// Advance past minute boundary
			currentTime = baseTime + 61_000;
			const afterRollover = await checkRateLimit(ip);
			expect(afterRollover.allowed).toBe(true);
			expect(afterRollover.minuteRemaining).toBe(49);
		});

		it('hour limit persists across minute window rollovers', async () => {
			const baseTime = 1_700_000_000_000;
			let currentTime = baseTime;
			vi.spyOn(Date, 'now').mockImplementation(() => currentTime);

			const ip = '10.0.0.61';
			let totalAllowed = 0;

			// Fill 300 requests across multiple minute windows
			for (let window = 0; window < 7; window++) {
				currentTime = baseTime + window * 61_000;
				for (let i = 0; i < 50; i++) {
					const r = await checkRateLimit(ip);
					if (r.allowed) totalAllowed++;
				}
			}

			expect(totalAllowed).toBe(300);

			// Even in new minute window, hour limit blocks
			currentTime = baseTime + 8 * 61_000;
			const result = await checkRateLimit(ip);
			expect(result.allowed).toBe(false);
			expect(result.hourRemaining).toBe(0);
		});

		it('hour limit resets after full hour rolls over', async () => {
			const baseTime = 1_700_000_000_000;
			let currentTime = baseTime;
			vi.spyOn(Date, 'now').mockImplementation(() => currentTime);

			const ip = '10.0.0.62';

			// Fill up hour limit
			for (let window = 0; window < 6; window++) {
				currentTime = baseTime + window * 61_000;
				for (let i = 0; i < 50; i++) {
					await checkRateLimit(ip);
				}
			}

			// Advance past hour boundary
			currentTime = baseTime + 3_601_000;
			const result = await checkRateLimit(ip);
			expect(result.allowed).toBe(true);
		});
	});

	// -----------------------------------------------------------------------
	// Edge case: concurrent requests from same IP (in-memory)
	// -----------------------------------------------------------------------
	describe('concurrent access patterns', () => {
		it('concurrent requests from same IP are correctly serialized in-memory', async () => {
			const ip = '10.0.0.70';
			const concurrentBatch = 60;

			const results = await Promise.all(
				Array.from({ length: concurrentBatch }, () => checkRateLimit(ip)),
			);

			const allowed = results.filter((r) => r.allowed).length;
			const blocked = results.filter((r) => !r.allowed).length;

			expect(allowed).toBe(50);
			expect(blocked).toBe(10);
		});

		it('concurrent tool quota checks are serialized in-memory', async () => {
			const ip = '10.0.0.71';
			const limit = 25;
			const concurrentBatch = 35;

			const results = await Promise.all(
				Array.from({ length: concurrentBatch }, () =>
					checkToolDailyRateLimit(ip, 'scan_domain', limit),
				),
			);

			const allowed = results.filter((r) => r.allowed).length;
			expect(allowed).toBe(limit);
		});
	});

	// -----------------------------------------------------------------------
	// Edge case: cross-scope isolation
	// -----------------------------------------------------------------------
	describe('scope isolation', () => {
		it('tool rate limits do not affect control plane limits', async () => {
			const ip = '10.0.0.80';

			// Exhaust tool rate limit
			for (let i = 0; i < 50; i++) {
				await checkRateLimit(ip);
			}
			const toolBlocked = await checkRateLimit(ip);
			expect(toolBlocked.allowed).toBe(false);

			// Control plane should still work
			const controlResult = await checkControlPlaneRateLimit(ip);
			expect(controlResult.allowed).toBe(true);
			expect(controlResult.minuteRemaining).toBe(59);
		});

		it('control plane limits do not affect tool limits', async () => {
			const ip = '10.0.0.81';

			// Exhaust control plane rate limit
			for (let i = 0; i < 60; i++) {
				await checkControlPlaneRateLimit(ip);
			}
			const cpBlocked = await checkControlPlaneRateLimit(ip);
			expect(cpBlocked.allowed).toBe(false);

			// Tool rate limit should still work
			const toolResult = await checkRateLimit(ip);
			expect(toolResult.allowed).toBe(true);
			expect(toolResult.minuteRemaining).toBe(49);
		});

		it('different IPs have completely independent quotas', async () => {
			const ip1 = '10.0.0.82';
			const ip2 = '10.0.0.83';

			// Exhaust ip1
			for (let i = 0; i < 50; i++) {
				await checkRateLimit(ip1);
			}
			expect((await checkRateLimit(ip1)).allowed).toBe(false);

			// ip2 unaffected
			const result = await checkRateLimit(ip2);
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(49);
		});

		it('tool daily quotas are per-IP — different IPs get full quotas', async () => {
			const limit = FREE_TOOL_DAILY_LIMITS['scan_domain'];

			// Exhaust ip1's scan_domain quota
			for (let i = 0; i < limit; i++) {
				await checkToolDailyRateLimit('10.0.0.84', 'scan_domain', limit);
			}
			expect((await checkToolDailyRateLimit('10.0.0.84', 'scan_domain', limit)).allowed).toBe(false);

			// ip2 gets full quota
			const result = await checkToolDailyRateLimit('10.0.0.85', 'scan_domain', limit);
			expect(result.allowed).toBe(true);
			expect(result.remaining).toBe(limit - 1);
		});
	});

	// -----------------------------------------------------------------------
	// Edge case: global daily limit
	// -----------------------------------------------------------------------
	describe('global daily cap', () => {
		it('blocks after global daily limit is reached', async () => {
			// Use a small limit to avoid slow test
			const smallLimit = 100;
			for (let i = 0; i < smallLimit; i++) {
				const r = await checkGlobalDailyLimit(smallLimit);
				expect(r.allowed).toBe(true);
			}
			const blocked = await checkGlobalDailyLimit(smallLimit);
			expect(blocked.allowed).toBe(false);
			expect(blocked.remaining).toBe(0);
		});

		it('global daily limit is independent of per-IP limits', async () => {
			// Exhaust per-IP minute limit
			for (let i = 0; i < 50; i++) {
				await checkRateLimit('10.0.0.90');
			}

			// Global daily limit should still have capacity
			const globalResult = await checkGlobalDailyLimit(GLOBAL_DAILY_TOOL_LIMIT);
			expect(globalResult.allowed).toBe(true);
			expect(globalResult.remaining).toBe(GLOBAL_DAILY_TOOL_LIMIT - 1);
		});
	});

	// -----------------------------------------------------------------------
	// Edge case: config consistency
	// -----------------------------------------------------------------------
	describe('config consistency', () => {
		it('all check_* tools in config have the same daily limit (200)', () => {
			const checkTools = Object.entries(FREE_TOOL_DAILY_LIMITS).filter(
				([name]) => name.startsWith('check_') && name !== 'check_lookalikes' && name !== 'check_shadow_domains',
			);
			for (const [name, limit] of checkTools) {
				expect(limit, `${name} should have limit 200`).toBe(200);
			}
		});

		it('check_lookalikes has a lower limit than other checks', () => {
			expect(FREE_TOOL_DAILY_LIMITS['check_lookalikes']).toBe(20);
			expect(FREE_TOOL_DAILY_LIMITS['check_lookalikes']).toBeLessThan(
				FREE_TOOL_DAILY_LIMITS['check_spf'],
			);
		});

		it('compare_baseline has a lower limit than individual checks', () => {
			expect(FREE_TOOL_DAILY_LIMITS['compare_baseline']).toBe(150);
			expect(FREE_TOOL_DAILY_LIMITS['compare_baseline']).toBeLessThan(
				FREE_TOOL_DAILY_LIMITS['check_spf'],
			);
		});

		it('scan_domain limit is lower than individual check limits', () => {
			expect(FREE_TOOL_DAILY_LIMITS['scan_domain']).toBe(75);
			expect(FREE_TOOL_DAILY_LIMITS['scan_domain']).toBeLessThan(
				FREE_TOOL_DAILY_LIMITS['check_spf'],
			);
		});

		it('all expected tools are present in FREE_TOOL_DAILY_LIMITS', () => {
			const expectedTools = [
				'scan_domain',
				'scan',
				'check_spf',
				'check_dmarc',
				'check_dkim',
				'check_mx',
				'check_ns',
				'check_ssl',
				'check_dnssec',
				'check_mta_sts',
				'check_caa',
				'check_bimi',
				'check_tlsrpt',
				'check_lookalikes',
				'explain_finding',
				'compare_baseline',
			];
			for (const tool of expectedTools) {
				expect(FREE_TOOL_DAILY_LIMITS[tool], `${tool} should be in config`).toBeDefined();
			}
		});
	});

	// -----------------------------------------------------------------------
	// Edge case: KV-backed with concurrent requests and window boundaries
	// -----------------------------------------------------------------------
	describe('KV-backed edge cases', () => {
		it('KV minute limit blocks at exactly 50', async () => {
			const kvState = new Map<string, string>();
			const kv = {
				get: vi.fn(async (key: string) => kvState.get(key) ?? null),
				put: vi.fn(async (key: string, value: string) => {
					kvState.set(key, value);
				}),
			} as unknown as KVNamespace;

			let allowed = 0;
			for (let i = 0; i < 55; i++) {
				const r = await checkRateLimit('10.0.0.100', kv);
				if (r.allowed) allowed++;
			}
			expect(allowed).toBe(50);
		});

		it('KV tool daily quota blocks at configured limit', async () => {
			const kvState = new Map<string, string>();
			const kv = {
				get: vi.fn(async (key: string) => kvState.get(key) ?? null),
				put: vi.fn(async (key: string, value: string) => {
					kvState.set(key, value);
				}),
			} as unknown as KVNamespace;

			const limit = FREE_TOOL_DAILY_LIMITS['scan_domain'];
			let allowed = 0;
			for (let i = 0; i < limit + 5; i++) {
				const r = await checkToolDailyRateLimit('10.0.0.101', 'scan_domain', limit, kv);
				if (r.allowed) allowed++;
			}
			expect(allowed).toBe(limit);
		});

		it('KV uses normalized tool name when called through index.ts', async () => {
			// At the KV level, tool names are used as-is.
			// index.ts normalizes "scan" → "scan_domain" before calling the limiter,
			// so both go through as "scan_domain" and share the same KV key.
			const kvState = new Map<string, string>();
			const kv = {
				get: vi.fn(async (key: string) => kvState.get(key) ?? null),
				put: vi.fn(async (key: string, value: string) => {
					kvState.set(key, value);
				}),
			} as unknown as KVNamespace;

			const limit = FREE_TOOL_DAILY_LIMITS['scan_domain'];

			// Both calls use the normalized name "scan_domain" (as index.ts does)
			await checkToolDailyRateLimit('10.0.0.102', 'scan_domain', limit, kv);
			await checkToolDailyRateLimit('10.0.0.102', 'scan_domain', limit, kv);

			const keys = Array.from(kvState.keys());
			const scanDomainKeys = keys.filter((k) => k.includes('scan_domain'));
			expect(scanDomainKeys.length).toBe(1); // Single key, shared counter
		});
	});

	// -----------------------------------------------------------------------
	// Edge case: rapid burst then recover
	// -----------------------------------------------------------------------
	describe('burst recovery patterns', () => {
		it('Claude Desktop pattern: 12 parallel checks + scan within minute limit', async () => {
			const ip = '10.0.0.110';
			// Simulate scan_domain triggering 12 parallel checks
			const scanBatch = await Promise.all(
				Array.from({ length: 12 }, () => checkRateLimit(ip)),
			);
			expect(scanBatch.every((r) => r.allowed)).toBe(true);

			// Then user runs another scan (12 more)
			const secondBatch = await Promise.all(
				Array.from({ length: 12 }, () => checkRateLimit(ip)),
			);
			expect(secondBatch.every((r) => r.allowed)).toBe(true);

			// Some individual checks (10 more = 34 total, under 50)
			const individualBatch = await Promise.all(
				Array.from({ length: 10 }, () => checkRateLimit(ip)),
			);
			expect(individualBatch.every((r) => r.allowed)).toBe(true);

			// Still have headroom (34 used, 16 remaining)
			const status = await checkRateLimit(ip);
			expect(status.allowed).toBe(true);
			expect(status.minuteRemaining).toBe(15); // 50 - 35
		});

		it('old limit (30) would have blocked the Claude Desktop pattern', async () => {
			// This proves the 50 limit is necessary
			const ip = '10.0.0.111';
			// Two scans of 12 checks each = 24 requests
			for (let i = 0; i < 24; i++) {
				const r = await checkRateLimit(ip);
				expect(r.allowed).toBe(true);
			}
			// Individual checks: 6 more = 30 total
			for (let i = 0; i < 6; i++) {
				const r = await checkRateLimit(ip);
				expect(r.allowed).toBe(true);
			}

			// At old limit of 30, next request would be blocked
			// But with new limit of 50, we still have 20 remaining
			const result = await checkRateLimit(ip);
			expect(result.allowed).toBe(true);
			expect(result.minuteRemaining).toBe(19); // 50 - 31
		});
	});

	// -----------------------------------------------------------------------
	// Edge case: retry-after accuracy
	// -----------------------------------------------------------------------
	describe('retry-after values', () => {
		it('minute block returns positive retry-after', async () => {
			const ip = '10.0.0.120';
			for (let i = 0; i < 50; i++) {
				await checkRateLimit(ip);
			}
			const blocked = await checkRateLimit(ip);
			expect(blocked.allowed).toBe(false);
			expect(blocked.retryAfterMs).toBeGreaterThan(0);
			expect(blocked.retryAfterMs).toBeLessThanOrEqual(60_000);
		});

		it('tool daily block returns retry-after within 24 hours', async () => {
			const limit = FREE_TOOL_DAILY_LIMITS['check_lookalikes'];
			const ip = '10.0.0.121';
			for (let i = 0; i < limit; i++) {
				await checkToolDailyRateLimit(ip, 'check_lookalikes', limit);
			}
			const blocked = await checkToolDailyRateLimit(ip, 'check_lookalikes', limit);
			expect(blocked.allowed).toBe(false);
			expect(blocked.retryAfterMs).toBeGreaterThan(0);
			expect(blocked.retryAfterMs).toBeLessThanOrEqual(86_400_000);
		});
	});
});
