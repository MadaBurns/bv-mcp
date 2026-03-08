import { afterEach, describe, expect, it, vi } from 'vitest';

import { checkScopedRateLimitInMemory, checkToolDailyRateLimitInMemory, pruneTimestamps, resetAllRateLimits } from '../src/lib/rate-limiter-memory';

afterEach(() => {
	resetAllRateLimits();
	vi.restoreAllMocks();
});

describe('rate-limiter-memory', () => {
	it('prunes timestamps outside the active window', () => {
		expect(pruneTimestamps([10, 20, 30, 40], 15, 40)).toEqual([30, 40]);
		expect(pruneTimestamps([30, 40], 15, 40)).toEqual([30, 40]);
	});

	it('tracks scoped in-memory limits independently', () => {
		for (let i = 0; i < 2; i++) {
			expect(checkScopedRateLimitInMemory('203.0.113.1', 'tools', 2, 5).allowed).toBe(true);
		}

		expect(checkScopedRateLimitInMemory('203.0.113.1', 'tools', 2, 5).allowed).toBe(false);
		expect(checkScopedRateLimitInMemory('203.0.113.1', 'control', 2, 5).allowed).toBe(true);
	});

	it('tracks daily tool quotas by principal and tool name', () => {
		expect(checkToolDailyRateLimitInMemory('198.51.100.20', 'scan_domain', 2).allowed).toBe(true);
		expect(checkToolDailyRateLimitInMemory('198.51.100.20', 'scan_domain', 2).allowed).toBe(true);
		expect(checkToolDailyRateLimitInMemory('198.51.100.20', 'scan_domain', 2).allowed).toBe(false);
		expect(checkToolDailyRateLimitInMemory('198.51.100.20', 'check_spf', 2).allowed).toBe(true);
	});
});