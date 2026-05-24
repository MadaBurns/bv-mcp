// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';

describe('per-IP daily free-tier cap', () => {
	afterEach(async () => {
		const { resetAllRateLimits } = await import('../src/lib/rate-limiter');
		resetAllRateLimits();
	});

	it('blocks an IP after FREE_IP_DAILY_LIMIT calls in a day (in-memory path)', async () => {
		const { checkIpDailyLimit, resetAllRateLimits } = await import('../src/lib/rate-limiter');
		const { FREE_IP_DAILY_LIMIT } = await import('../src/lib/config');
		resetAllRateLimits();
		let res;
		for (let i = 0; i <= FREE_IP_DAILY_LIMIT; i++) res = await checkIpDailyLimit('192.0.2.5', undefined);
		expect(res!.allowed).toBe(false);
	});

	it('allows under the cap', async () => {
		const { checkIpDailyLimit, resetAllRateLimits } = await import('../src/lib/rate-limiter');
		resetAllRateLimits();
		const res = await checkIpDailyLimit('192.0.2.6', undefined);
		expect(res.allowed).toBe(true);
	});
});
