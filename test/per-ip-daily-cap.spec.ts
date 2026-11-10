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

	it('a tools/call denied by the per-minute limit leaves the per-IP and global daily counts unchanged (SQ-560)', async () => {
		const { checkRateLimit, checkIpDailyLimit, checkGlobalDailyLimit, resetAllRateLimits, resetGlobalDailyLimit } =
			await import('../src/lib/rate-limiter');
		const { FREE_IP_DAILY_LIMIT, GLOBAL_DAILY_TOOL_LIMIT } = await import('../src/lib/config');
		const { executeMcpRequest } = await import('../src/mcp/execute');
		resetAllRateLimits();
		resetGlobalDailyLimit();
		const ip = '192.0.2.7';

		// Fill the 50/min window directly, so no tools/call is allowed (or counted) beforehand.
		for (let i = 0; i < 50; i++) expect((await checkRateLimit(ip)).allowed).toBe(true);
		for (let id = 1; id <= 3; id++) {
			const denied = await executeMcpRequest({
				body: { jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'check_spf', arguments: { domain: 'example.com' } } },
				allowStreaming: false,
				batchMode: false,
				batchSize: 1,
				responseTransport: 'json',
				startTime: Date.now(),
				ip,
				isAuthenticated: false,
				validateSession: false,
				serverVersion: 'test',
			});
			if (denied.kind !== 'response') throw new Error('expected response');
			expect(denied.httpStatus).toBe(429);
			expect((denied.payload as { error: { message: string } }).error.message).toMatch(/^Rate limit exceeded\. Retry after \d+s$/);
		}

		// Each probe counts itself once, so an untouched counter reports exactly limit - 1.
		expect((await checkIpDailyLimit(ip, undefined)).remaining).toBe(FREE_IP_DAILY_LIMIT - 1);
		expect((await checkGlobalDailyLimit(GLOBAL_DAILY_TOOL_LIMIT)).remaining).toBe(GLOBAL_DAILY_TOOL_LIMIT - 1);
	});
});
