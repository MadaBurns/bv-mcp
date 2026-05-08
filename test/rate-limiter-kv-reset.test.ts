// #96 fix: rate-limiter KV state must be resettable per-test in addition to
// the in-memory counter. Pre-fix, `resetAllRateLimits()` only cleared the
// per-isolate Map but left `rl:min:*`, `rl:hr:*`, `rl:day:tool:*` and
// `rl:global:day:*` keys in the RATE_LIMIT KV namespace. On slow CI workers
// where vitest's import phase consumes ~123s, the 60s minute-window TTL
// hadn't expired by the time the next test ran — earlier tests' counters
// bled forward and broke `tools/call notifications consume exactly one
// rate-limit unit per request` (line 1219) and `auto-recovers expired
// sessions for tools/call by reviving the same session ID` (line 1484) in
// `test/index.spec.ts`.

import { env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { resetAllRateLimitsKv } from '../src/lib/rate-limiter';

async function listRlKeys(): Promise<string[]> {
	const list = await env.RATE_LIMIT.list({ prefix: 'rl:' });
	return list.keys.map((k) => k.name);
}

beforeEach(async () => {
	await resetAllRateLimitsKv(env.RATE_LIMIT);
});
afterEach(async () => {
	await resetAllRateLimitsKv(env.RATE_LIMIT);
});

describe('resetAllRateLimitsKv', () => {
	it('removes every rl:* key from the namespace', async () => {
		await env.RATE_LIMIT.put('rl:min:192.0.2.1:200', '50', { expirationTtl: 60 });
		await env.RATE_LIMIT.put('rl:hr:192.0.2.1:33', '300', { expirationTtl: 3600 });
		await env.RATE_LIMIT.put('rl:day:tool:scan_domain:abcd:55', '10', { expirationTtl: 86_400 });
		await env.RATE_LIMIT.put('rl:global:day:55', '500', { expirationTtl: 86_400 });
		await env.RATE_LIMIT.put('rl:ctl:min:192.0.2.1:200', '5', { expirationTtl: 60 });

		expect((await listRlKeys()).length).toBeGreaterThanOrEqual(5);

		await resetAllRateLimitsKv(env.RATE_LIMIT);

		expect(await listRlKeys()).toEqual([]);
	});

	it('leaves non-rl keys alone', async () => {
		await env.RATE_LIMIT.put('tier:abcd', '{"tier":"free"}', { expirationTtl: 60 });
		await env.RATE_LIMIT.put('rl:min:192.0.2.1:200', '50', { expirationTtl: 60 });

		await resetAllRateLimitsKv(env.RATE_LIMIT);

		expect(await env.RATE_LIMIT.get('tier:abcd')).toBe('{"tier":"free"}');
		expect(await env.RATE_LIMIT.get('rl:min:192.0.2.1:200')).toBeNull();
	});

	it('is fail-soft on KV errors (test isolation must not throw)', async () => {
		const broken = {
			list: async () => {
				throw new Error('KV unavailable');
			},
		} as unknown as KVNamespace;
		// Must not throw — caller's beforeEach should never reject because of test infra.
		await expect(resetAllRateLimitsKv(broken)).resolves.toBeUndefined();
	});
});
