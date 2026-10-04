// SPDX-License-Identifier: BUSL-1.1
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ScheduledEnv } from '../src/scheduled';
import { armRepeatCooldown, recoverRepeatAlert, shouldSendRepeat } from '../src/lib/alert-repeat';

describe('repeat alert incident lifecycle', () => {
	afterEach(() => vi.restoreAllMocks());
	function fixture() {
		const values = new Map<string, { value: string; expires?: number }>();
		const kv = {
			async get(key: string) {
				const row = values.get(key);
				return row && (!row.expires || row.expires > Date.now()) ? row.value : null;
			},
			async put(key: string, value: string, options?: { expirationTtl?: number }) {
				values.set(key, { value, expires: options?.expirationTtl ? Date.now() + options.expirationTtl * 1000 : undefined });
			},
			async delete(key: string) {
				values.delete(key);
			},
		};
		return { env: { RATE_LIMIT: kv as unknown as KVNamespace } as ScheduledEnv, kv };
	}
	it('reminds at the daily boundary and recovers once, permitting a fresh identical incident', async () => {
		const { env } = fixture();
		let now = 100000;
		vi.spyOn(Date, 'now').mockImplementation(() => now);
		const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('ok'));
		expect(await shouldSendRepeat(env, 'watchdog', 'failed')).toBe(true);
		await armRepeatCooldown(env, 'watchdog', 'failed', now);
		now += 86400000 - 1;
		expect(await shouldSendRepeat(env, 'watchdog', 'failed')).toBe(false);
		now++;
		expect(await shouldSendRepeat(env, 'watchdog', 'failed')).toBe(true);
		await recoverRepeatAlert(env, 'https://hooks.slack.com/test', 'watchdog');
		await recoverRepeatAlert(env, 'https://hooks.slack.com/test', 'watchdog');
		expect(fetch).toHaveBeenCalledTimes(1);
		expect(await shouldSendRepeat(env, 'watchdog', 'failed')).toBe(true);
	});
	it('retries recovery after rejected delivery', async () => {
		const { env } = fixture();
		await armRepeatCooldown(env, 'watchdog', 'failed', Date.now());
		const fetch = vi
			.spyOn(globalThis, 'fetch')
			.mockResolvedValueOnce(new Response('down', { status: 503 }))
			.mockResolvedValue(new Response('ok'));
		await recoverRepeatAlert(env, 'https://hooks.slack.com/test', 'watchdog');
		await recoverRepeatAlert(env, 'https://hooks.slack.com/test', 'watchdog');
		await recoverRepeatAlert(env, 'https://hooks.slack.com/test', 'watchdog');
		expect(fetch).toHaveBeenCalledTimes(2);
	});
	it('clears earlier reasons so a recovered incident can recur immediately', async () => {
		const { env } = fixture();
		vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('ok'));
		await armRepeatCooldown(env, 'watchdog', 'reason A', Date.now());
		await armRepeatCooldown(env, 'watchdog', 'reason B', Date.now());
		await recoverRepeatAlert(env, 'https://hooks.slack.com/test', 'watchdog');
		expect(await shouldSendRepeat(env, 'watchdog', 'reason A')).toBe(true);
	});
	it('fails open to sending on store failures', async () => {
		const { env, kv } = fixture();
		vi.spyOn(kv, 'get').mockRejectedValue(new Error('unavailable'));
		expect(await shouldSendRepeat(env, 'watchdog', 'failed')).toBe(true);
	});
	it('does not arm suppression when recording active incident state fails', async () => {
		const { env, kv } = fixture();
		vi.spyOn(kv, 'put').mockRejectedValueOnce(new Error('active state unavailable'));
		await armRepeatCooldown(env, 'watchdog', 'failed', Date.now());
		expect(await shouldSendRepeat(env, 'watchdog', 'failed')).toBe(true);
	});
});
