// T10 item 1 regression: handleFuzzingScan runs on the `*/15 * * * *` cron but used to read only
// the last FUZZ_THRESHOLDS.windowSeconds (60 s) of counter buckets, so a burst that ended more
// than a minute before the tick was never scored (and the 600 s counter TTL would have evicted
// it before the next 15-min tick anyway). The scan must look back over the full inter-tick
// interval while scoreWindow keeps applying the per-60 s-window threshold.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { env } from 'cloudflare:test';
import { handleFuzzingScan } from '../src/scheduled';
import { FUZZ_THRESHOLDS } from '../src/lib/config';
import { recordEvent } from '../src/lib/fuzzing-counter';

const ALERT_WEBHOOK = 'https://hooks.example.test/t10-scan-window';

let originalFetch: typeof globalThis.fetch;
let webhookCalls: { url: string; body: string }[] = [];

async function clearFuzz() {
	const list = await env.RATE_LIMIT.list({ prefix: 'fuzz:' });
	await Promise.all(list.keys.map((k) => env.RATE_LIMIT.delete(k.name)));
}

/** Seed `count` events of `kind` into the 10 s bucket containing `nowSec - agoSeconds`. */
async function seedAgo(principalId: string, agoSeconds: number, count: number, kind = 'unknown_tool'): Promise<void> {
	const bucket = Math.floor((Date.now() / 1000 - agoSeconds) / 10) * 10;
	await env.RATE_LIMIT.put(`fuzz:p:${principalId}:e:${bucket}:${kind}`, String(count), { expirationTtl: 3600 });
}

beforeEach(async () => {
	await clearFuzz();
	webhookCalls = [];
	originalFetch = globalThis.fetch;
	globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
		if (url.startsWith(ALERT_WEBHOOK)) {
			webhookCalls.push({ url, body: typeof init?.body === 'string' ? init.body : '' });
			return new Response('ok', { status: 200 });
		}
		return originalFetch(input as RequestInfo, init);
	}) as typeof fetch;
});

afterEach(async () => {
	globalThis.fetch = originalFetch;
	await clearFuzz();
});

describe('handleFuzzingScan — fuzzing scan window covers the inter-tick interval', () => {
	const scanEnv = () => ({ ...env, ALERT_WEBHOOK_URL: ALERT_WEBHOOK, RATE_LIMIT: env.RATE_LIMIT });

	it('scores a burst that ended 5 minutes before the tick (outside the old 60 s read window)', async () => {
		const principal = 'c'.repeat(16);
		await seedAgo(principal, 300, FUZZ_THRESHOLDS.unknown_tool + 5);

		await handleFuzzingScan(scanEnv());
		expect(webhookCalls.length).toBe(1);
		expect(JSON.parse(webhookCalls[0].body).kind).toBe('unknown_tool');
	});

	it('keeps per-window semantics: sub-threshold bursts spread across the interval are NOT summed', async () => {
		const principal = 'd'.repeat(16);
		const half = Math.floor(FUZZ_THRESHOLDS.unknown_tool / 2);
		// Three bursts of `half` events, 3 minutes apart: each 60 s window sees only `half` (< 30),
		// while the sum across the whole look-back would be 45 (>= 30).
		await seedAgo(principal, 30, half);
		await seedAgo(principal, 210, half);
		await seedAgo(principal, 390, half);

		await handleFuzzingScan(scanEnv());
		expect(webhookCalls.length).toBe(0);
	});

	it('recordEvent TTL outlives the 15-minute cron interval so the next tick can still see the burst', async () => {
		const principal = 'e'.repeat(16);
		await recordEvent(env.RATE_LIMIT, principal, 'unknown_tool', Math.floor(Date.now() / 1000));
		const list = await env.RATE_LIMIT.list({ prefix: `fuzz:p:${principal}:` });
		expect(list.keys.length).toBe(1);
		const expiration = list.keys[0].expiration;
		expect(expiration).toBeDefined();
		// Cron cadence is 15 min (900 s); the counter must survive at least that long plus the window.
		expect(expiration! - Math.floor(Date.now() / 1000)).toBeGreaterThanOrEqual(900 + FUZZ_THRESHOLDS.windowSeconds - 5);
	});
});
