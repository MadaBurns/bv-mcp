// M4 regression: handleFuzzingScan ran every 15 min and re-alerted every flagged
// principal each tick — no per-principal cooldown, no per-tick cap. A sustained
// fuzzer (or rotating-IP attacker) drove repeat alerts that hit Slack webhook
// rate limits without backoff.
//
// Fix: write a `fuzz:alerted:<principalId>` KV marker (1h TTL); skip if present.
// Cap total alerts per tick at MAX_ALERTS_PER_TICK.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { env } from 'cloudflare:test';
import { handleFuzzingScan } from '../src/scheduled';
import { FUZZ_THRESHOLDS } from '../src/lib/config';

const ALERT_WEBHOOK = 'https://hooks.example.test/m4-dedup';

let originalFetch: typeof globalThis.fetch;
let webhookCalls: { url: string; body: string }[] = [];

async function clearFuzz() {
	const list = await env.RATE_LIMIT.list({ prefix: 'fuzz:' });
	await Promise.all(list.keys.map((k) => env.RATE_LIMIT.delete(k.name)));
}

/**
 * Seed the fuzz counter for `principalId` with `count` events of `kind`,
 * all in the current 10s bucket so they fall inside the sliding window.
 */
async function seedFuzzWindow(principalId: string, count: number, kind = 'unknown_tool'): Promise<void> {
	const bucket = Math.floor(Date.now() / 1000 / 10) * 10;
	const key = `fuzz:p:${principalId}:e:${bucket}:${kind}`;
	await env.RATE_LIMIT.put(key, String(count), { expirationTtl: 600 });
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

describe('handleFuzzingScan — alert dedup + cap', () => {
	it('alerts on first tick, suppresses on second tick within the cooldown', async () => {
		const principal = 'a'.repeat(16); // keyHash-shaped principalId
		await seedFuzzWindow(principal, FUZZ_THRESHOLDS.unknown_tool + 5);

		const customEnv = { ...env, ALERT_WEBHOOK_URL: ALERT_WEBHOOK, RATE_LIMIT: env.RATE_LIMIT };

		await handleFuzzingScan(customEnv);
		expect(webhookCalls.length).toBe(1);

		// Second tick within the cooldown — events are still in the window, threshold
		// still trips, but the dedup marker should suppress the alert.
		webhookCalls.length = 0;
		await handleFuzzingScan(customEnv);
		expect(webhookCalls.length).toBe(0);
	});

	it('caps alerts per tick at MAX_ALERTS_PER_TICK (10)', async () => {
		// Seed 15 distinct principals all over threshold; cap should fire after 10.
		for (let i = 0; i < 15; i++) {
			const principal = String(i).padStart(16, 'b');
			await seedFuzzWindow(principal, FUZZ_THRESHOLDS.unknown_tool + 5);
		}

		const customEnv = { ...env, ALERT_WEBHOOK_URL: ALERT_WEBHOOK, RATE_LIMIT: env.RATE_LIMIT };
		await handleFuzzingScan(customEnv);
		expect(webhookCalls.length).toBeLessThanOrEqual(10);
		expect(webhookCalls.length).toBeGreaterThan(0);
	});
});
