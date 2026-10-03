// SPDX-License-Identifier: BUSL-1.1

/**
 * T10 item 5: the #1164 repeat-suppression cooldown must be armed only AFTER the
 * webhook accepted the alert. It used to be armed inside `shouldSendRepeat` BEFORE
 * `sendAlert` ran and ignored delivery, so an alert that first fired while the
 * webhook was down stayed suppressed for 24 h after the webhook recovered.
 * `handleClientIpHeaderAudit` already arms its cooldown on delivery only.
 *
 * Driven through the watchdog lane (a controlled, repeatable failure reason) and the
 * access-rollup provisioning lane, the two reachable without live Analytics Engine.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ScheduledEnv } from '../src/scheduled';

describe('alert cooldown is armed on delivery, not before it (T10)', () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
		vi.restoreAllMocks();
	});

	function makeFakeKv() {
		const store = new Map<string, string>();
		return {
			async get(key: string) {
				return store.has(key) ? (store.get(key) as string) : null;
			},
			async put(key: string, value: string) {
				store.set(key, value);
			},
			_store: store,
		} as unknown as KVNamespace & { _store: Map<string, string> };
	}

	/** AE queries throw (drives the watchdog); webhook POSTs return `webhookStatus()`. */
	function mockFetch(webhookStatus: () => number): Array<{ url: string; body: string }> {
		const calls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			if (url.includes('analytics_engine/sql')) throw new Error('Authentication error: token expired');
			calls.push({ url, body: init?.body as string });
			return new Response('x', { status: webhookStatus() });
		}) as typeof fetch;
		return calls;
	}

	const watchdogAlerts = (calls: Array<{ url: string; body: string }>) =>
		calls.filter((c) => c.url.includes('hooks.slack.com') && c.body.includes('Alerting pipeline failure'));

	function makeEnv(rateLimit?: KVNamespace): ScheduledEnv {
		return {
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
			RATE_LIMIT: rateLimit,
		} as unknown as ScheduledEnv;
	}

	it('re-sends on the next tick when the first delivery was rejected (webhook down)', async () => {
		const rateLimit = makeFakeKv();
		let status = 500;
		const calls = mockFetch(() => status);
		const { handleScheduled } = await import('../src/scheduled');
		const env = makeEnv(rateLimit);

		await handleScheduled(env); // webhook down: attempted, rejected
		expect(watchdogAlerts(calls)).toHaveLength(1);
		expect([...rateLimit._store.keys()].filter((k) => k.startsWith('alert-repeat:'))).toHaveLength(0);

		status = 200; // webhook recovers
		await handleScheduled(env);
		expect(watchdogAlerts(calls)).toHaveLength(2);
	});

	it('arms the cooldown once a delivery is accepted, so the following tick is suppressed', async () => {
		const rateLimit = makeFakeKv();
		let status = 500;
		const calls = mockFetch(() => status);
		const { handleScheduled } = await import('../src/scheduled');
		const env = makeEnv(rateLimit);

		await handleScheduled(env); // rejected
		status = 200;
		await handleScheduled(env); // delivered -> arms
		await handleScheduled(env); // suppressed

		expect(watchdogAlerts(calls)).toHaveLength(2);
		expect([...rateLimit._store.keys()].filter((k) => k.startsWith('alert-repeat:alerting_self_check:'))).toHaveLength(1);
	});

	it('re-sends on the next tick when the webhook fetch itself throws (unreachable)', async () => {
		const rateLimit = makeFakeKv();
		let reachable = false;
		const calls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			if (url.includes('analytics_engine/sql')) throw new Error('Authentication error: token expired');
			calls.push({ url, body: init?.body as string });
			if (!reachable) throw new Error('connection refused');
			return new Response('ok');
		}) as typeof fetch;
		const { handleScheduled } = await import('../src/scheduled');
		const env = makeEnv(rateLimit);

		await handleScheduled(env);
		reachable = true;
		await handleScheduled(env);

		expect(watchdogAlerts(calls)).toHaveLength(2);
	});
});
