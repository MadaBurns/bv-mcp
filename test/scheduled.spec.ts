import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ScheduledEnv } from '../src/scheduled';

describe('handleScheduled', () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it('does nothing when ALERT_WEBHOOK_URL is not configured', async () => {
		const mockFetch = vi.fn() as typeof fetch;
		globalThis.fetch = mockFetch;
		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({} as ScheduledEnv);
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it('does nothing when CF_ACCOUNT_ID or CF_ANALYTICS_TOKEN is missing', async () => {
		const mockFetch = vi.fn() as typeof fetch;
		globalThis.fetch = mockFetch;
		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({ ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test' } as ScheduledEnv);
		expect(mockFetch).not.toHaveBeenCalled();
	});

	it('sends alert when error rate exceeds threshold', async () => {
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push({ url, body: init?.body as string });

			// Mock Analytics Engine SQL API response
			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				if (query.includes('tool_call')) {
					return new Response(
						JSON.stringify({
							data: [{ total_calls: 100, error_count: 15, error_pct: 15.0, p95_ms: 5000 }],
						}),
					);
				}
				if (query.includes('rate_limit')) {
					return new Response(JSON.stringify({ data: [{ total_hits: 5 }] }));
				}
			}
			// Webhook call
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
			ALERT_ERROR_THRESHOLD: '5',
			ALERT_P95_THRESHOLD: '10000',
			ALERT_RATE_LIMIT_THRESHOLD: '50',
		});

		// Should have called Analytics Engine + webhook
		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		expect(webhookCall!.body).toContain('error');
	});

	it('does not send alert when metrics are within thresholds', async () => {
		const fetchCalls: string[] = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push(url);

			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				if (query.includes('tool_call')) {
					return new Response(
						JSON.stringify({
							data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }],
						}),
					);
				}
				if (query.includes('rate_limit')) {
					return new Response(JSON.stringify({ data: [{ total_hits: 2 }] }));
				}
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		});

		// Should NOT have called the webhook
		const webhookCalls = fetchCalls.filter((u) => u.includes('hooks.slack.com'));
		expect(webhookCalls).toHaveLength(0);
	});
});
