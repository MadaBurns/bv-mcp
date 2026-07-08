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

	it('sends a service-binding degradation alert when present-binding events appear', async () => {
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push({ url, body: init?.body as string });

			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				// Healthy tool_call + rate_limit so only the degradation branch fires.
				if (query.includes("index1 = 'degradation'")) {
					return new Response(JSON.stringify({ data: [{ component: 'recon', degradation_type: 'binding_5xx', event_count: 4 }] }));
				}
				if (query.includes('tool_call')) {
					return new Response(JSON.stringify({ data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }] }));
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

		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		expect(webhookCall!.body).toContain('binding');
	});

	it('sends an async-path failure alert when queue_batch failures cross the threshold', async () => {
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push({ url, body: init?.body as string });

			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				if (query.includes("index1 = 'queue_batch'")) {
					// 4 failed messages across an errored brand-audit batch.
					return new Response(
						JSON.stringify({
							data: [{ handler: 'brand-audit-queue', batch_count: 1, error_batch_count: 1, failure_count: 4 }],
						}),
					);
				}
				// Healthy tool_call / rate_limit / degradation so only the queue branch fires.
				if (query.includes("index1 = 'degradation'")) return new Response(JSON.stringify({ data: [] }));
				if (query.includes('tool_call')) {
					return new Response(JSON.stringify({ data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }] }));
				}
				if (query.includes('rate_limit')) return new Response(JSON.stringify({ data: [{ total_hits: 2 }] }));
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		});

		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		expect(webhookCall!.body).toContain('Async-path failures');
		expect(webhookCall!.body).toContain('brand-audit-queue');
	});

	it('sends a cost-ceiling alert when a cost_ceiling_degraded row reaches the cron (R9)', async () => {
		// The whole point of the R9 fix: a cost_ceiling_degraded row (emitted while
		// the QuotaCoordinator breaker is OPEN) must NOT be filtered out and must
		// reach the 15-min cron alert. Here the engine returns such a row.
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push({ url, body: init?.body as string });
			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				if (query.includes("index1 = 'degradation'")) {
					return new Response(
						JSON.stringify({ data: [{ component: 'global_cost_ceiling', degradation_type: 'cost_ceiling_degraded', event_count: 8 }] }),
					);
				}
				if (query.includes('tool_call')) {
					return new Response(JSON.stringify({ data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }] }));
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

		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		// Title reads as a cost-ceiling degradation (not "Service-binding") and the
		// breakdown carries the cost-ceiling component.
		expect(webhookCall!.body).toContain('cost-ceiling');
		expect(webhookCall!.body).toContain('global_cost_ceiling');
	});

	it('does NOT send an async-path failure alert when no queue_batch failures occur (0 rows)', async () => {
		const fetchCalls: string[] = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push(url);
			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				// The query's HAVING clause filters clean batches, so the engine returns no rows.
				if (query.includes("index1 = 'queue_batch'")) return new Response(JSON.stringify({ data: [] }));
				if (query.includes("index1 = 'degradation'")) return new Response(JSON.stringify({ data: [] }));
				if (query.includes('tool_call'))
					return new Response(JSON.stringify({ data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }] }));
				if (query.includes('rate_limit')) return new Response(JSON.stringify({ data: [{ total_hits: 2 }] }));
				return new Response(JSON.stringify({ data: [] }));
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({ CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't', ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test' });
		expect(fetchCalls.filter((u) => u.includes('hooks.slack.com'))).toHaveLength(0);
	});

	it('does NOT send a degradation alert when only kv_fallback occurs (query excludes it → 0 rows)', async () => {
		const fetchCalls: string[] = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push(url);
			if (url.includes('analytics_engine/sql')) {
				const query = init?.body as string;
				// The SQL itself filters kv_fallback, so the engine returns no rows here.
				if (query.includes("index1 = 'degradation'")) return new Response(JSON.stringify({ data: [] }));
				if (query.includes('tool_call'))
					return new Response(JSON.stringify({ data: [{ total_calls: 100, error_count: 1, error_pct: 1.0, p95_ms: 500 }] }));
				if (query.includes('rate_limit')) return new Response(JSON.stringify({ data: [{ total_hits: 2 }] }));
				return new Response(JSON.stringify({ data: [] }));
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({ CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't', ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test' });
		expect(fetchCalls.filter((u) => u.includes('hooks.slack.com'))).toHaveLength(0);
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
				return new Response(JSON.stringify({ data: [] }));
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

	it('sends a watchdog alert through the webhook when the analytics query pipeline fails', async () => {
		const fetchCalls: Array<{ url: string; body: string }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			fetchCalls.push({ url, body: init?.body as string });
			if (url.includes('analytics_engine/sql')) {
				throw new Error('Authentication error: token expired');
			}
			return new Response('ok');
		}) as typeof fetch;

		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled({
			CF_ACCOUNT_ID: 'test-account',
			CF_ANALYTICS_TOKEN: 'test-token',
			ALERT_WEBHOOK_URL: 'https://hooks.slack.com/test',
		} as ScheduledEnv);

		const webhookCall = fetchCalls.find((c) => c.url.includes('hooks.slack.com'));
		expect(webhookCall).toBeDefined();
		expect(webhookCall!.body).toContain('Alerting pipeline failure');
	});
});
