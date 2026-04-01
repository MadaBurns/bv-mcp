import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { buildAlertPayload, sendAlert } from '../src/lib/alerting';

describe('buildAlertPayload', () => {
	it('builds Slack-compatible payload', () => {
		const payload = buildAlertPayload({
			title: 'High error rate',
			severity: 'warning',
			metrics: { error_pct: 12.5, p95_ms: 8500, total_calls: 200 },
			threshold: 'error_pct > 5%',
		});
		expect(payload.text).toContain('High error rate');
		expect(payload.text).toContain('12.5');
	});

	it('includes severity emoji', () => {
		const warning = buildAlertPayload({ title: 'test', severity: 'warning', metrics: {}, threshold: 'n/a' });
		const critical = buildAlertPayload({ title: 'test', severity: 'critical', metrics: {}, threshold: 'n/a' });
		expect(warning.text).toContain('Warning');
		expect(critical.text).toContain('Critical');
	});
});

describe('sendAlert', () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it('posts JSON to webhook URL', async () => {
		const calls: Array<{ url: string; init: RequestInit }> = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			calls.push({ url: String(input), init: init! });
			return new Response('ok', { status: 200 });
		}) as typeof fetch;
		await sendAlert('https://hooks.slack.com/test', { text: 'hello' });
		expect(calls).toHaveLength(1);
		expect(calls[0].url).toBe('https://hooks.slack.com/test');
		expect(calls[0].init.method).toBe('POST');
	});

	it('does not throw on fetch failure', async () => {
		globalThis.fetch = vi.fn(async () => {
			throw new Error('network error');
		}) as typeof fetch;
		// Should not throw
		await sendAlert('https://hooks.slack.com/test', { text: 'hello' });
	});

	it('no-ops when webhookUrl is empty', async () => {
		const mockFetch = vi.fn() as typeof fetch;
		globalThis.fetch = mockFetch;
		await sendAlert('', { text: 'hello' });
		expect(mockFetch).not.toHaveBeenCalled();
	});
});
