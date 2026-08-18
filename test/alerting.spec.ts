import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { buildAlertPayload, sendAlert, sendFuzzingAlert } from '../src/lib/alerting';
import type { FuzzingAlert } from '../src/schemas/alerting';

const FUZZ_PAYLOAD: FuzzingAlert = {
	type: 'fuzzing_suspected',
	principalKind: 'ip',
	principalIdHash: 'i_deadbeef',
	kind: 'unknown_tool',
	count: 42,
	windowSeconds: 900,
	observedAt: '2026-08-09T00:00:00.000Z',
};

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

	it('sends fetch with redirect manual for SSRF protection', async () => {
		const calls: RequestInit[] = [];
		globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
			calls.push(init!);
			return new Response('ok', { status: 200 });
		}) as typeof fetch;
		await sendAlert('https://hooks.slack.com/test', { text: 'hello' });
		expect(calls[0].redirect).toBe('manual');
	});

	it('passes a bounded AbortSignal to fetch so a stalled webhook cannot hang the cron', async () => {
		const calls: RequestInit[] = [];
		globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
			calls.push(init!);
			return new Response('ok', { status: 200 });
		}) as typeof fetch;
		await sendAlert('https://hooks.slack.com/test', { text: 'hello' });
		expect(calls[0].signal).toBeInstanceOf(AbortSignal);
		expect(calls[0].signal!.aborted).toBe(false);
	});

	it('logs warning on HTTP error response without throwing', async () => {
		const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
		globalThis.fetch = vi.fn(async () => {
			return new Response('Forbidden', { status: 403 });
		}) as typeof fetch;
		// Should not throw
		await sendAlert('https://hooks.slack.com/test', { text: 'hello' });
		const logCalls = consoleSpy.mock.calls.map((c) => c[0]);
		const hasAlertWarning = logCalls.some((log) => typeof log === 'string' && log.includes('403'));
		expect(hasAlertWarning).toBe(true);
		consoleSpy.mockRestore();
	});

	it('rejects non-HTTPS webhook URLs', async () => {
		const mockFetch = vi.fn() as typeof fetch;
		globalThis.fetch = mockFetch;
		await sendAlert('http://hooks.slack.com/test', { text: 'hello' });
		expect(mockFetch).not.toHaveBeenCalled();
	});
});

describe('sendAlert delivery outcome', () => {
	let originalFetch: typeof globalThis.fetch;

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it('reports true when the webhook accepts the alert', async () => {
		globalThis.fetch = vi.fn(async () => new Response('ok', { status: 200 })) as typeof fetch;
		expect(await sendAlert('https://hooks.slack.com/test', { text: 'hello' })).toBe(true);
	});

	it('reports false when the webhook rejects the alert', async () => {
		// The exact production failure: a Cloudflare bot challenge returns 403 and the
		// alert is dropped. Callers could not observe this because sendAlert was void.
		globalThis.fetch = vi.fn(async () => new Response('Forbidden', { status: 403 })) as typeof fetch;
		expect(await sendAlert('https://hooks.slack.com/test', { text: 'hello' })).toBe(false);
	});

	it('reports false when delivery throws', async () => {
		globalThis.fetch = vi.fn(async () => {
			throw new Error('network error');
		}) as typeof fetch;
		expect(await sendAlert('https://hooks.slack.com/test', { text: 'hello' })).toBe(false);
	});

	it('reports false for an unusable webhook URL', async () => {
		globalThis.fetch = vi.fn() as typeof fetch;
		expect(await sendAlert('', { text: 'hello' })).toBe(false);
		expect(await sendAlert('http://hooks.slack.com/test', { text: 'hello' })).toBe(false);
	});
});

describe('sendAlert service-binding dispatch', () => {
	let originalFetch: typeof globalThis.fetch;
	const INGEST_URL = 'https://www.blackveilsecurity.com/api/internal/ops/bv-mcp-alerts/abc123';

	beforeEach(() => {
		originalFetch = globalThis.fetch;
	});

	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it('delivers the bv-web ingest URL over the service binding, not the public edge', async () => {
		// Why this exists: Worker-originated fetches to www.blackveilsecurity.com are
		// intercepted by the zone's bot challenge and 403'd before reaching bv-web.
		// Service bindings bypass the edge entirely.
		const globalCalls: string[] = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			globalCalls.push(String(input));
			return new Response('Forbidden', { status: 403 });
		}) as typeof fetch;

		const bindingCalls: string[] = [];
		const bvWeb = {
			fetch: vi.fn(async (input: RequestInfo | URL) => {
				bindingCalls.push(String(input));
				return new Response(JSON.stringify({ ok: true }), { status: 200 });
			}),
		};

		const delivered = await sendAlert(INGEST_URL, { text: 'hello' }, { bvWeb: bvWeb as unknown as Fetcher });

		expect(delivered).toBe(true);
		expect(bindingCalls).toHaveLength(1);
		expect(globalCalls).toHaveLength(0);
	});

	it('leaves a generic webhook on global fetch even when the binding is available', async () => {
		// sendAlert is deliberately a generic Slack/Discord-shaped poster. Only the
		// bv-web ingest path may be re-routed through the internal binding.
		const globalCalls: string[] = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			globalCalls.push(String(input));
			return new Response('ok', { status: 200 });
		}) as typeof fetch;
		const bvWeb = { fetch: vi.fn(async () => new Response('ok', { status: 200 })) };

		await sendAlert('https://hooks.slack.com/test', { text: 'hello' }, { bvWeb: bvWeb as unknown as Fetcher });

		expect(globalCalls).toHaveLength(1);
		expect(bvWeb.fetch).not.toHaveBeenCalled();
	});

	it('routes a fuzzing alert over the binding and reports the outcome', async () => {
		// sendFuzzingAlert previously discarded its response entirely, so a 403 here
		// was 100% silent — worse than sendAlert, which at least logged.
		globalThis.fetch = vi.fn(async () => new Response('Forbidden', { status: 403 })) as typeof fetch;
		const bvWeb = { fetch: vi.fn(async () => new Response(JSON.stringify({ ok: true }), { status: 200 })) };

		const delivered = await sendFuzzingAlert(INGEST_URL, FUZZ_PAYLOAD, { bvWeb: bvWeb as unknown as Fetcher });

		expect(delivered).toBe(true);
		expect(bvWeb.fetch).toHaveBeenCalledTimes(1);
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});

	it('reports false when a fuzzing alert is rejected', async () => {
		globalThis.fetch = vi.fn(async () => new Response('Not Found', { status: 404 })) as typeof fetch;
		expect(await sendFuzzingAlert('https://hooks.slack.com/test', FUZZ_PAYLOAD)).toBe(false);
	});

	it('falls back to global fetch for the ingest URL when no binding is bound', async () => {
		// BSL self-hosts have no BV_WEB binding; they must keep the public-URL path.
		const globalCalls: string[] = [];
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
			globalCalls.push(String(input));
			return new Response('ok', { status: 200 });
		}) as typeof fetch;

		await sendAlert(INGEST_URL, { text: 'hello' });

		expect(globalCalls).toEqual([INGEST_URL]);
	});
});
