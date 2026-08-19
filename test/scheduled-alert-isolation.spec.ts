// SPDX-License-Identifier: BUSL-1.1

/**
 * ONE FAILING QUERY MUST NOT BLIND EVERY OTHER ALERT.
 *
 * `runAlertingChecks` ran all six threshold queries inside a single `try`, so the
 * FIRST rejection aborted the whole check — error rate, p95, rate-limit surge,
 * binding degradation, queue failures and tail exceptions all went dark together
 * and only the watchdog fired. That is exactly how a malformed-SQL 422 in the very
 * first query (`queryRecentAnomalies`) disabled the entire alerting pipeline for
 * 610 consecutive cron ticks in 2026-08 (PR #708) — including the tail-exception
 * alert, which is the one that would have surfaced fatal Worker crashes.
 *
 * The blast radius of a single broken query must be that query alone. These tests
 * fail an EARLY query and assert the LATER, independent alerts still fire.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';

const WEBHOOK = 'https://hooks.slack.com/test';

interface Call {
	url: string;
	body: string;
}

/**
 * Install a fetch mock where every AE query succeeds with alert-worthy data EXCEPT
 * the ones whose SQL matches `failOn`, which reject with a 422 the way the AE SQL
 * API does for an unsupported construct.
 */
function mockAnalytics(failOn: RegExp): Call[] {
	const calls: Call[] = [];
	globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
		const body = (init?.body as string) ?? '';
		calls.push({ url, body });

		if (!url.includes('analytics_engine/sql')) return new Response('ok');

		if (failOn.test(body)) {
			return new Response('Input was invalid: unsupported expression type: CASE WHEN', { status: 422 });
		}
		// Every non-failing query returns data that TRIPS its threshold, so a missing
		// alert means the query never ran — not that it ran and found nothing.
		if (body.includes("index1 = 'tool_call'")) {
			return Response.json({ data: [{ total_calls: 100, error_count: 90, error_pct: 90, p95_ms: 99_000 }] });
		}
		if (body.includes("index1 = 'rate_limit'")) return Response.json({ data: [{ total_hits: 9_999 }] });
		if (body.includes("index1 = 'degradation'")) {
			return Response.json({ data: [{ component: 'BV_RECON', degradation_type: 'timeout', event_count: 500 }] });
		}
		if (body.includes("index1 = 'queue_batch'")) {
			return Response.json({ data: [{ handler: 'brand-audit', batch_count: 5, error_batch_count: 5, failure_count: 50 }] });
		}
		if (body.includes("index1 = 'tail'")) return Response.json({ data: [{ exception_count: 250 }] });
		return Response.json({ data: [] });
	}) as typeof fetch;
	return calls;
}

function alertTitles(calls: Call[]): string[] {
	return calls.filter((c) => c.url.includes('hooks.slack.com')).map((c) => c.body);
}

const ENV = { CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't', ALERT_WEBHOOK_URL: WEBHOOK };

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('alert query isolation', () => {
	it('a failing FIRST query (anomalies) does not suppress the later alerts', async () => {
		// queryRecentAnomalies is the first query and the one that 422'd in the real
		// outage. Under the single-try design this killed all five later alerts.
		const calls = mockAnalytics(/index1 = 'tool_call'/);
		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(ENV);

		const sent = alertTitles(calls).join('\n');
		expect(sent).toContain('Rate limit surge');
		expect(sent).toContain('Service-binding degradation');
		expect(sent).toContain('Async-path failures');
		expect(sent).toContain('Fatal Worker exceptions');
	});

	it('reports the failed query as a partial failure, not a total pipeline failure', async () => {
		const calls = mockAnalytics(/index1 = 'tool_call'/);
		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(ENV);

		const sent = alertTitles(calls).join('\n');
		// The operator must still learn a query broke — silently degrading to "some
		// alerts" would be worse than the outage, because nothing would page at all.
		expect(sent).toContain('Alerting check degraded');
		// …and it must name WHICH one plus the AE reason, so it is diagnosable.
		expect(sent).toContain('anomalies');
		expect(sent).toContain('unsupported expression type');
		// It is NOT the total-failure watchdog: that would misreport a partial outage.
		expect(sent).not.toContain('analytics check could not run');
	});

	it('a failing MIDDLE query does not suppress the queries after it', async () => {
		const calls = mockAnalytics(/index1 = 'degradation'/);
		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(ENV);

		const sent = alertTitles(calls).join('\n');
		expect(sent).toContain('Error rate');
		expect(sent).toContain('Rate limit surge');
		expect(sent).toContain('Async-path failures');
		expect(sent).toContain('Fatal Worker exceptions');
		expect(sent).not.toContain('Service-binding degradation');
	});

	it('still pages the TOTAL-failure watchdog when every query fails', async () => {
		// A whole-pipeline outage (expired token, AE down) must keep its single loud
		// page rather than fragmenting into six separate degraded notices.
		const calls = mockAnalytics(/index1/);
		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(ENV);

		const sent = alertTitles(calls).join('\n');
		expect(sent).toContain('Alerting pipeline failure');
		expect(sent).toContain('analytics check could not run');
	});

	it('sends no degraded notice when every query succeeds', async () => {
		const calls = mockAnalytics(/__never_matches__/);
		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(ENV);

		const sent = alertTitles(calls).join('\n');
		expect(sent).not.toContain('Alerting check degraded');
		expect(sent).not.toContain('Alerting pipeline failure');
		// Sanity: the mock really was tripping thresholds, so the absence above is
		// meaningful rather than a silent no-op.
		expect(sent).toContain('Fatal Worker exceptions');
	});
});
