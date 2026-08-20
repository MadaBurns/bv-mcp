// SPDX-License-Identifier: BUSL-1.1

/**
 * THE P95 ALERT PAGED `critical` FOR DESIGNED BEHAVIOUR (#729).
 *
 * A live example: `P95 latency 22612ms (last 15m)` / `total_calls: 35`, severity
 * critical. Nothing was wrong. Three independent defects combined:
 *
 *  1. NO VOLUME FLOOR. The only guard was `total_calls > 0`. At the measured rate
 *     (~11 tool calls/hour) a 15m window holds ~3 calls, and
 *     `quantileExactWeighted(0.95)` over a handful of samples converges on the
 *     MAXIMUM — so "p95" was reporting the single slowest call in the window.
 *  2. NO WORKLOAD CLASS. `batch_scan` (25s budget), `compare_domains`,
 *     `discover_subdomains` and `discover_brand_domains` were pooled with
 *     `scan_domain` against one 10s ceiling. Measured over 7 days, those four are
 *     the ONLY tools whose p95 exceeds 10s — `discover_brand_domains` at 25,715ms
 *     could not run without paging critical, because 25,715 > 10,000 × 2.
 *  3. THRESHOLD BELOW THE DESIGN ENVELOPE. `scan_domain` is ~90% of interactive
 *     volume and is built to run to a 15s `SCAN_TIMEOUT_MS`; its measured p95 is
 *     8,952ms, ~10% under the old 10s ceiling.
 *
 * These tests pin the fix as INVARIANTS (abstain below the floor, class-specific
 * ceilings, one evaluation per non-overlapping window) rather than as the specific
 * numbers, so retuning a threshold does not require rewriting the guarantees.
 */

import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { LONG_RUNNING_TOOLS, isLongRunningTool } from '../src/lib/config';

const WEBHOOK = 'https://hooks.slack.com/test';

const ENV = { CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't', ALERT_WEBHOOK_URL: WEBHOOK };

interface Call {
	url: string;
	body: string;
}

/**
 * A time at which the latency lane evaluates. Epoch-minutes divisible by the 360m
 * lookback: any UTC 06:00 works, because 1440 (minutes/day) is a multiple of 360.
 */
const AT_WINDOW_BOUNDARY = Date.UTC(2026, 7, 21, 6, 0, 0);
/** 09:30Z — 570 minutes into the day, so 570 % 360 = 210: mid-window, must not evaluate. */
const MID_WINDOW = Date.UTC(2026, 7, 21, 9, 30, 0);

/**
 * Mock AE. `latencyRows` is what the workload-class query returns; every OTHER
 * query returns data that does NOT trip its threshold, so any alert observed came
 * from the latency lane and nothing else.
 */
function mockAnalytics(latencyRows: Array<Record<string, unknown>>): Call[] {
	const calls: Call[] = [];
	globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
		const body = (init?.body as string) ?? '';
		calls.push({ url, body });

		if (!url.includes('analytics_engine/sql')) return new Response('ok');
		if (body.includes('workload_class')) return Response.json({ data: latencyRows });
		// The 15m anomalies lane: healthy error rate, but a p95 that WOULD have paged
		// under the old design. See the regression test below.
		if (body.includes("index1 = 'tool_call'")) {
			return Response.json({ data: [{ total_calls: 35, error_count: 0, error_pct: 0, p95_ms: 22_612 }] });
		}
		return Response.json({ data: [] });
	}) as typeof fetch;
	return calls;
}

function alertsSent(calls: Call[]): string {
	return calls
		.filter((c) => c.url.includes('hooks.slack.com'))
		.map((c) => c.body)
		.join('\n');
}

function latencyQueries(calls: Call[]): Call[] {
	return calls.filter((c) => c.url.includes('analytics_engine/sql') && c.body.includes('workload_class'));
}

async function runAt(when: number, latencyRows: Array<Record<string, unknown>>): Promise<Call[]> {
	vi.setSystemTime(when);
	const calls = mockAnalytics(latencyRows);
	const { handleScheduled } = await import('../src/scheduled');
	await handleScheduled(ENV);
	return calls;
}

beforeEach(() => {
	vi.useFakeTimers();
});

afterEach(() => {
	vi.useRealTimers();
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('p95 latency lane — volume floor', () => {
	it('abstains instead of paging when the window holds too few calls to support a percentile', async () => {
		// The reported incident's shape, taken to its root: a tiny sample where the
		// "p95" is really just the slowest single call.
		const calls = await runAt(AT_WINDOW_BOUNDARY, [{ workload_class: 'interactive', total_calls: 3, p95_ms: 99_000, max_ms: 99_000 }]);

		expect(alertsSent(calls)).not.toContain('P95 latency');
	});

	it('pages once the sample is large enough for the same latency', async () => {
		// NON-VACUOUSNESS: identical p95, only the call count differs. If this did not
		// alert, the test above would prove nothing — it could be passing because the
		// lane is dead rather than because it abstained.
		const calls = await runAt(AT_WINDOW_BOUNDARY, [{ workload_class: 'interactive', total_calls: 400, p95_ms: 99_000, max_ms: 99_000 }]);

		expect(alertsSent(calls)).toContain('P95 latency');
	});

	it('puts the sample size in the alert TITLE, not only the metrics block', async () => {
		// "p95 22612ms over 35 calls" and "p95 22612ms" are read very differently, and
		// the reader sees the title first. The original alert omitted it from the title.
		const calls = await runAt(AT_WINDOW_BOUNDARY, [{ workload_class: 'interactive', total_calls: 400, p95_ms: 99_000, max_ms: 120_000 }]);

		// The payload is prose: the title is the first line, after the severity label.
		const title = (JSON.parse(alertsSent(calls)).text as string).split('\n')[0];
		expect(title).toContain('P95 latency');
		expect(title).toContain('400');
		expect(title).toContain('interactive');
		// The metrics block is NOT where the count was missing — the title was.
		expect(title).not.toContain('total_calls:');
	});
});

describe('p95 latency lane — workload class', () => {
	it('does not page for an enumeration tool running inside its own documented budget', async () => {
		// discover_brand_domains measured p95 25,715ms over 7 days. Under one shared
		// 10s ceiling that is 2.5x the threshold — it could not run without paging
		// critical, forever, for behaving exactly as designed.
		const calls = await runAt(AT_WINDOW_BOUNDARY, [{ workload_class: 'batch', total_calls: 55, p95_ms: 25_715, max_ms: 25_715 }]);

		expect(alertsSent(calls)).not.toContain('P95 latency');
	});

	it('applies a STRICTER ceiling to interactive traffic at the same latency', async () => {
		// Same number, opposite verdict: the class is what decides, so the two ceilings
		// are demonstrably distinct rather than one value with a cosmetic label.
		const calls = await runAt(AT_WINDOW_BOUNDARY, [{ workload_class: 'interactive', total_calls: 55, p95_ms: 25_715, max_ms: 25_715 }]);

		const sent = alertsSent(calls);
		expect(sent).toContain('P95 latency');
		expect(sent).toContain('interactive');
	});

	it('still pages for a batch class that blows past even the batch ceiling', async () => {
		// Widening the ceiling must not amount to switching the alert off for that class.
		const calls = await runAt(AT_WINDOW_BOUNDARY, [{ workload_class: 'batch', total_calls: 55, p95_ms: 300_000, max_ms: 300_000 }]);

		expect(alertsSent(calls)).toContain('P95 latency');
	});

	it('classifies an unrecognised class as interactive (fail-strict, not fail-open)', async () => {
		// A new or malformed class must inherit the TIGHTER ceiling. Defaulting to
		// `batch` would let an unmapped workload quietly buy itself a 30s allowance.
		const calls = await runAt(AT_WINDOW_BOUNDARY, [{ workload_class: 'something_new', total_calls: 55, p95_ms: 25_715, max_ms: 25_715 }]);

		expect(alertsSent(calls)).toContain('P95 latency');
	});

	it('derives the SQL class predicate from LONG_RUNNING_TOOLS rather than a second hardcoded list', async () => {
		const calls = await runAt(AT_WINDOW_BOUNDARY, []);
		const sql = latencyQueries(calls)[0]?.body ?? '';

		expect(sql).not.toBe('');
		for (const tool of LONG_RUNNING_TOOLS) {
			expect(sql).toContain(`'${tool}'`);
		}
		// scan_domain carries the bulk of interactive volume: if it ever lands in the
		// batch class the interactive percentile becomes meaningless.
		expect(isLongRunningTool('scan_domain')).toBe(false);
		expect(sql).not.toContain(`'scan_domain'`);
	});
});

describe('p95 latency lane — one evaluation per window', () => {
	it('does not issue the query at all mid-window', async () => {
		// A 6h lookback read every 15m would re-report the same slow window up to 24
		// times, turning one true finding into 24 pages — the same failure this issue
		// is about with the sign flipped.
		const calls = await runAt(MID_WINDOW, [{ workload_class: 'interactive', total_calls: 400, p95_ms: 99_000, max_ms: 99_000 }]);

		expect(latencyQueries(calls)).toHaveLength(0);
		expect(alertsSent(calls)).not.toContain('P95 latency');
	});

	it('issues it exactly once on the window boundary', async () => {
		const calls = await runAt(AT_WINDOW_BOUNDARY, [{ workload_class: 'interactive', total_calls: 400, p95_ms: 99_000, max_ms: 99_000 }]);

		expect(latencyQueries(calls)).toHaveLength(1);
	});
});

describe('p95 latency lane — the 15m anomalies lane no longer alerts on latency', () => {
	it('does not page on p95 from the short error-rate window', async () => {
		// The exact reported payload: p95 22,612ms over 35 calls, error rate healthy.
		// The anomalies query still SELECTs p95_ms (it is useful context inside an
		// error-rate page) but must no longer be a paging condition of its own.
		const calls = await runAt(MID_WINDOW, []);

		const sent = alertsSent(calls);
		expect(sent).not.toContain('P95 latency');
		expect(sent).not.toContain('22612');
	});

	it('keeps p95 as CONTEXT inside an error-rate page', async () => {
		// Removing the alert must not remove the datum: when the error-rate lane does
		// fire, p95 is still on the payload for whoever is reading it.
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			const body = (init?.body as string) ?? '';
			if (!url.includes('analytics_engine/sql')) return new Response('ok');
			if (body.includes('workload_class')) return Response.json({ data: [] });
			if (body.includes("index1 = 'tool_call'")) {
				return Response.json({ data: [{ total_calls: 100, error_count: 90, error_pct: 90, p95_ms: 22_612 }] });
			}
			return Response.json({ data: [] });
		}) as typeof fetch;

		const sentBodies: string[] = [];
		const realFetch = globalThis.fetch;
		globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
			if (url.includes('hooks.slack.com')) sentBodies.push((init?.body as string) ?? '');
			return realFetch(input, init);
		}) as typeof fetch;

		vi.setSystemTime(MID_WINDOW);
		const { handleScheduled } = await import('../src/scheduled');
		await handleScheduled(ENV);

		const sent = sentBodies.join('\n');
		expect(sent).toContain('Error rate');
		expect(sent).toContain('22612');
		// …but the latency alert itself is still gone.
		expect(sent).not.toContain('P95 latency');
	});
});

describe('p95 latency lane — SQL construction', () => {
	it('drops any tool name that is not a plain lowercase identifier', async () => {
		// The class predicate interpolates tool names into SQL. Every current member is
		// a plain identifier, so this guards the CONSTRUCTION, not a live hole.
		const { queryLatencyByWorkloadClass } = await import('../src/lib/analytics-queries');
		const sql = queryLatencyByWorkloadClass('360', undefined, ['batch_scan', "evil'; DROP TABLE x; --", 'Bad-Name']);

		expect(sql).toContain(`'batch_scan'`);
		expect(sql).not.toContain('DROP TABLE');
		expect(sql).not.toContain('Bad-Name');
	});

	it('degrades to an all-interactive classification rather than emitting an empty IN ()', async () => {
		const { queryLatencyByWorkloadClass } = await import('../src/lib/analytics-queries');
		const sql = queryLatencyByWorkloadClass('360', []);

		expect(sql).not.toContain('IN ()');
		expect(sql).toContain('workload_class');
	});
});
