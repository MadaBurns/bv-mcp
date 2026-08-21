// SPDX-License-Identifier: BUSL-1.1

/**
 * THE ERROR-RATE ALERT PAGED `critical` ON A SINGLE PROBE CALL.
 *
 * Live examples off the operator alert board, all severity `critical`:
 *
 *   Error rate 100.0%  error_count: 1  total_calls: 1   p95_ms: 0
 *   Error rate  50.0%  error_count: 1  total_calls: 2   p95_ms: 7174
 *   Error rate  45.5%  error_count: 5  total_calls: 11  p95_ms: 3570
 *
 * Nothing was wrong. Two defects combined, and both had already been diagnosed and
 * fixed ELSEWHERE in the same codebase without the alerting lane inheriting either:
 *
 *  1. NO DENOMINATOR FLOOR. The only guard was `total_calls > 0`, so a percentage was
 *     computed over as little as one call. At the measured traffic (~11 tool calls per
 *     hour) a 15m window holds ~3 calls, so a single error is 33% and the only call in
 *     a window is 100% — both far past `errorThreshold * 2`, hence `critical`. The
 *     latency lane learned this in #729 (`minLatencySamples`), and `queryErrorRate`
 *     already carried `HAVING total > 10`; this lane had no floor at all.
 *  2. CONFLATED ERROR CLASSES. `error_pct` counts pre-dispatch arg-validation
 *     rejections (blob4='none' — no tool ran) as service errors. Those are fuzzers and
 *     probes hitting a public endpoint. `queryErrorRate` split them out precisely
 *     because that floor of noise inflated low-volume tools (check_mx read ~16% but was
 *     ~0% real failures) — yet the query that PAGES kept reading the conflated number.
 *     `p95_ms: 0` on the two 100% alerts is the fingerprint: no tool work ran at all.
 *
 * These tests pin the fix as INVARIANTS — abstain below the floor, judge only errors
 * from tools that actually executed, keep the denominator in the title — so retuning a
 * threshold does not require rewriting the guarantees.
 */

import { describe, it, expect, vi, afterEach } from 'vitest';

const WEBHOOK = 'https://hooks.slack.com/test';
const ENV = { CF_ACCOUNT_ID: 'a', CF_ANALYTICS_TOKEN: 't', ALERT_WEBHOOK_URL: WEBHOOK };

interface Call {
	url: string;
	body: string;
}

/**
 * Mock AE. `anomalyRow` is what the 15m anomalies query returns; every OTHER query
 * returns data that does not trip its own threshold, so any alert observed came from
 * the error-rate lane and nothing else.
 */
function mockAnalytics(anomalyRow: Record<string, unknown> | null): Call[] {
	const calls: Call[] = [];
	globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : (input as Request).url;
		const body = (init?.body as string) ?? '';
		calls.push({ url, body });

		if (!url.includes('analytics_engine/sql')) return new Response('ok');
		// The anomalies lane is the only tool_call query without a GROUP BY.
		if (body.includes("index1 = 'tool_call'") && !body.includes('workload_class') && !body.includes('blob1 AS tool_name')) {
			return Response.json({ data: anomalyRow ? [anomalyRow] : [] });
		}
		return Response.json({ data: [] });
	}) as typeof fetch;
	return calls;
}

async function run(anomalyRow: Record<string, unknown> | null): Promise<Call[]> {
	const calls = mockAnalytics(anomalyRow);
	const { handleScheduled } = await import('../src/scheduled');
	await handleScheduled(ENV);
	return calls;
}

function alertsSent(calls: Call[]): string {
	return calls
		.filter((c) => c.url.includes('hooks.slack.com'))
		.map((c) => c.body)
		.join('\n');
}

afterEach(() => {
	vi.restoreAllMocks();
	vi.resetModules();
});

describe('error-rate lane — denominator floor', () => {
	it('does not page on a single errored call in the window (the reported incident)', async () => {
		// Verbatim shape of the worst alert on the board: one call, one error, 100%.
		const calls = await run({ total_calls: 1, error_count: 1, real_error_count: 1, error_pct: 100, real_error_pct: 100, p95_ms: 0 });

		expect(alertsSent(calls)).not.toContain('Error rate');
	});

	it('does not page at 45.5% over 11 calls', async () => {
		// The subtlest of the reported alerts — a real-looking rate that is still a
		// sample too small to distinguish from noise.
		const calls = await run({ total_calls: 11, error_count: 5, real_error_count: 5, error_pct: 45.5, real_error_pct: 45.5, p95_ms: 3570 });

		expect(alertsSent(calls)).not.toContain('Error rate');
	});

	it('pages once the sample is large enough at the SAME error rate', async () => {
		// NON-VACUOUSNESS: identical rate, only the call count differs. Without this,
		// the tests above could be passing because the lane is dead rather than because
		// it abstained.
		const calls = await run({
			total_calls: 200,
			error_count: 91,
			real_error_count: 91,
			error_pct: 45.5,
			real_error_pct: 45.5,
			p95_ms: 3570,
		});

		expect(alertsSent(calls)).toContain('Error rate');
	});

	it('sits the floor exactly where one lone error cannot trip the default threshold', async () => {
		// The floor is DERIVED from the 5% threshold it guards, not picked round:
		// 1/20 = 5.0%, which is not > 5%. Pinning the relationship rather than the
		// number keeps the derivation honest if either value is retuned.
		const oneErrorAtFloor = await run({
			total_calls: 20,
			error_count: 1,
			real_error_count: 1,
			error_pct: 5,
			real_error_pct: 5,
			p95_ms: 100,
		});
		expect(alertsSent(oneErrorAtFloor)).not.toContain('Error rate');

		// Two errors over the same window IS above threshold and is believed.
		const twoErrorsAtFloor = await run({
			total_calls: 20,
			error_count: 2,
			real_error_count: 2,
			error_pct: 10,
			real_error_pct: 10,
			p95_ms: 100,
		});
		expect(alertsSent(twoErrorsAtFloor)).toContain('Error rate');
	});
});

describe('error-rate lane — real vs input errors', () => {
	it('does not page when every error was a pre-dispatch arg rejection', async () => {
		// A fuzzer sending bad/absent domains to the public endpoint. Volume is well
		// over the floor, so ONLY the class split can be what suppresses this.
		const calls = await run({
			total_calls: 200,
			error_count: 120,
			input_error_count: 120,
			real_error_count: 0,
			error_pct: 60,
			real_error_pct: 0,
			p95_ms: 0,
		});

		expect(alertsSent(calls)).not.toContain('Error rate');
	});

	it('pages when tools that actually executed are failing', async () => {
		// Same volume, same raw error_count — the errors are just real this time.
		const calls = await run({
			total_calls: 200,
			error_count: 120,
			input_error_count: 0,
			real_error_count: 120,
			error_pct: 60,
			real_error_pct: 60,
			p95_ms: 4000,
		});

		expect(alertsSent(calls)).toContain('Error rate');
	});

	it('judges the real rate even when fuzz noise pushes the conflated rate over the line', async () => {
		// The mixed case the split exists for: conflated 60% would page `critical`,
		// real 2% is healthy. Judging the wrong column here is the whole defect.
		const calls = await run({
			total_calls: 200,
			error_count: 120,
			input_error_count: 116,
			real_error_count: 4,
			error_pct: 60,
			real_error_pct: 2,
			p95_ms: 800,
		});

		expect(alertsSent(calls)).not.toContain('Error rate');
	});

	it('falls back to the conflated rate when a reader returns no real_error_pct', async () => {
		// FAIL-LOUD, not fail-silent. An older/pinned query shape omits the split; the
		// lane must over-report rather than silently read 0% and hide an outage.
		const calls = await run({ total_calls: 200, error_count: 120, error_pct: 60, p95_ms: 4000 });

		expect(alertsSent(calls)).toContain('Error rate');
	});
});

describe('error-rate lane — alert legibility', () => {
	it('puts the error count and sample size in the alert TITLE, not only the metrics block', async () => {
		// "45.5%" and "5 of 11 calls" are read very differently, and the reader sees the
		// title first. Every alert on the reported board omitted the denominator from
		// the title — the same omission the latency lane fixed in #729.
		const calls = await run({
			total_calls: 200,
			error_count: 91,
			input_error_count: 0,
			real_error_count: 91,
			error_pct: 45.5,
			real_error_pct: 45.5,
			p95_ms: 3570,
		});

		const title = (JSON.parse(alertsSent(calls)).text as string).split('\n')[0];
		expect(title).toContain('Error rate');
		expect(title).toContain('91');
		expect(title).toContain('200');
		expect(title).not.toContain('total_calls:');
	});

	it('reports the suppressed input-error count so the reader can see what was excluded', async () => {
		// The alert must not silently drop the noise it declined to judge — an operator
		// comparing against a raw AE query needs the two numbers to reconcile.
		const calls = await run({
			total_calls: 200,
			error_count: 100,
			input_error_count: 40,
			real_error_count: 60,
			error_pct: 50,
			real_error_pct: 30,
			p95_ms: 4000,
		});

		const sent = alertsSent(calls);
		expect(sent).toContain('input_error_count');
		expect(sent).toContain('40');
		expect(sent).toContain('real_error_count');
	});
});

describe('error-rate lane — query shape', () => {
	it('selects the real/input error split the lane depends on', async () => {
		// The lane reads `real_error_pct`; if the query stops emitting it, the fallback
		// silently reverts to the conflated behaviour this fix removed. Pin the seam.
		const calls = await run(null);
		const sql = calls.find((c) => c.url.includes('analytics_engine/sql') && c.body.includes('real_error_pct'))?.body ?? '';

		expect(sql).not.toBe('');
		expect(sql).toContain("blob3 = 'error' AND blob4 != 'none'");
		expect(sql).toContain("blob3 = 'error' AND blob4 = 'none'");
		expect(sql).toContain('real_error_count');
		expect(sql).toContain('input_error_count');
		// Divide-by-zero guard must use if(), not GREATEST() — AE's SQL API 422s on the
		// latter, which is what had every alert dead once before.
		expect(sql).toContain('if(SUM(_sample_interval) > 0, SUM(_sample_interval), 1)');
	});
});
