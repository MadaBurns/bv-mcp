// SPDX-License-Identifier: BUSL-1.1

/**
 * R8 regression tests for `checkIpScopedQuotaBatch` — the per-IP batched quota
 * evaluation and its BYPASS DISCIPLINE (LINUS MUST-FIX #1 / ADAM #1 + #6).
 *
 * The load-bearing invariant: a 2xx-but-unparseable `evaluate` response means the
 * DO ALREADY committed its increments, so we must NOT re-run the serial
 * `checkRateLimit` / `checkToolDailyRateLimit` increments (which would
 * double/triple-count and wrongly 429 a paying-quota caller). We assert this two
 * ways: (a) the coordinator namespace is fetched EXACTLY ONCE on a malformed
 * response (no serial follow-up round trips), and (b) a degradation event fires.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { checkIpScopedQuotaBatch, resetQuotaCoordinatorBreaker, type QuotaDegradationReason } from '../src/lib/rate-limiter';

const SHARDED = { enabled: true, salt: '' } as const;

afterEach(() => {
	resetQuotaCoordinatorBreaker();
	vi.restoreAllMocks();
});

/**
 * A fake QUOTA_COORDINATOR namespace whose evaluate response body is controllable.
 * Counts every `getByName(...).fetch(...)` so we can prove how many round trips ran.
 */
function fakeNamespace(bodyFactory: () => unknown, status = 200): { ns: DurableObjectNamespace; fetchCount: () => number } {
	let count = 0;
	const ns = {
		getByName: () => ({
			fetch: async () => {
				count += 1;
				return new Response(JSON.stringify(bodyFactory()), { status, headers: { 'content-type': 'application/json' } });
			},
		}),
	} as unknown as DurableObjectNamespace;
	return { ns, fetchCount: () => count };
}

describe('checkIpScopedQuotaBatch — happy path', () => {
	it('returns both verdicts from a single batched evaluate', async () => {
		const { ns, fetchCount } = fakeNamespace(() => ({
			results: [
				{ index: 0, kind: 'scoped-rate', result: { allowed: true, minuteRemaining: 49, hourRemaining: 299 } },
				{ index: 1, kind: 'tool-daily', result: { allowed: true, remaining: 199, limit: 200 } },
			],
		}));
		const out = await checkIpScopedQuotaBatch('203.0.113.5', 'check_spf', 200, { quotaCoordinator: ns, routing: SHARDED });
		expect(out.rate.allowed).toBe(true);
		expect(out.toolDaily).toMatchObject({ allowed: true, remaining: 199, limit: 200 });
		// ONE round trip — the whole point of batching.
		expect(fetchCount()).toBe(1);
	});

	it('short-circuit denial: scoped-rate denied surfaces no toolDaily verdict', async () => {
		const { ns } = fakeNamespace(() => ({
			results: [{ index: 0, kind: 'scoped-rate', result: { allowed: false, minuteRemaining: 0, hourRemaining: 50, retryAfterMs: 15_000 } }],
		}));
		const out = await checkIpScopedQuotaBatch('203.0.113.6', 'check_spf', 200, { quotaCoordinator: ns, routing: SHARDED });
		expect(out.rate.allowed).toBe(false);
		expect(out.toolDaily).toBeUndefined();
	});
});

describe('malformed-response bypass (LINUS MUST-FIX #1 / ADAM #1)', () => {
	it('does NOT re-run serial checks on a malformed array results ({results:{}})', async () => {
		// `results` is an OBJECT not an array → MalformedEvaluateResponse from the helper.
		const { ns, fetchCount } = fakeNamespace(() => ({ results: {} }));
		const reasons: QuotaDegradationReason[] = [];
		const out = await checkIpScopedQuotaBatch('203.0.113.7', 'check_spf', 200, {
			quotaCoordinator: ns,
			routing: SHARDED,
			onDegradation: (r) => reasons.push(r),
		});
		// Exactly ONE round trip (the evaluate). No serial checkRateLimit /
		// checkToolDailyRateLimit follow-up → no second/third increment.
		expect(fetchCount()).toBe(1);
		// Single non-incrementing fail-soft allow.
		expect(out.rate.allowed).toBe(true);
		expect(out.toolDaily).toMatchObject({ allowed: true, limit: 200 });
		// Observable degradation signal.
		expect(reasons).toEqual(['malformed_response']);
	});

	it('does NOT re-run serial checks when results is a non-array truthy value (no scoped-rate entry)', async () => {
		// A results array missing the scoped-rate entry — parseEvaluateResponse rejects an
		// unknown kind, so this is the "tool-daily only, no scoped-rate" skew scenario.
		const { ns, fetchCount } = fakeNamespace(() => ({
			results: [{ index: 0, kind: 'tool-daily', result: { allowed: true, remaining: 4, limit: 5 } }],
		}));
		const reasons: QuotaDegradationReason[] = [];
		const out = await checkIpScopedQuotaBatch('203.0.113.8', 'check_spf', 200, {
			quotaCoordinator: ns,
			routing: SHARDED,
			onDegradation: (r) => reasons.push(r),
		});
		// One round trip; no serial re-increment even though scoped-rate is missing.
		expect(fetchCount()).toBe(1);
		expect(out.rate.allowed).toBe(true);
		expect(reasons).toEqual(['malformed_response']);
	});
});

describe('genuine DO-did-not-run fallthrough (degrades + falls to serial)', () => {
	it('emits a degradation event and serves a verdict when no coordinator is provided', async () => {
		const reasons: QuotaDegradationReason[] = [];
		// No quotaCoordinator → goes straight to the serial path (in-memory fallback).
		// No degradation emitted here (we never attempted the coordinator).
		const out = await checkIpScopedQuotaBatch('203.0.113.9', 'check_spf', 200, {
			routing: SHARDED,
			onDegradation: (r) => reasons.push(r),
		});
		expect(out.rate.allowed).toBe(true);
		expect(reasons).toEqual([]);
	});

	it('falls through to serial (and degrades) when the evaluate call throws a network error', async () => {
		const throwingNs = {
			getByName: () => ({
				fetch: async () => {
					throw new Error('network down');
				},
			}),
		} as unknown as DurableObjectNamespace;
		const reasons: QuotaDegradationReason[] = [];
		const out = await checkIpScopedQuotaBatch('203.0.113.10', 'check_spf', 200, {
			quotaCoordinator: throwingNs,
			routing: SHARDED,
			onDegradation: (r) => reasons.push(r),
		});
		// Serial in-memory fallback still produces a verdict.
		expect(out.rate.allowed).toBe(true);
		// Degraded with evaluate_error (the DO did not commit, so re-running is safe).
		expect(reasons).toContain('evaluate_error');
	});
});

describe('flag-OFF default == today (no routing arg)', () => {
	it('with SINGLETON routing, the batch still routes its evaluate to the singleton', async () => {
		const names: string[] = [];
		const ns = {
			getByName: (name: string) => {
				names.push(name);
				return {
					fetch: async () =>
						new Response(
							JSON.stringify({
								results: [
									{ index: 0, kind: 'scoped-rate', result: { allowed: true, minuteRemaining: 49, hourRemaining: 299 } },
									{ index: 1, kind: 'tool-daily', result: { allowed: true, remaining: 4, limit: 5 } },
								],
							}),
							{ status: 200, headers: { 'content-type': 'application/json' } },
						),
				};
			},
		} as unknown as DurableObjectNamespace;
		// Omit `routing` entirely → defaults to SINGLETON_ROUTING.
		await checkIpScopedQuotaBatch('203.0.113.11', 'check_spf', 5, { quotaCoordinator: ns });
		expect(names).toEqual(['global-quota-coordinator']);
	});
});
