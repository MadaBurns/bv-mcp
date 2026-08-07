// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #638 (secondary defect), package half.
 *
 * FOUR branches of `checkHTTPSecurity` end with no header ever observed — the
 * WAF/appliance block, the HTTP 401, the residual 4xx, and the connection
 * failure/timeout — and all four used to stamp their finding with `missingControl: true`.
 * That flag means "we measured, and the control is ABSENT"; none of them established
 * that. It was being used only as a lever to force the score-0/passed-false shape, which
 * is now expressed directly via `unmeasuredZero` instead.
 *
 * The two properties this pins are in TENSION, so both must hold on every branch:
 *   1. NO `missingControl` — the result must not claim the headers are absent.
 *   2. STILL score 0 / passed false — dropping the flag alone would let the findings
 *      compute to a PASS (measured: `info` → 100/passed, `medium` → 85/passed), i.e.
 *      an unmeasured check reported as a clean one. That is the opposite defect and
 *      is exactly what a naive "just delete the flag" fix would have shipped.
 *
 * `checkStatus` is what makes the scoring engine EXCLUDE the category rather than score
 * the 0. The two OTHER inconclusive branches (5xx server error, robots.txt skip) never
 * carried `missingControl` and are deliberately untouched — pinned below so a future
 * "generalise inconclusive ⇒ zero" refactor can't silently rescore them.
 *
 * Imports the SOURCE module, not the built `@blackveil/dns-checks` — this assertion must
 * be meaningful without a dist rebuild.
 */

import { describe, it, expect } from 'vitest';
import { checkHTTPSecurity } from '../../checks/check-http-security';
import { RobotsDisallowedError } from '../../robots-gate';
import type { FetchFunction } from '../../types';

/** Every request (HEAD and the GET fallback) is refused by an unattributed appliance. */
const blockingFetch: FetchFunction = async () => new Response(null, { status: 403 });

/** The four never-completed-probe branches, each with the fetch that reaches it. */
const UNMEASURED_BRANCHES: Array<[label: string, fetchFn: FetchFunction, status: 'error' | 'timeout']> = [
	['403 WAF/appliance block', blockingFetch, 'error'],
	['405 HEAD-not-allowed', async () => new Response(null, { status: 405 }), 'error'],
	['401 auth-gated endpoint', async () => new Response(null, { status: 401 }), 'error'],
	['404 residual 4xx', async () => new Response(null, { status: 404 }), 'error'],
	[
		'connection failure',
		async () => {
			throw new Error('network unreachable');
		},
		'error',
	],
	[
		'connection timeout',
		async () => {
			throw new Error('The operation timed out');
		},
		'timeout',
	],
];

describe('checkHTTPSecurity — a never-completed probe is inconclusive, not a missing control', () => {
	it.each(UNMEASURED_BRANCHES)('%s: no missingControl, yet still score 0 / passed false', async (_label, fetchFn, status) => {
		const result = await checkHTTPSecurity('example.com', fetchFn);
		// (1) Nothing may claim absence…
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		expect(result.findings.some((f) => f.metadata?.inconclusive === true)).toBe(true);
		// (2) …but an unmeasured check must never read as a PASS.
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		// …and the category is EXCLUDED from scoring, not scored at that 0.
		expect(result.checkStatus).toBe(status);
	});

	it('emits the appliance finding WITHOUT missingControl', async () => {
		const result = await checkHTTPSecurity('example.com', blockingFetch);
		const appliance = result.findings.find((f) => f.title === 'HTTP check blocked by security appliance');
		expect(appliance).toBeDefined();
		expect(appliance!.severity).toBe('info');
		expect(appliance!.metadata?.inconclusive).toBe(true);
		expect(appliance!.metadata?.missingControl).toBeUndefined();
	});

	it('the 5xx server-error branch is NOT zeroed — the origin was reached and answered', async () => {
		const result = await checkHTTPSecurity('example.com', async () => new Response(null, { status: 503 }));
		// Never carried missingControl, so it is not part of this defect and must not be
		// swept up by a "generalise inconclusive ⇒ zero" refactor.
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(85);
		expect(result.passed).toBe(true);
	});

	it('the robots.txt skip is NOT zeroed — a voluntary abstention, not a failed probe', async () => {
		const result = await checkHTTPSecurity('example.com', async () => {
			throw new RobotsDisallowedError('disallowed');
		});
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(100);
		expect(result.passed).toBe(true);
	});

	it('an ordinary healthy response is untouched by the change (no false zeroing)', async () => {
		const fetchFn: FetchFunction = async () =>
			new Response(null, {
				status: 200,
				headers: {
					'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
					'x-frame-options': 'DENY',
					'x-content-type-options': 'nosniff',
					'referrer-policy': 'no-referrer',
					'permissions-policy': 'camera=()',
					'strict-transport-security': 'max-age=31536000; includeSubDomains',
				},
			});
		const result = await checkHTTPSecurity('example.com', fetchFn);
		expect(result.checkStatus).toBeUndefined();
		expect(result.score).toBeGreaterThan(0);
	});
});
