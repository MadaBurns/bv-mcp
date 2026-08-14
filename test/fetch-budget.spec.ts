// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit spec for the per-check fetch budget (issue #641).
 *
 * `withFetchBudget` exists because `check_ssl` issues three STRICTLY SEQUENTIAL
 * fetches with fixed timeouts (robots.txt 3s → `https://` 4s → `http://` 4s = 11s)
 * inside `scan_domain`'s 8s per-check budget, so `safeCheck` killed the check and
 * the whole `ssl` category was lost. Everything asserted here is about that:
 *
 *  - it must be a NO-OP without a budget (direct `check_ssl` keeps current behaviour),
 *  - every call must share ONE absolute deadline (later fetches get less time),
 *  - it must COMPOSE with the package's own `AbortSignal.timeout`, never replace it,
 *  - once the budget is gone it must reject WITHOUT spending a Workers subrequest,
 *  - and its rejection message is coupled to a downstream substring test in
 *    `@blackveil/dns-checks` — see the `message coupling` block, which fails loudly
 *    with an explanation if the wording is ever changed.
 *
 * Timing notes: workerd's `Date.now()` only advances across I/O, so every elapsed
 * measurement here is taken around a real `setTimeout`/abort event (measured
 * accurate to ~4ms in this pool). Tolerances are wide enough for CI jitter but
 * far narrower than the deltas a regression would produce.
 */

import { describe, it, expect } from 'vitest';

/** Mirrors the module-private constant in `src/lib/fetch-budget.ts`. */
const MIN_USEFUL_FETCH_MS = 200;

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Resolves with `Date.now()` at the instant `signal` aborts (immediately if already aborted). */
function abortedAt(signal: AbortSignal): Promise<number> {
	if (signal.aborted) return Promise.resolve(Date.now());
	return new Promise((resolve) => signal.addEventListener('abort', () => resolve(Date.now())));
}

/** A fetch that never settles on its own — only the composed signal can end it. */
function makeHangingFetch() {
	const calls: Array<{ url: string; init?: RequestInit }> = [];
	const fetchFn = (url: string, init?: RequestInit): Promise<Response> => {
		calls.push({ url, init });
		return new Promise((_resolve, reject) => {
			const signal = init?.signal;
			if (!signal) return; // no signal → hangs forever; a test relying on abort would time out, which is the point
			if (signal.aborted) return reject(new Error('The operation was aborted'));
			signal.addEventListener('abort', () => reject(new Error('The operation was aborted')));
		});
	};
	return { fetchFn, calls };
}

/** A fetch that answers immediately and records what it was handed. */
function makeInstantFetch() {
	const calls: Array<{ url: string; init?: RequestInit }> = [];
	const fetchFn = async (url: string, init?: RequestInit): Promise<Response> => {
		calls.push({ url, init });
		return new Response(null, { status: 200 });
	};
	return { fetchFn, calls };
}

describe('withFetchBudget — pass-through when no budget is supplied', () => {
	it('returns the SAME function reference for budgetMs === undefined (identity, not equivalence)', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { fetchFn } = makeInstantFetch();

		const result = withFetchBudget(fetchFn, undefined);

		// Identity is the contract, not merely "behaves the same": a direct `check_ssl`
		// call (and every BSL self-host path) must run byte-for-byte the pre-#641 code
		// path, with no wrapper frame, no clock, and no composed signal in between.
		expect(result).toBe(fetchFn);
	});

	it('leaves init untouched when unwrapped — the exact object and signal reach the underlying fetch', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { fetchFn, calls } = makeInstantFetch();
		const perFetchSignal = AbortSignal.timeout(4_000);
		const init: RequestInit = { method: 'HEAD', redirect: 'manual', signal: perFetchSignal };

		await withFetchBudget(fetchFn, undefined)('https://example.test', init);

		expect(calls).toHaveLength(1);
		expect(calls[0].init).toBe(init);
		expect(calls[0].init?.signal).toBe(perFetchSignal);
	});
});

describe('withFetchBudget — the budget shrinks across successive calls', () => {
	it('gives every call ONE shared absolute deadline, so a later call gets strictly less time', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { fetchFn, calls } = makeInstantFetch();

		const budgetMs = 1_200;
		const createdAt = Date.now();
		const wrapped = withFetchBudget(fetchFn, budgetMs);

		// Leg 1 — issued immediately, so it is handed roughly the whole budget.
		const firstCallAt = Date.now();
		await wrapped('https://first.test');

		// Real elapsed time between the legs (workerd's clock only moves across I/O).
		await delay(500);

		// Leg 2 — must be bounded by what leg 1 and the gap left behind, NOT by a fresh budget.
		const secondCallAt = Date.now();
		await wrapped('https://second.test');

		expect(calls).toHaveLength(2);
		const firstSignal = calls[0].init?.signal;
		const secondSignal = calls[1].init?.signal;
		expect(firstSignal).toBeInstanceOf(AbortSignal);
		expect(secondSignal).toBeInstanceOf(AbortSignal);

		// Observe the signals themselves rather than any internal remaining-ms arithmetic.
		const [firstAbortAt, secondAbortAt] = await Promise.all([abortedAt(firstSignal!), abortedAt(secondSignal!)]);

		const firstWindow = firstAbortAt - firstCallAt;
		const secondWindow = secondAbortAt - secondCallAt;

		// Both legs expire at the same wall-clock instant — the budget's deadline.
		expect(Math.abs(firstAbortAt - secondAbortAt)).toBeLessThan(150);
		expect(Math.abs(firstAbortAt - (createdAt + budgetMs))).toBeLessThan(250);
		expect(Math.abs(secondAbortAt - (createdAt + budgetMs))).toBeLessThan(250);

		// Which is exactly what "shrinking" means: leg 2's own window is ~500ms shorter.
		expect(secondWindow).toBeLessThan(firstWindow - 300);
		// And a per-call budget (the bug this prevents) would have given leg 2 the full 1200ms.
		expect(secondWindow).toBeLessThan(budgetMs - 300);
	});
});

describe('withFetchBudget — composes with the per-fetch signal, never substitutes it', () => {
	it('budget SHORTER than the per-fetch timeout: the budget aborts the fetch', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { fetchFn } = makeHangingFetch();

		// The package's own `AbortSignal.timeout(4000)` would let this run for 4s.
		const perFetchSignal = AbortSignal.timeout(4_000);
		const wrapped = withFetchBudget(fetchFn, 400);

		const startedAt = Date.now();
		await expect(wrapped('https://example.test', { signal: perFetchSignal })).rejects.toThrow(/abort/i);
		const elapsed = Date.now() - startedAt;

		expect(elapsed).toBeGreaterThan(150);
		expect(elapsed).toBeLessThan(1_500);
	});

	it('per-fetch timeout SHORTER than the budget: the pre-existing signal still aborts the fetch', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { fetchFn } = makeHangingFetch();

		// If the wrapper SUBSTITUTED its own signal instead of composing, this fetch would
		// live for the full 5s budget and the check's own timeout would silently stop working.
		const perFetchSignal = AbortSignal.timeout(300);
		const wrapped = withFetchBudget(fetchFn, 5_000);

		const startedAt = Date.now();
		await expect(wrapped('https://example.test', { signal: perFetchSignal })).rejects.toThrow(/abort/i);
		const elapsed = Date.now() - startedAt;

		expect(elapsed).toBeLessThan(1_500);
	});

	it('preserves the rest of init and hands down a composed (not the original, not a bare) signal', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { fetchFn, calls } = makeInstantFetch();

		const perFetchSignal = AbortSignal.timeout(4_000);
		await withFetchBudget(fetchFn, 3_000)('https://example.test', { method: 'HEAD', redirect: 'manual', signal: perFetchSignal });

		expect(calls).toHaveLength(1);
		expect(calls[0].init?.method).toBe('HEAD');
		expect(calls[0].init?.redirect).toBe('manual');
		// Composed: a NEW signal that is neither the caller's nor a naked budget timer.
		expect(calls[0].init?.signal).toBeInstanceOf(AbortSignal);
		expect(calls[0].init?.signal).not.toBe(perFetchSignal);
	});

	it('attaches a budget signal even when init carries none', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { fetchFn, calls } = makeInstantFetch();

		await withFetchBudget(fetchFn, 3_000)('https://example.test');

		expect(calls[0].init?.signal).toBeInstanceOf(AbortSignal);
	});
});

describe('withFetchBudget — exhaustion rejects WITHOUT issuing a fetch', () => {
	it('rejects immediately and never calls the underlying fetch when the budget is already too small', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { fetchFn, calls } = makeInstantFetch();

		await expect(withFetchBudget(fetchFn, 100)('https://example.test')).rejects.toThrow(/budget exhausted/i);

		// THE POINT: a fetch that would abort before a response head arrives is not worth
		// one of the 50 (Free-plan) Workers subrequests. Issuing it and letting it abort
		// would burn the subrequest for nothing; the guard preserves it for another check.
		expect(calls).toHaveLength(0);
	});

	it('treats exactly MIN_USEFUL_FETCH_MS as too small (the guard is `<=`, not `<`)', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { fetchFn, calls } = makeInstantFetch();

		await expect(withFetchBudget(fetchFn, MIN_USEFUL_FETCH_MS)('https://example.test')).rejects.toThrow(/budget exhausted/i);
		expect(calls).toHaveLength(0);

		// Comfortably above the floor → the fetch is issued. (No `await` between creation
		// and call, so workerd's clock has not moved and the whole budget is still there.)
		await withFetchBudget(fetchFn, MIN_USEFUL_FETCH_MS * 2)('https://example.test');
		expect(calls).toHaveLength(1);
	});

	it('rejects a later call once earlier calls have spent the budget', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { fetchFn, calls } = makeHangingFetch();

		const wrapped = withFetchBudget(fetchFn, 700);

		// Leg 1 consumes the entire budget waiting for a host that never answers.
		await expect(wrapped('https://slow.test')).rejects.toThrow(/abort/i);
		expect(calls).toHaveLength(1);

		// Leg 2 — `check_ssl`'s final `http://` redirect probe — is dropped, not attempted.
		await expect(wrapped('http://slow.test')).rejects.toThrow(/budget exhausted/i);
		expect(calls).toHaveLength(1);
	});
});

describe('withFetchBudget — rejection message is COUPLED to checkHttps in @blackveil/dns-checks', () => {
	/**
	 * `checkHttps` (packages/dns-checks/src/checks/check-ssl.ts) classifies a thrown
	 * fetch by SUBSTRING, not by error type:
	 *
	 *   err.message.includes('timeout') || err.message.includes('abort')
	 *     ? 'Connection timeout'  → checkStatus: 'timeout'
	 *     : 'Connection failed'   → checkStatus: 'error'
	 *
	 * So the wording of `BUDGET_EXHAUSTED_MESSAGE` decides how an exhausted budget is
	 * reported to customers. These tests exist so that a "harmless" rewording fails
	 * HERE, with the reason, instead of silently re-labelling every budget-dropped
	 * SSL leg as a connection error in production reports.
	 */
	const classifiesAsTimeout = (message: string) => message.includes('timeout') || message.includes('abort');

	it('contains the literal substring the downstream classifier tests for', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { fetchFn } = makeInstantFetch();

		const rejection: unknown = await withFetchBudget(
			fetchFn,
			1,
		)('https://example.test').then(
			() => undefined,
			(e: unknown) => e,
		);

		expect(rejection).toBeInstanceOf(Error);
		const message = (rejection as Error).message;
		// Literal, deliberately not a regex-with-alternatives: this is the exact token
		// `checkHttps` greps for. If you reword the message, update `checkHttps` too.
		expect(message).toContain('timeout');
		expect(classifiesAsTimeout(message)).toBe(true);
	});

	it('END-TO-END: checkSSL reports an exhausted budget as checkStatus "timeout" (and spends no subrequest)', async () => {
		const { withFetchBudget } = await import('../src/lib/fetch-budget');
		const { checkSSL } = await import('@blackveil/dns-checks');
		const { fetchFn, calls } = makeInstantFetch();

		// A budget that is already gone — the state after robots.txt + `https://` have run long.
		const budgeted = withFetchBudget(fetchFn, 50);
		const result = await checkSSL('example.test', budgeted);

		// 'timeout' (not 'error') keeps the category EXCLUDED as inconclusive rather than
		// scored as a measured connection failure.
		expect(result.checkStatus).toBe('timeout');
		expect(calls).toHaveLength(0);
	});

	it('COUNTERFACTUAL: a message without "timeout"/"abort" downgrades the same event to checkStatus "error"', async () => {
		const { checkSSL } = await import('@blackveil/dns-checks');

		// This is the wording someone would plausibly "tidy" the message down to.
		const rewordedMessage = 'Fetch budget exhausted before this request';
		expect(classifiesAsTimeout(rewordedMessage)).toBe(false);

		const rejectingFetch = () => Promise.reject(new Error(rewordedMessage));
		const result = await checkSSL('example.test', rejectingFetch);

		// THIS is what breaks: the identical event is now reported as a connection error.
		// Keep `timeout` in BUDGET_EXHAUSTED_MESSAGE (or teach `checkHttps` a real error
		// type instead of a substring test).
		expect(result.checkStatus).toBe('error');
	});
});

describe('fetchBudgetFor — margin below the per-check timeout, and the floor', () => {
	it('leaves a 750ms margin under the default per-check timeout', async () => {
		const { fetchBudgetFor } = await import('../src/lib/fetch-budget');
		const { PER_CHECK_TIMEOUT_MS } = await import('../src/lib/config');

		expect(PER_CHECK_TIMEOUT_MS).toBe(8_000);
		expect(fetchBudgetFor(PER_CHECK_TIMEOUT_MS)).toBe(7_250);
		expect(PER_CHECK_TIMEOUT_MS - fetchBudgetFor(PER_CHECK_TIMEOUT_MS)).toBe(750);
	});

	it('stays strictly below the per-check timeout across the whole clamped env range', async () => {
		const { fetchBudgetFor } = await import('../src/lib/fetch-budget');
		const { parsePerCheckTimeout } = await import('../src/lib/config');

		// `parsePerCheckTimeout` clamps PER_CHECK_TIMEOUT_MS to [2000, 15000]
		// (below-min or invalid → the 8000 default; above-max → 15000).
		const reachable = [
			parsePerCheckTimeout(undefined),
			parsePerCheckTimeout('2000'),
			parsePerCheckTimeout('3500'),
			parsePerCheckTimeout('15000'),
			parsePerCheckTimeout('999999'), // clamped down to 15000
			parsePerCheckTimeout('10'), // below min → default 8000
			parsePerCheckTimeout('not-a-number'), // invalid → default 8000
		];

		for (const perCheck of reachable) {
			const budget = fetchBudgetFor(perCheck);
			expect(perCheck).toBeGreaterThanOrEqual(2_000);
			expect(perCheck).toBeLessThanOrEqual(15_000);
			// The margin is what makes the check's OWN abort land before safeCheck's killer.
			// Losing that race is the #641 failure: safeCheck first = every finding discarded.
			expect(budget).toBeLessThan(perCheck);
			expect(perCheck - budget).toBe(750);
		}
	});

	it("the check's own abort really does fire before a safeCheck-style killer at the per-check timeout", async () => {
		const { withFetchBudget, fetchBudgetFor } = await import('../src/lib/fetch-budget');
		const { fetchFn } = makeHangingFetch();

		// Smallest per-check timeout the env clamp permits — the tightest real race.
		const perCheckTimeoutMs = 2_000;
		const killerFired = { value: false };
		const killer = AbortSignal.timeout(perCheckTimeoutMs);
		killer.addEventListener('abort', () => {
			killerFired.value = true;
		});

		const wrapped = withFetchBudget(fetchFn, fetchBudgetFor(perCheckTimeoutMs));
		await expect(wrapped('https://slow.test')).rejects.toThrow(/abort/i);

		// The fetch gave up first, so the check keeps control and returns what it measured
		// instead of being killed with its findings still in hand.
		expect(killerFired.value).toBe(false);
	});

	it('applies the 1000ms floor below a ~1750ms per-check timeout — which the [2000, 15000] clamp makes unreachable', async () => {
		const { fetchBudgetFor } = await import('../src/lib/fetch-budget');

		// The floor only binds under 1750ms:
		expect(fetchBudgetFor(1_750)).toBe(1_000);
		expect(fetchBudgetFor(1_200)).toBe(1_000);
		expect(fetchBudgetFor(1_000)).toBe(1_000);
		// …and 1750 is below the clamp's 2000 minimum, so on every configurable path the
		// `Math.max` is inert and the margin is exactly 750ms (asserted above). Documented
		// rather than deleted: the floor is the backstop if that clamp is ever loosened.
		expect(fetchBudgetFor(2_000)).toBe(1_250);

		// Known sharp edge, recorded so it is a decision and not a surprise: below ~1000ms
		// the floor returns a budget LARGER than the per-check timeout, inverting the
		// "abort before safeCheck" guarantee. Unreachable today (clamp min 2000).
		expect(fetchBudgetFor(900)).toBeGreaterThan(900);
	});
});
