// SPDX-License-Identifier: BUSL-1.1

/**
 * End-to-end wiring proof for the `ssl` per-check fetch budget (issue #641).
 *
 * ## What actually broke
 *
 * `checkSSL` issues three STRICTLY SEQUENTIAL fetches, each with its own fixed
 * timeout: the robots.txt gate (3s) → `https://<domain>` (4s) → the `http://`
 * redirect probe (4s). Worst case 11s, inside `scan_domain`'s 8s
 * `PER_CHECK_TIMEOUT_MS`. When the first legs ran slow the outer `safeCheck`
 * killed the check mid-flight and `scan_domain` lost the ENTIRE `ssl` category —
 * `checkStatus: 'timeout'`, excluded from `categoryScores`, 3–4 points of score
 * movement, a different displayed grade on a re-scan purely from cache state.
 * 12 of 21 cold scans in the #641 investigation.
 *
 * ## Why this file exists alongside test/fetch-budget.spec.ts
 *
 * That spec pins `withFetchBudget`/`fetchBudgetFor` as units. A unit test cannot
 * see the thing that regressed: the budget has to travel
 * `scanDomain` → `CHECK_DISPATCH.ssl`'s optional 7th param → `checkSsl`'s
 * `budgetMs` → the wrapper ORDER inside `check-ssl.ts`. Any link dropping the
 * value re-opens #641 while every unit test stays green — a 7th positional
 * parameter is exactly what a future refactor drops silently.
 *
 * So there are two proofs here, deliberately at different altitudes:
 *
 *  1. **Behavioural** — drive the real `checkSsl` through a real `scanDomain`
 *     against a mocked network whose legs are slow relative to a REDUCED
 *     per-check budget, and assert the `ssl` category comes back MEASURED. This
 *     is the customer-visible regression; asserting an argument was passed is
 *     not a substitute for it.
 *  2. **Argument** — assert the value reaching `checkSsl` is DERIVED from the
 *     per-check timeout (two different timeouts → two different budgets), so a
 *     hardcoded constant that happens to work at the default 8s cannot pass.
 *
 * Both were mutation-verified: stubbing the dispatch site's 7th argument to
 * `undefined` fails both.
 *
 * ## Harness notes (see CLAUDE.md §Testing, bv-mcp-testing skill)
 *
 *  - Times are scaled to a REDUCED `perCheckTimeoutMs` (a `ScanRuntimeOptions`
 *    override, unclamped in `resolveScanTimeoutBudget`) rather than to the real
 *    3s/4s/4s — the pool's per-test timeout is 15s.
 *  - `Date.now()` in workerd only advances across I/O, so every simulated leg is
 *    a real `setTimeout`, never a synchronous burn.
 *  - The hanging leg's mock HONOURS `init.signal`. This is load-bearing, not
 *    politeness: a mock that ignores the signal hangs forever no matter how the
 *    budget is composed, which would make this test fail against CORRECT code
 *    and prove nothing. Real `fetch` aborts; the mock must too.
 *  - Checks only run on cache-miss → `forceRefresh: true` + `IN_MEMORY_CACHE.clear()`.
 *  - The apex NS probe runs through `globalThis.fetch` BEFORE any check is
 *    dispatched; if it doesn't return NOERROR the scan short-circuits and zero
 *    checks fire — hence the DoH branches in the mock.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse, createDohResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { buildCheckResult } from '../src/lib/scoring';
import { fetchBudgetFor } from '../src/lib/fetch-budget';
import { PER_CHECK_TIMEOUT_MS } from '../src/lib/config';

const { restore } = setupFetchMock();

/**
 * Reduced per-check budget for the behavioural case. Real value is 8s; every
 * simulated leg below is scaled to this so one scan fits the pool's 15s ceiling.
 * `fetchBudgetFor(3000)` = 2250ms, which is what bounds the final probe.
 */
const REDUCED_PER_CHECK_MS = 3_000;
const REDUCED_BUDGET_MS = fetchBudgetFor(REDUCED_PER_CHECK_MS); // 2250

/** How long the robots.txt gate fetch takes before the `https://` leg can start. */
const ROBOTS_DELAY_MS = 250;
/** How long the `https://` leg takes. Robots + this must leave >0 budget for leg 3. */
const HTTPS_DELAY_MS = 250;

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => {
	restore();
	vi.doUnmock('../src/tools/check-ssl');
	vi.resetModules();
});

const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * A fetch that never resolves on its own and rejects only when its signal
 * aborts — i.e. what a real stalled origin does. Returning a bare
 * `new Promise(() => {})` instead would be unabortable, so the budget could
 * never demonstrate anything.
 */
function hangUntilAborted(init?: RequestInit): Promise<Response> {
	return new Promise<Response>((_resolve, reject) => {
		const signal = init?.signal;
		const fail = () => reject(Object.assign(new Error('The operation was aborted (timeout)'), { name: 'AbortError' }));
		if (!signal) return; // no signal at all → genuinely unbounded, as a raw fetch would be
		if (signal.aborted) return fail();
		signal.addEventListener('abort', fail, { once: true });
	});
}

/** DoH + non-ssl HTTP defaults, healthy and fast, so only `ssl` is under test. */
function respondToNonSslUrl(url: string): Promise<Response> | undefined {
	if (url.includes('cloudflare-dns.com')) {
		if (url.includes('type=TXT') || url.includes('type=16')) {
			if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
			if (url.includes('_domainkey.')) return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
			if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
			if (url.includes('_smtp._tls.'))
				return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
			if (url.includes('default._bimi.'))
				return Promise.resolve(txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']));
			return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
		}
		if (url.includes('type=NS') || url.includes('type=2'))
			return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
		if (url.includes('type=CAA') || url.includes('type=257'))
			return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
		if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('example.com', true));
		return Promise.resolve(createDohResponse([], []));
	}
	if (url.includes('mta-sts.') && url.includes('.well-known')) {
		return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
	}
	return undefined;
}

/** Call counters so the test can assert WHICH legs were issued, not just the outcome. */
interface LegCounts {
	robots: number;
	https: number;
	httpRedirectProbe: number;
}

/**
 * The #641 pathology, scaled down: robots.txt and `https://` both answer, but
 * slowly, and the `http://` redirect probe never answers at all.
 *
 * Timeline against `REDUCED_BUDGET_MS` (2250):
 *   t=0     robots.txt issued, budget-bounded to 2250 → answers at 250
 *   t=250   `https://` issued, budget-bounded to 2000 → answers at 500
 *   t=500   `http://`  issued, budget-bounded to 1750 → ABORTS at 2250
 *   → checkSSL returns ~2250ms, inside the 3000ms per-check budget.
 *
 * WITHOUT the budget the third leg carries only the package's own 4000ms
 * timeout, so the check cannot return before ~4500ms and `safeCheck` kills it at
 * 3000ms — losing the whole category, which is the regression.
 */
function mockSlowSslLegs(counts: LegCounts) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		const nonSsl = respondToNonSslUrl(url);
		if (nonSsl) return nonSsl;

		if (url === 'https://example.com/robots.txt') {
			counts.robots += 1;
			// Allow-all robots.txt: the gate must not become the reason `ssl` is excluded.
			return delay(ROBOTS_DELAY_MS).then(() => httpResponse('User-agent: *\nDisallow:\n'));
		}
		if (url === 'http://example.com' || url === 'http://example.com/') {
			counts.httpRedirectProbe += 1;
			return hangUntilAborted(init);
		}
		if (url === 'https://example.com' || url === 'https://example.com/') {
			counts.https += 1;
			// 200 + HSTS → measurable, healthy posture with no critical finding, so
			// checkSSL goes on to the third leg (the one this fix bounds).
			return delay(HTTPS_DELAY_MS).then(() => httpResponse('OK'));
		}
		if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));
		return Promise.resolve(httpResponse('OK'));
	});
}

describe('ssl fetch budget — behavioural proof (issue #641)', () => {
	it('keeps the ssl category MEASURED when the early legs are slow enough to have blown the per-check budget', async () => {
		const counts: LegCounts = { robots: 0, https: 0, httpRedirectProbe: 0 };
		mockSlowSslLegs(counts);

		const { scanDomain } = await import('../src/tools/scan-domain');
		const startedAt = Date.now();
		const result = await scanDomain('example.com', undefined, {
			forceRefresh: true,
			perCheckTimeoutMs: REDUCED_PER_CHECK_MS,
			scanTimeoutMs: 12_000,
		});
		const elapsedMs = Date.now() - startedAt;

		// Preconditions: the pathology actually ran. Without these, a mock that
		// silently short-circuited would let the real assertions pass vacuously.
		expect(counts.robots, 'robots.txt gate fetch must have been issued').toBeGreaterThanOrEqual(1);
		expect(counts.https, 'the https:// leg must have been issued').toBeGreaterThanOrEqual(1);
		expect(counts.httpRedirectProbe, 'the stalled http:// redirect probe must have been reached').toBeGreaterThanOrEqual(1);

		const ssl = result.checks.find((c) => c.category === 'ssl');
		expect(ssl, 'ssl must be present in the scan results').toBeDefined();

		// THE REGRESSION. All four of these flip on unfixed code.
		expect(ssl!.checkStatus, 'ssl must not be a per-check timeout casualty').toBeUndefined();
		expect(ssl!.score, 'ssl must carry a real measured score, not the safeCheck zero').toBeGreaterThan(0);
		expect(ssl!.passed).toBe(true);
		expect(
			result.score.categoryScores,
			'a timed-out ssl is EXCLUDED from categoryScores — that exclusion is the 3–4 points #641 measured',
		).toHaveProperty('ssl');

		// The check degraded by dropping/bounding its LAST probe, not by
		// fabricating a finding: `checkHttpRedirect` swallows a failed probe, so a
		// budget-aborted leg emits nothing at all.
		expect(ssl!.findings.some((f) => f.title.toLowerCase().includes('timed out'))).toBe(false);
		expect(ssl!.findings.some((f) => f.severity === 'critical' || f.severity === 'high')).toBe(false);

		// Secondary: the budget must land BEFORE safeCheck's killer, not race it.
		// The scan cannot outlive the per-check budget if ssl returned on its own.
		expect(elapsedMs, `scan took ${elapsedMs}ms; ssl should have self-bounded at ~${REDUCED_BUDGET_MS}ms`).toBeLessThan(
			REDUCED_PER_CHECK_MS,
		);
	}, 20_000);
});

describe('ssl fetch budget — argument proof (issue #641)', () => {
	/**
	 * Run one scan with `checkSsl` replaced by a spy, and hand back its first call.
	 * The rest of the network is healthy and fast — this case is about the value
	 * that arrives, not about timing.
	 */
	async function captureSslOptions(perCheckTimeoutMs?: number): Promise<Record<string, unknown>> {
		vi.resetModules();
		const ssl = vi.fn().mockResolvedValue({ ...buildCheckResult('ssl', []), passed: true });
		vi.doMock('../src/tools/check-ssl', () => ({ checkSsl: ssl }));

		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			return respondToNonSslUrl(url) ?? Promise.resolve(httpResponse('OK'));
		});

		const { scanDomain } = await import('../src/tools/scan-domain');
		await scanDomain('example.com', undefined, { forceRefresh: true, ...(perCheckTimeoutMs ? { perCheckTimeoutMs } : {}) });

		expect(ssl, 'checkSsl spy never fired — the harness short-circuited before dispatch').toHaveBeenCalled();
		return ssl.mock.calls[0][1] as Record<string, unknown>;
	}

	it('passes a budget DERIVED from the per-check timeout, not a constant', async () => {
		// Two different per-check timeouts must produce two different budgets. A
		// hardcoded literal that happens to be right at the 8s default cannot pass both.
		const atThreeSeconds = await captureSslOptions(3_000);
		const atNineSeconds = await captureSslOptions(9_000);

		expect(atThreeSeconds.budgetMs).toBe(2_250); // fetchBudgetFor(3000)
		expect(atNineSeconds.budgetMs).toBe(8_250); // fetchBudgetFor(9000)
		expect(atThreeSeconds.budgetMs).not.toBe(atNineSeconds.budgetMs);

		// And it agrees with the exported derivation, so the two can't drift apart.
		expect(atThreeSeconds.budgetMs).toBe(fetchBudgetFor(3_000));
		expect(atNineSeconds.budgetMs).toBe(fetchBudgetFor(9_000));
	}, 20_000);

	it('defaults to the production per-check timeout, and always lands inside it', async () => {
		const options = await captureSslOptions();

		expect(options.budgetMs).toBe(fetchBudgetFor(PER_CHECK_TIMEOUT_MS)); // 7250 of 8000
		// Load-bearing invariant: the budget must expire BEFORE safeCheck's killer.
		// A budget >= the per-check timeout would race it and re-open #641.
		expect(options.budgetMs as number).toBeLessThan(PER_CHECK_TIMEOUT_MS);
		expect(options.budgetMs as number).toBeGreaterThan(0);

		// The 7th dispatch param must not have displaced the params already threaded
		// through it — a positional-arg refactor breaks these together.
		expect(options).toHaveProperty('signal');
		expect(options).toHaveProperty('robotsMemo');
		expect(options.robotsMemo).toBeDefined();
	}, 20_000);
});
