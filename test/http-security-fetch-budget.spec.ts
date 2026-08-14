// SPDX-License-Identifier: BUSL-1.1

/**
 * End-to-end wiring proof for the `http_security` per-check fetch budget (issue #674).
 *
 * ## What was wrong
 *
 * `check_http_security` already had a total-budget guard — `TOTAL_BUDGET_MS`, a
 * `Promise.race` that aborts in-flight fetches. But it is **10s, larger than the
 * 8s `PER_CHECK_TIMEOUT_MS`**, so under `scan_domain` `safeCheck` always won and
 * the guard was dead code on the one path where this check is not the only thing
 * running. It stays live for DIRECT callers, bounded only by the 28s
 * `TOOL_CALL_TIMEOUT_MS` — the constant was right for one caller and wrong for
 * the other.
 *
 * ## Why lowering the constant is not the fix
 *
 * Firing the total-budget race earlier only swaps one lost category for another:
 * the race returns a timeout result, and the category is excluded either way.
 * What makes this check different from `ssl` is that it degrades gracefully **by
 * construction** — `dualFetchHeaders` is `Promise.allSettled` and the redirect
 * loop `break`s on a throw — so bounding each INDIVIDUAL fetch lets the check
 * finish and report the headers it did read, instead of reporting nothing.
 *
 * That is what these tests pin: a slow/stalled origin leg must cost the finding
 * it would have produced, never the whole category.
 *
 * Harness notes are the same as `ssl-fetch-budget-wiring.spec.ts`: times scaled
 * to a reduced per-check budget, `Date.now()` only advances across I/O so every
 * leg is a real `setTimeout`, and the stalled mock HONOURS `init.signal` (a mock
 * that ignores it hangs forever regardless of the budget and would fail against
 * correct code).
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse, createDohResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { fetchBudgetFor } from '../src/lib/fetch-budget';

const { restore } = setupFetchMock();

const REDUCED_PER_CHECK_MS = 3_000;
/** What the dispatch site cuts from the per-check timeout: 2250ms. */
const REDUCED_BUDGET_MS = fetchBudgetFor(REDUCED_PER_CHECK_MS);

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => {
	restore();
	vi.resetModules();
});

const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** A stalled origin: never resolves on its own, rejects only when its signal aborts. */
function hangUntilAborted(init?: RequestInit): Promise<Response> {
	return new Promise<Response>((_resolve, reject) => {
		const signal = init?.signal;
		const fail = () => reject(Object.assign(new Error('The operation was aborted (timeout)'), { name: 'AbortError' }));
		if (!signal) return;
		if (signal.aborted) return fail();
		signal.addEventListener('abort', fail, { once: true });
	});
}

/** Healthy, fast defaults for every category that is not under test. */
function respondToNonHttpUrl(url: string): Promise<Response> | undefined {
	if (url.includes('cloudflare-dns.com')) {
		if (url.includes('type=TXT') || url.includes('type=16')) {
			if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
			if (url.includes('_domainkey.')) return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
			return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
		}
		if (url.includes('type=NS') || url.includes('type=2'))
			return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
		if (url.includes('type=CAA') || url.includes('type=257'))
			return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
		if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('example.com', true));
		return Promise.resolve(createDohResponse([], []));
	}
	return undefined;
}

/** Response carrying a measurable security-header posture. */
function securityHeaderResponse(): Response {
	return new Response('OK', {
		status: 200,
		headers: new Headers({
			'strict-transport-security': 'max-age=31536000; includeSubDomains',
			'content-security-policy': "default-src 'self'",
			'x-content-type-options': 'nosniff',
			'x-frame-options': 'DENY',
		}),
	}) as Response;
}

interface LegCounts {
	robots: number;
	firstHop: number;
	redirectHop: number;
}

/**
 * The #674 pathology, verified against `fetchWithRedirects` rather than assumed:
 * the FIRST hop answers with a 301 (so real headers have been read), and the
 * redirect TARGET stalls forever.
 *
 * This is the shape that degrades gracefully: the redirect loop wraps the hop in
 * a `try/catch` and `break`s on a throw, keeping the last good response, so a
 * budget-cut hop costs the finding it would have produced and nothing else.
 *
 * Timeline against a 2250ms budget:
 *   t=0     robots.txt   → answers at 150
 *   t=150   hop 1 (HEAD) → answers at 300 with a 301
 *   t=300   hop 2 (HEAD) → budget-bounded to 1950, ABORTS at 2250
 *   → the check returns ~2250ms, inside the 3000ms per-check kill.
 *
 * Without the budget hop 2 carries only its own fixed 4000ms timeout, so the
 * check cannot return before ~4300ms and `safeCheck` kills it at 3000ms —
 * discarding headers it had already read. That is the regression.
 *
 * NOTE the earlier draft of this test stalled a plain-`http://` leg, and its
 * precondition caught that no such leg is issued on this path at all: the check
 * fetches robots.txt and `https://<domain>` only. Kept as a warning that the
 * preconditions below are load-bearing, not decoration.
 */
function mockStalledRedirectHop(counts: LegCounts) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		const nonHttp = respondToNonHttpUrl(url);
		if (nonHttp) return nonHttp;

		if (url.endsWith('/robots.txt')) {
			counts.robots += 1;
			return delay(150).then(() => httpResponse('User-agent: *\nDisallow:\n'));
		}
		if (url.startsWith('https://example.com/next')) {
			counts.redirectHop += 1;
			return hangUntilAborted(init);
		}
		if (url === 'https://example.com' || url === 'https://example.com/') {
			counts.firstHop += 1;
			return delay(150).then(
				() =>
					new Response(null, {
						status: 301,
						headers: new Headers({
							location: 'https://example.com/next',
							'strict-transport-security': 'max-age=31536000; includeSubDomains',
						}),
					}) as Response,
			);
		}
		return Promise.resolve(securityHeaderResponse());
	});
}

describe('http_security per-check fetch budget (#674)', () => {
	it('keeps the category MEASURED when a redirect hop stalls', async () => {
		const counts: LegCounts = { robots: 0, firstHop: 0, redirectHop: 0 };
		mockStalledRedirectHop(counts);

		const { scanDomain } = await import('../src/tools/scan-domain');
		const startedAt = Date.now();
		const result = await scanDomain('example.com', undefined, {
			forceRefresh: true,
			perCheckTimeoutMs: REDUCED_PER_CHECK_MS,
		});
		const elapsed = Date.now() - startedAt;

		// Preconditions — without these the test can pass while proving nothing.
		// The stalled hop must actually have been reached.
		expect(counts.firstHop).toBeGreaterThan(0);
		expect(counts.redirectHop).toBeGreaterThan(0);

		// The regression, as the customer sees it: category present and scored.
		// Read `result.checks` (the CheckResult array) — NOT a `checkStatuses` map,
		// which belongs to the FORMATTED report shape, not `ScanDomainResult`. The
		// typecheck:tests ratchet caught the first draft doing that: optional-chaining
		// a property the type does not have yields `undefined`, and
		// `expect(undefined).not.toBe('timeout')` passes no matter what the code does.
		const httpCheck = result.checks.find((c) => c.category === 'http_security');
		expect(httpCheck).toBeDefined();
		expect(httpCheck?.checkStatus).not.toBe('timeout');
		expect(httpCheck?.findings.length).toBeGreaterThan(0);
		expect(Object.keys(result.score?.categoryScores ?? {})).toContain('http_security');

		// Bounded by the budget, not by the check's own 10s TOTAL_BUDGET_MS.
		expect(REDUCED_BUDGET_MS).toBeLessThan(REDUCED_PER_CHECK_MS);
		expect(elapsed).toBeLessThan(REDUCED_PER_CHECK_MS + 1_500);
	});

	it('clamps the total-budget race below the per-check kill', async () => {
		vi.resetModules();
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');

		globalThis.fetch = vi.fn().mockImplementation((_input: string | URL | Request, init?: RequestInit) => hangUntilAborted(init));

		const startedAt = Date.now();
		const result = await checkHttpSecurity('example.com', { budgetMs: 800 });
		const elapsed = Date.now() - startedAt;

		// The check's own guard is 10s. Supplying a budget must bring the whole
		// check home well inside it — otherwise safeCheck would still win and the
		// guard would still be dead code under a scan.
		expect(elapsed).toBeLessThan(4_000);
		expect(result.category).toBe('http_security');

		// A budget timeout measured NOTHING, so it must not claim the control is
		// absent (#638/#662): excluded via checkStatus, never zeroed via missingControl.
		if (result.checkStatus === 'timeout') {
			expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		}
	});

	it('no budget → the check is unchanged (direct callers keep the 10s guard)', async () => {
		vi.resetModules();
		const counts: LegCounts = { robots: 0, firstHop: 0, redirectHop: 0 };
		mockStalledRedirectHop(counts);

		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		const result = await checkHttpSecurity('example.com');

		// Direct calls have no 8s ceiling, so nothing is bounded away: the check
		// still analyses the https posture it read. This is the byte-for-byte
		// path every BSL self-host and every direct tool call takes.
		expect(result.category).toBe('http_security');
		expect(result.findings.length).toBeGreaterThan(0);
	});
});
