// SPDX-License-Identifier: BUSL-1.1

/**
 * End-to-end wiring proof for the `mta_sts` per-check fetch budget (issue #674).
 *
 * ## What actually breaks
 *
 * `checkMTASTS` makes two STRICTLY SEQUENTIAL external calls behind the DNS lookups:
 * the robots.txt gate on `mta-sts.<domain>` (3s) → the policy fetch (4s). Neither is
 * bounded by anything the Worker wrapper passes — the package spends `options.timeout`
 * on its DNS queries and hardcodes `AbortSignal.timeout(4000)` from its OWN module-local
 * constant on the policy fetch, so the `timeout: HTTPS_TIMEOUT_MS` this repo's wrapper
 * hands it is inert for the leg that actually stalls. 7s of fixed fetch timeouts, after
 * DNS, inside an 8s `PER_CHECK_TIMEOUT_MS`: `safeCheck` kills the check and `scan_domain`
 * loses the whole `mta_sts` category, INCLUDING the `_mta-sts` TXT / TLS-RPT / MX-coverage
 * findings that had already been measured from DNS.
 *
 * ## What the budget can and cannot buy here — read before adding assertions
 *
 * Unlike `ssl` and `http_security`, a budget-cut `mta_sts` must NOT come back scored. The
 * leg the budget cuts IS the measurement: a policy fetch that never completed says nothing
 * about whether the policy is served. `check-mta-sts.ts` therefore routes a budget-cut
 * fetch into the SAME path as a WAF stall (`excludeForPolicyThrow`) — `checkStatus: 'error'`
 * with an `inconclusive` finding, never the package's confident `high` "policy file not
 * accessible" and never `missingControl`. Asserting "present in categoryScores" on the
 * stalled case would be asserting a fabrication.
 *
 * What the budget buys is the difference between `'error'` and `'timeout'`:
 *   • the DNS-derived findings survive and are shown, instead of a synthetic
 *     "MTA_STS check timed out";
 *   • `checkStatus: 'error'` + score 0 is the RETRYABLE class (`shouldRetry` in
 *     scan-domain.ts excludes `'timeout'`), so a transient stall gets a second, unbudgeted
 *     attempt — and when that one answers, the category is measured and scored again.
 * The third test drives exactly that recovery, which is the customer-visible fix.
 *
 * ## Harness notes (see CLAUDE.md §Testing, bv-mcp-testing skill)
 *
 *  - Times are scaled to a REDUCED `perCheckTimeoutMs` (a `ScanRuntimeOptions` override)
 *    rather than the real 3s/4s legs — the pool's per-test ceiling is 15s.
 *  - `Date.now()` in workerd only advances across I/O, so every simulated leg is a real
 *    `setTimeout`.
 *  - The stalled mock HONOURS `init.signal`. Load-bearing: a mock returning a bare
 *    `new Promise(() => {})` is unabortable and would fail against CORRECT code.
 *  - Each case uses a DISTINCT domain. `check-mta-sts.ts` keeps a module-scope
 *    `withRobotsGate` whose robots.txt verdict is memoized per hostname for the isolate's
 *    lifetime (deliberately — see the comment on `gatedFetch`), so reusing one domain
 *    across cases would serve an earlier case's cached verdict.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse, createDohResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { buildCheckResult } from '../src/lib/scoring';
import { fetchBudgetFor } from '../src/lib/fetch-budget';
import { PER_CHECK_TIMEOUT_MS } from '../src/lib/config';

const { restore } = setupFetchMock();

/** Reduced per-check budget. `fetchBudgetFor(3000)` = 2250ms, which is what bounds the legs. */
const REDUCED_PER_CHECK_MS = 3_000;
const REDUCED_BUDGET_MS = fetchBudgetFor(REDUCED_PER_CHECK_MS);

/** robots.txt answers quickly, so the policy fetch is unambiguously the leg under test. */
const ROBOTS_DELAY_MS = 150;

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => {
	restore();
	vi.doUnmock('../src/tools/check-mta-sts');
	vi.resetModules();
});

const delay = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** A stalled origin: never resolves on its own, rejects only when its signal aborts. */
function hangUntilAborted(init?: RequestInit): Promise<Response> {
	return new Promise<Response>((_resolve, reject) => {
		const signal = init?.signal;
		const fail = () => reject(Object.assign(new Error('The operation was aborted (timeout)'), { name: 'AbortError' }));
		if (!signal) return; // no signal at all → genuinely unbounded, as a raw fetch would be
		if (signal.aborted) return fail();
		signal.addEventListener('abort', fail, { once: true });
	});
}

/** Healthy, fast DoH answers for every category that is not under test. */
function respondToDoh(url: string, domain: string): Promise<Response> | undefined {
	if (!url.includes('cloudflare-dns.com')) return undefined;
	if (url.includes('type=TXT') || url.includes('type=16')) {
		if (url.includes('_dmarc.')) return Promise.resolve(txtResponse(`_dmarc.${domain}`, ['v=DMARC1; p=reject']));
		if (url.includes('_domainkey.')) return Promise.resolve(txtResponse(`default._domainkey.${domain}`, ['v=DKIM1; k=rsa; p=MIGf']));
		// Load-bearing: the package only fetches the policy when the TXT record exists.
		if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse(`_mta-sts.${domain}`, ['v=STSv1; id=20240101']));
		if (url.includes('_smtp._tls.')) return Promise.resolve(txtResponse(`_smtp._tls.${domain}`, ['v=TLSRPTv1; rua=mailto:tls@' + domain]));
		return Promise.resolve(txtResponse(domain, ['v=spf1 include:_spf.google.com -all']));
	}
	if (url.includes('type=NS') || url.includes('type=2')) return Promise.resolve(nsResponse(domain, [`ns1.${domain}.`, `ns2.${domain}.`]));
	if (url.includes('type=CAA') || url.includes('type=257')) return Promise.resolve(caaResponse(domain, ['0 issue "letsencrypt.org"']));
	if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse(domain, true));
	return Promise.resolve(createDohResponse([], []));
}

const HEALTHY_POLICY = 'version: STSv1\nmode: enforce\nmx: *.example.net\nmax_age: 86400';

interface LegCounts {
	robots: number;
	policy: number;
}

/**
 * Mock the network for one domain. `policyMode` decides what the policy fetch does:
 *   'stall'         — never answers; only an abort ends it (every attempt).
 *   'stall-then-ok' — the FIRST attempt stalls, later attempts answer immediately.
 *                     This models a transient stall and is what the retry pass recovers.
 */
function mockNetwork(domain: string, policyMode: 'stall' | 'stall-then-ok', counts: LegCounts) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		const doh = respondToDoh(url, domain);
		if (doh) return doh;

		if (url === `https://mta-sts.${domain}/robots.txt`) {
			counts.robots += 1;
			// Allow-all: the gate must never be the reason the category is excluded.
			return delay(ROBOTS_DELAY_MS).then(() => httpResponse('User-agent: *\nDisallow:\n'));
		}
		if (url.includes(`mta-sts.${domain}`) && url.includes('.well-known')) {
			counts.policy += 1;
			if (policyMode === 'stall-then-ok' && counts.policy > 1) return Promise.resolve(new Response(HEALTHY_POLICY));
			return hangUntilAborted(init);
		}
		if (url.endsWith('/robots.txt')) return Promise.resolve(httpResponse('User-agent: *\nDisallow:\n'));
		return Promise.resolve(httpResponse('OK'));
	});
}

describe('mta_sts fetch budget — behavioural proof (issue #674)', () => {
	it('returns an EXCLUDED-but-reported category instead of being killed, and never claims the policy is absent', async () => {
		const domain = 'stalled-policy.example.net';
		const counts: LegCounts = { robots: 0, policy: 0 };
		mockNetwork(domain, 'stall', counts);

		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain(domain, undefined, {
			forceRefresh: true,
			perCheckTimeoutMs: REDUCED_PER_CHECK_MS,
			scanTimeoutMs: 12_000,
		});

		// Preconditions — without these the assertions below can pass vacuously.
		expect(counts.robots, 'the robots.txt gate leg must have been issued').toBeGreaterThanOrEqual(1);
		expect(counts.policy, 'the stalled policy fetch must have been reached').toBeGreaterThanOrEqual(1);

		// Read the CheckResult array, NOT a `checkStatuses` map — that belongs to the
		// FORMATTED report shape, and optional-chaining a property the type does not have
		// yields `undefined`, making every assertion pass no matter what the code does.
		const mtaSts = result.checks.find((c) => c.category === 'mta_sts');
		expect(mtaSts, 'mta_sts must be present in the scan results at all').toBeDefined();

		// THE REGRESSION. On unfixed code the check is still inside its 4s policy fetch when
		// safeCheck fires at 3s, so this is `'timeout'` with a synthetic "check timed out"
		// finding and none of the DNS-derived evidence.
		expect(mtaSts!.checkStatus, 'a budget-cut policy fetch is a per-check ERROR, not a scan timeout').toBe('error');
		expect(
			mtaSts!.findings.some((f) => f.title.includes('check timed out')),
			'the safeCheck synthetic must not be what came back',
		).toBe(false);

		// Degrade, never fabricate. The package's confident `high` claims are the whole
		// hazard: "policy file not accessible" from a probe that never reached the origin.
		expect(mtaSts!.findings.some((f) => f.severity === 'high')).toBe(false);
		expect(mtaSts!.findings.some((f) => f.title === 'MTA-STS policy file not accessible')).toBe(false);
		expect(mtaSts!.findings.some((f) => f.title === 'MTA-STS policy fetch failed')).toBe(false);
		expect(
			mtaSts!.findings.some((f) => f.metadata?.inconclusive === true),
			'the stall must be reported as inconclusive',
		).toBe(true);
		// The contradiction audited by measured-vs-unmeasured-metadata.audit.test.ts.
		expect(mtaSts!.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);

		// Excluded, not zeroed: an unmeasured category must not sit in the score at 0.
		expect(Object.keys(result.score.categoryScores)).not.toContain('mta_sts');
	}, 20_000);

	it('a transient stall is RECOVERED: the retryable error class restores the category to the score', async () => {
		// The customer-visible payoff. `shouldRetry` fires only for checkStatus 'error' +
		// score 0; the killed-by-safeCheck shape is 'timeout' and is deliberately never
		// retried, so on unfixed code this category is simply gone.
		const domain = 'transient-policy.example.net';
		const counts: LegCounts = { robots: 0, policy: 0 };
		mockNetwork(domain, 'stall-then-ok', counts);

		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain(domain, undefined, {
			forceRefresh: true,
			perCheckTimeoutMs: REDUCED_PER_CHECK_MS,
			scanTimeoutMs: 12_000,
		});

		expect(counts.policy, 'the retry pass must have issued a SECOND policy fetch').toBeGreaterThanOrEqual(2);

		const mtaSts = result.checks.find((c) => c.category === 'mta_sts');
		expect(mtaSts).toBeDefined();
		expect(mtaSts!.checkStatus, 'the successful retry must have replaced the excluded result').toBeUndefined();
		expect(mtaSts!.score).toBeGreaterThan(0);
		expect(Object.keys(result.score.categoryScores), 'the recovered category is scored again').toContain('mta_sts');
	}, 20_000);

	it('no budget → unchanged: the direct call still runs the full unbounded policy fetch', async () => {
		// The other half of the contract, and the reason the whole scan path could
		// deterministically lose this category: without a budget the policy fetch runs to
		// the package's own fixed 4s timeout — longer than the 3s per-check kill that
		// `safeCheck` applies under a scan. Direct callers (and every BSL self-host) keep
		// exactly that behaviour, including the same inconclusive-exclusion semantics.
		const domain = 'direct-unbudgeted.example.net';
		const counts: LegCounts = { robots: 0, policy: 0 };
		mockNetwork(domain, 'stall', counts);

		const { checkMtaSts } = await import('../src/tools/check-mta-sts');
		const startedAt = Date.now();
		const result = await checkMtaSts(domain);
		const elapsed = Date.now() - startedAt;

		expect(counts.policy).toBe(1);
		expect(elapsed, `unbudgeted policy fetch ran ${elapsed}ms; the package's own timeout is 4s`).toBeGreaterThan(REDUCED_PER_CHECK_MS);
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.metadata?.inconclusive === true)).toBe(true);
	}, 20_000);
});

describe('mta_sts fetch budget — argument proof (issue #674)', () => {
	/** Run one scan with `checkMtaSts` replaced by a spy and hand back its 4th argument. */
	async function captureMtaStsOptions(perCheckTimeoutMs?: number): Promise<Record<string, unknown>> {
		vi.resetModules();
		const mtaSts = vi.fn().mockResolvedValue({ ...buildCheckResult('mta_sts', []), passed: true });
		vi.doMock('../src/tools/check-mta-sts', () => ({ checkMtaSts: mtaSts }));

		const domain = 'args.example.net';
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			return respondToDoh(url, domain) ?? Promise.resolve(httpResponse('OK'));
		});

		const { scanDomain } = await import('../src/tools/scan-domain');
		await scanDomain(domain, undefined, { forceRefresh: true, ...(perCheckTimeoutMs ? { perCheckTimeoutMs } : {}) });

		expect(mtaSts, 'checkMtaSts spy never fired — the harness short-circuited before dispatch').toHaveBeenCalled();
		return mtaSts.mock.calls[0][3] as Record<string, unknown>;
	}

	it('passes a budget DERIVED from the per-check timeout, not a constant', async () => {
		const atThreeSeconds = await captureMtaStsOptions(3_000);
		const atNineSeconds = await captureMtaStsOptions(9_000);

		expect(atThreeSeconds.budgetMs).toBe(fetchBudgetFor(3_000));
		expect(atNineSeconds.budgetMs).toBe(fetchBudgetFor(9_000));
		expect(atThreeSeconds.budgetMs).not.toBe(atNineSeconds.budgetMs);
	}, 20_000);

	it('defaults to the production per-check timeout, and always lands inside it', async () => {
		const options = await captureMtaStsOptions();

		expect(options.budgetMs).toBe(fetchBudgetFor(PER_CHECK_TIMEOUT_MS));
		// Load-bearing: the budget must expire BEFORE safeCheck's killer, not race it.
		expect(options.budgetMs as number).toBeLessThan(PER_CHECK_TIMEOUT_MS);
		expect(REDUCED_BUDGET_MS).toBeLessThan(REDUCED_PER_CHECK_MS);
	}, 20_000);
});
