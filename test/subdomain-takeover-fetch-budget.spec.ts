// SPDX-License-Identifier: BUSL-1.1

/**
 * End-to-end wiring proof for the `subdomain_takeover` per-check fetch budget (issue #674).
 *
 * ## What actually breaks
 *
 * The sweep is DNS-first, but every CNAME that points at a known takeover service AND
 * still resolves costs an HTTP fingerprint probe: `https://<fqdn>` behind a robots.txt
 * gate (3s) with the package's own fixed 4s timeout, issued after two sequential DNS
 * lookups. Nothing the Worker wrapper passes can lower either. Inside an 8s
 * `PER_CHECK_TIMEOUT_MS` that sum blows the budget, `safeCheck` kills the check, and
 * `scan_domain` loses the whole category — including the DANGLING-CNAME findings, which
 * are DNS-derived, were already complete, and carry this category's entire score.
 *
 * ## The correctness hazard the budget introduces, and how it is closed
 *
 * `probeHttpFingerprint` SWALLOWS every transport failure by design (a timeout is not
 * deprovision evidence). So a budget-cut probe would silently collapse into the package's
 * clean verdict — "No dangling CNAME records found", an `info` finding, category 100,
 * passed. That is "slow" being rewritten as "absent", which is worse than having no
 * budget at all. `check-subdomain-takeover.ts` therefore OBSERVES the cut and splits:
 *
 *   • real evidence survived (a dangling CNAME) → keep the result and its score, append a
 *     non-scoring `info` note recording the unverified probe;
 *   • nothing was found → withhold the clean claim and EXCLUDE the category
 *     (`checkStatus: 'error'` + `inconclusive`, never `missingControl`).
 *
 * Both branches are pinned below; the second is the anti-fabrication test.
 *
 * ## Harness notes (see CLAUDE.md §Testing, bv-mcp-testing skill)
 *
 *  - Times are scaled to a REDUCED `perCheckTimeoutMs`; `Date.now()` in workerd only
 *    advances across I/O, so each simulated leg is a real `setTimeout`.
 *  - The stalled mock HONOURS `init.signal` — a bare `new Promise(() => {})` is
 *    unabortable and would fail against CORRECT code.
 *  - Distinct domains per case: the probe's robots.txt verdict is memoized per hostname
 *    inside the gate built for that call.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse, createDohResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { buildCheckResult } from '../src/lib/scoring';
import { fetchBudgetFor } from '../src/lib/fetch-budget';
import { PER_CHECK_TIMEOUT_MS } from '../src/lib/config';

const { restore } = setupFetchMock();

const REDUCED_PER_CHECK_MS = 3_000;
const REDUCED_BUDGET_MS = fetchBudgetFor(REDUCED_PER_CHECK_MS);
const ROBOTS_DELAY_MS = 150;

/** `app` and `staging` are both members of the package's KNOWN_SUBDOMAINS sweep list. */
const PROBED_LABEL = 'app';
const DANGLING_LABEL = 'staging';
/** A CNAME target matching a TAKEOVER_FINGERPRINTS service, so the probe actually fires. */
const RESOLVING_TARGET = 'live-app.herokuapp.com';
const DANGLING_TARGET = 'ghost-app.herokuapp.com';

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => {
	restore();
	vi.doUnmock('../src/tools/check-subdomain-takeover');
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

function cnameResponse(name: string, cname: string) {
	return createDohResponse([{ name, type: 5 }], [{ name, type: 5, TTL: 300, data: `${cname}.` }]);
}

function aResponse(name: string, ips: string[]) {
	return createDohResponse(
		[{ name, type: 1 }],
		ips.map((ip) => ({ name, type: 1, TTL: 300, data: ip })),
	);
}

interface LegCounts {
	robots: number;
	probe: number;
}

/**
 * Mock the network for one domain.
 *
 * `withDangling` adds a second, DNS-only takeover vector (`staging` → an unresolved
 * target) so the two branches of the degradation split can be exercised separately:
 * with it, real evidence survives the cut probe; without it, the sweep finds nothing and
 * the clean claim must be withheld.
 */
function mockNetwork(domain: string, opts: { withDangling: boolean }, counts: LegCounts) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes(`${PROBED_LABEL}.${domain}`)) return Promise.resolve(cnameResponse(`${PROBED_LABEL}.${domain}`, RESOLVING_TARGET));
				if (opts.withDangling && url.includes(`${DANGLING_LABEL}.${domain}`))
					return Promise.resolve(cnameResponse(`${DANGLING_LABEL}.${domain}`, DANGLING_TARGET));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				// The probed target RESOLVES — that is what sends the check on to the HTTP probe.
				if (url.includes(RESOLVING_TARGET)) return Promise.resolve(aResponse(RESOLVING_TARGET, ['203.0.113.10']));
				// The dangling target does not, which is the DNS-only evidence.
				if (url.includes(DANGLING_TARGET)) return Promise.resolve(createDohResponse([], []));
				return Promise.resolve(dnssecResponse(domain, true));
			}
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) return Promise.resolve(txtResponse(`_dmarc.${domain}`, ['v=DMARC1; p=reject']));
				if (url.includes('_domainkey.')) return Promise.resolve(txtResponse(`default._domainkey.${domain}`, ['v=DKIM1; k=rsa; p=MIGf']));
				return Promise.resolve(txtResponse(domain, ['v=spf1 include:_spf.google.com -all']));
			}
			if (url.includes('type=NS') || url.includes('type=2'))
				return Promise.resolve(nsResponse(domain, [`ns1.${domain}.`, `ns2.${domain}.`]));
			if (url.includes('type=CAA') || url.includes('type=257')) return Promise.resolve(caaResponse(domain, ['0 issue "letsencrypt.org"']));
			return Promise.resolve(createDohResponse([], []));
		}

		if (url === `https://${PROBED_LABEL}.${domain}/robots.txt`) {
			counts.robots += 1;
			return delay(ROBOTS_DELAY_MS).then(() => httpResponse('User-agent: *\nDisallow:\n'));
		}
		// THE LEG UNDER TEST: the fingerprint probe stalls forever.
		if (url === `https://${PROBED_LABEL}.${domain}` || url === `https://${PROBED_LABEL}.${domain}/`) {
			counts.probe += 1;
			return hangUntilAborted(init);
		}
		if (url.endsWith('/robots.txt')) return Promise.resolve(httpResponse('User-agent: *\nDisallow:\n'));
		return Promise.resolve(httpResponse('OK'));
	});
}

describe('subdomain_takeover fetch budget — behavioural proof (issue #674)', () => {
	it('keeps the category MEASURED when the fingerprint probe stalls, and records the gap', async () => {
		const domain = 'stalled-probe.example.net';
		const counts: LegCounts = { robots: 0, probe: 0 };
		mockNetwork(domain, { withDangling: true }, counts);

		const { scanDomain } = await import('../src/tools/scan-domain');
		const startedAt = Date.now();
		const result = await scanDomain(domain, undefined, {
			forceRefresh: true,
			perCheckTimeoutMs: REDUCED_PER_CHECK_MS,
			scanTimeoutMs: 12_000,
		});
		const elapsed = Date.now() - startedAt;

		// Preconditions — without these the assertions can pass vacuously.
		expect(counts.robots, 'the robots.txt gate leg must have been issued').toBeGreaterThanOrEqual(1);
		expect(counts.probe, 'the stalled fingerprint probe must have been reached').toBeGreaterThanOrEqual(1);

		// THE REGRESSION, as the customer sees it. Read `result.checks` (the CheckResult
		// array) — a `checkStatuses` map belongs to the FORMATTED report shape, and
		// optional-chaining a property the type does not have passes vacuously.
		const takeover = result.checks.find((c) => c.category === 'subdomain_takeover');
		expect(takeover, 'subdomain_takeover must be present in the scan results').toBeDefined();
		expect(takeover!.checkStatus, 'the DNS-derived evidence must not be a per-check timeout casualty').not.toBe('timeout');
		expect(takeover!.checkStatus).toBeUndefined();
		expect(Object.keys(result.score.categoryScores), 'a killed check is EXCLUDED from categoryScores').toContain('subdomain_takeover');

		// The measured evidence survived intact.
		const dangling = takeover!.findings.find((f) => f.title.includes('Dangling CNAME'));
		expect(dangling, 'the DNS-derived dangling-CNAME finding is what the kill used to discard').toBeDefined();
		expect(dangling!.title).toContain(`${DANGLING_LABEL}.${domain}`);

		// The unverified probe is RECORDED, not silently absorbed — and as `info`, which
		// carries a 0 penalty, so honesty here can never move a grade.
		const note = takeover!.findings.find((f) => f.metadata?.inconclusive === true);
		expect(note, 'the cut probe must be reported').toBeDefined();
		expect(note!.severity).toBe('info');
		expect(note!.metadata?.errorKind).toBe('timeout');
		expect(note!.metadata?.missingControl).toBeUndefined();

		// Self-bounded before safeCheck's killer rather than racing it.
		expect(elapsed, `scan took ${elapsed}ms; the probe should have self-bounded at ~${REDUCED_BUDGET_MS}ms`).toBeLessThan(
			REDUCED_PER_CHECK_MS + 1_500,
		);
	}, 20_000);

	it('withholds the clean "no dangling CNAME" verdict when the only probe was cut', async () => {
		// The anti-fabrication case. With nothing else found, the package returns its clean
		// `info` verdict — a claim of absence resting on a probe that never completed. The
		// wrapper must withhold it and exclude the category instead.
		const domain = 'unverified-probe.example.net';
		const counts: LegCounts = { robots: 0, probe: 0 };
		mockNetwork(domain, { withDangling: false }, counts);

		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain(domain, undefined, {
			forceRefresh: true,
			perCheckTimeoutMs: REDUCED_PER_CHECK_MS,
			scanTimeoutMs: 12_000,
		});

		expect(counts.probe, 'the stalled fingerprint probe must have been reached').toBeGreaterThanOrEqual(1);

		const takeover = result.checks.find((c) => c.category === 'subdomain_takeover');
		expect(takeover).toBeDefined();
		expect(
			takeover!.findings.some((f) => f.title.includes('No dangling CNAME')),
			'the clean claim must be withheld',
		).toBe(false);
		expect(takeover!.checkStatus, 'unmeasured → excluded, not passed').toBe('error');
		expect(takeover!.passed).toBe(false);
		expect(takeover!.findings.some((f) => f.metadata?.inconclusive === true)).toBe(true);
		// The contradiction audited by measured-vs-unmeasured-metadata.audit.test.ts.
		expect(takeover!.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		expect(Object.keys(result.score.categoryScores)).not.toContain('subdomain_takeover');
	}, 20_000);

	it('no budget → unchanged: the direct call keeps the package’s silent-timeout semantics', async () => {
		// Byte-for-byte contract for every direct `check_subdomain_takeover` call and every
		// BSL self-host: the probe runs to the package's own fixed 4s timeout (longer than
		// the 3s per-check kill a scan would apply — which is why the scan path lost the
		// category), the failure stays silent, and no inconclusive note is added.
		const domain = 'direct-unbudgeted.example.net';
		const counts: LegCounts = { robots: 0, probe: 0 };
		mockNetwork(domain, { withDangling: false }, counts);

		const { checkSubdomainTakeover } = await import('../src/tools/check-subdomain-takeover');
		const startedAt = Date.now();
		const result = await checkSubdomainTakeover(domain);
		const elapsed = Date.now() - startedAt;

		expect(counts.probe).toBe(1);
		expect(elapsed, `unbudgeted probe ran ${elapsed}ms; the package's own timeout is 4s`).toBeGreaterThan(REDUCED_PER_CHECK_MS);
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.some((f) => f.title.includes('No dangling CNAME'))).toBe(true);
		expect(result.findings.some((f) => f.metadata?.inconclusive === true)).toBe(false);
	}, 20_000);
});

describe('subdomain_takeover fetch budget — argument proof (issue #674)', () => {
	/** Run one scan with `checkSubdomainTakeover` replaced by a spy; hand back its 3rd argument. */
	async function captureTakeoverOptions(perCheckTimeoutMs?: number): Promise<Record<string, unknown>> {
		vi.resetModules();
		const takeover = vi.fn().mockResolvedValue({ ...buildCheckResult('subdomain_takeover', []), passed: true });
		vi.doMock('../src/tools/check-subdomain-takeover', () => ({ checkSubdomainTakeover: takeover }));

		const domain = 'args.example.net';
		const counts: LegCounts = { robots: 0, probe: 0 };
		mockNetwork(domain, { withDangling: false }, counts);

		const { scanDomain } = await import('../src/tools/scan-domain');
		await scanDomain(domain, undefined, { forceRefresh: true, ...(perCheckTimeoutMs ? { perCheckTimeoutMs } : {}) });

		expect(takeover, 'checkSubdomainTakeover spy never fired — the harness short-circuited').toHaveBeenCalled();
		return takeover.mock.calls[0][2] as Record<string, unknown>;
	}

	it('passes a budget DERIVED from the per-check timeout, not a constant', async () => {
		const atThreeSeconds = await captureTakeoverOptions(3_000);
		const atNineSeconds = await captureTakeoverOptions(9_000);

		expect(atThreeSeconds.budgetMs).toBe(fetchBudgetFor(3_000));
		expect(atNineSeconds.budgetMs).toBe(fetchBudgetFor(9_000));
		expect(atThreeSeconds.budgetMs).not.toBe(atNineSeconds.budgetMs);
	}, 20_000);

	it('defaults to the production per-check timeout, and always lands inside it', async () => {
		const options = await captureTakeoverOptions();

		expect(options.budgetMs).toBe(fetchBudgetFor(PER_CHECK_TIMEOUT_MS));
		// Load-bearing: our abort must land BEFORE safeCheck's killer, not race it.
		expect(options.budgetMs as number).toBeLessThan(PER_CHECK_TIMEOUT_MS);
	}, 20_000);
});
