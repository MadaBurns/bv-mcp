// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos A: `scan_domain` under a DNS-over-HTTPS outage.
 *
 * Each `it` is a hypothesis (testing-methodology principle 8): "Given <failure>,
 * the system should <degradation>". When the code does NOT degrade as the
 * hypothesis claims, the test pins the MEASURED behaviour instead and says so
 * in its title with a `FALSIFIED:` prefix. Those tests characterise a known gap:
 * when the fix lands they fail, and the fixer must invert them into the
 * hypothesis they name. Do not "repair" one by weakening its assertion.
 *
 * Boundary: every outbound subrequest goes through the global `fetch`, stubbed
 * here by a router keyed on the DoH resolver plus the query name and type. Nothing
 * under src/ is mocked: the apex probe, all 19 checks, post-processing, the scoring
 * engine, the maturity ladder and the scan cache all run for real. For time, the
 * shipped `perCheckTimeoutMs` knob (resolveScanTimeoutBudget) shrinks the per-check
 * budget in H3 only. The 15s scan budget stays at its production default.
 *
 * Existing coverage, grepped in test/ on 2026-09-24. None of the three hypotheses
 * is covered at this layer, so none is skipped:
 *  - H1: the evidence gate is tested on synthetic results (evidence-gate-safety.spec.ts).
 *    The ungraded post-scoring branches are tested with a MOCKED engine
 *    (scan-domain-ungraded-postscoring.spec.ts). The per-check cache is tested with one
 *    timed-out ssl check (scan-domain.spec.ts "does NOT poison the per-check cache").
 *    No test drives scanDomain with every resolver failing. No test covers the
 *    top-level scan-cache write for an ungraded result.
 *  - H2: dns-transport.spec.ts covers bv-dns and Google as confirmation of an EMPTY
 *    primary answer at the transport. Nothing covers a FAILING primary during a scan.
 *  - H3: scan-domain.spec.ts "preserves partial results when scan times out" hangs the
 *    raw-HTTPS ssl fetch, not a DoH query name, and asserts the timeout conditionally.
 *    No test hangs a single DoH query name.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IN_MEMORY_CACHE, buildScanCacheKey, cacheGet } from '../../src/lib/cache';
import type { CheckCategory } from '../../src/lib/scoring';
import type { ScanDomainResult } from '../../src/tools/scan-domain';
import { setupFetchMock } from '../helpers/dns-mock';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => {
	restore();
	IN_MEMORY_CACHE.clear();
});

// ---------------------------------------------------------------------------
// Network boundary: a fetch router for three DoH resolvers plus the raw-HTTPS probes
// ---------------------------------------------------------------------------

/** The configured bv-dns secondary. Production wires it from BV_DOH_ENDPOINT. */
const BV_DNS_ENDPOINT = 'https://bv-dns.chaos.invalid/dns-query';
const SECONDARY_DOH = { endpoint: BV_DNS_ENDPOINT, token: 'chaos-bv-dns-token' };

type Resolver = 'primary' | 'google' | 'bvdns';

/**
 * How a resolver behaves. `timeout` rejects the fetch with the same
 * DOMException('TimeoutError') that `AbortSignal.timeout` produces in the runtime.
 * That is the boundary shape of a resolver that never answered in time. It fires
 * immediately, so the test does not wait out the real 3s DNS timeout.
 */
type ResolverMode = 'healthy' | 'http503' | 'timeout';

interface DohQuery {
	resolver: Resolver;
	name: string;
	type: string;
}

const TYPE_CODES: Record<string, number> = {
	A: 1,
	NS: 2,
	CNAME: 5,
	SOA: 6,
	PTR: 12,
	MX: 15,
	TXT: 16,
	AAAA: 28,
	SRV: 33,
	DS: 43,
	DNSKEY: 48,
	TLSA: 52,
	SVCB: 64,
	HTTPS: 65,
	CAA: 257,
};

/**
 * A healthy mail-enabled zone. With it, all 19 scan categories complete, so the
 * healthy control scores every category. Any (name, type) not listed here gets an
 * empty NOERROR answer.
 */
function healthyZone(domain: string): Map<string, string[]> {
	return new Map<string, string[]>([
		[`${domain}|NS`, [`ns1.${domain}.`, `ns2.${domain}.`]],
		[`${domain}|SOA`, [`ns1.${domain}. hostmaster.${domain}. 2024010101 7200 3600 1209600 300`]],
		[`${domain}|A`, ['192.0.2.10']],
		[`ns1.${domain}|A`, ['192.0.2.53']],
		[`ns2.${domain}|A`, ['198.51.100.53']],
		[`${domain}|MX`, [`10 mx1.${domain}.`]],
		[`mx1.${domain}|A`, ['192.0.2.25']],
		[`${domain}|TXT`, ['"v=spf1 mx -all"']],
		[`_dmarc.${domain}|TXT`, [`"v=DMARC1; p=reject; rua=mailto:dmarc@${domain}"`]],
		[`default._domainkey.${domain}|TXT`, ['"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"']],
		[`_mta-sts.${domain}|TXT`, ['"v=STSv1; id=20240101"']],
		[`_smtp._tls.${domain}|TXT`, [`"v=TLSRPTv1; rua=mailto:tls@${domain}"`]],
		[`${domain}|CAA`, ['0 issue "letsencrypt.org"']],
	]);
}

function dohAnswer(name: string, type: string, data: string[]): Response {
	const code = TYPE_CODES[type] ?? 0;
	return Response.json({
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name, type: code }],
		Answer: data.map((value) => ({ name, type: code, TTL: 300, data: value })),
	});
}

function resolverOf(url: URL): Resolver | null {
	if (url.hostname === 'cloudflare-dns.com') return 'primary';
	if (url.hostname === 'dns.google') return 'google';
	if (url.origin === new URL(BV_DNS_ENDPOINT).origin) return 'bvdns';
	return null;
}

/** Healthy raw-HTTPS answers for the non-DoH probes (ssl, http_security, the mta_sts policy). */
function webResponse(url: URL, domain: string): Response {
	if (url.hostname === `mta-sts.${domain}` && url.pathname === '/.well-known/mta-sts.txt') {
		return new Response(`version: STSv1\nmode: enforce\nmx: mx1.${domain}\nmax_age: 86400\n`, { status: 200 });
	}
	if (url.pathname === '/robots.txt') return new Response('not found', { status: 404 });
	if (url.hostname === domain || url.hostname === `www.${domain}`) {
		return new Response('<html>ok</html>', {
			status: 200,
			headers: {
				'content-type': 'text/html',
				'strict-transport-security': 'max-age=31536000; includeSubDomains',
				'content-security-policy': "default-src 'self'",
				'x-content-type-options': 'nosniff',
				'x-frame-options': 'DENY',
				'referrer-policy': 'no-referrer',
			},
		});
	}
	return new Response('not found', { status: 404 });
}

/**
 * Install the network. `primary` sets the behaviour of Cloudflare DoH. `fallback`
 * sets bv-dns and Google together. `hangName` makes every query for that one name
 * return a fetch that never settles and ignores its abort signal: a stuck subrequest.
 * Then the per-check race is the only thing that can end the check. A hang that
 * honoured the signal would be cut by the DNS layer's own 3s timeout instead. It
 * would also retry AFTER the test ended, through whatever `fetch` is installed then.
 * Raw-HTTPS probes always answer healthily, so each case isolates the DoH failure.
 */
function installNetwork(opts: { domain: string; primary: ResolverMode; fallback: ResolverMode; hangName?: string }) {
	const queries: DohQuery[] = [];
	let hung = 0;
	const zone = healthyZone(opts.domain);
	globalThis.fetch = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
		const url = new URL(input instanceof Request ? input.url : String(input));
		const resolver = resolverOf(url);
		if (!resolver) return webResponse(url, opts.domain);

		const name = (url.searchParams.get('name') ?? '').replace(/\.$/, '').toLowerCase();
		const type = url.searchParams.get('type') ?? '';
		queries.push({ resolver, name, type });
		if (opts.hangName !== undefined && name === opts.hangName) {
			hung += 1;
			return new Promise<Response>(() => {});
		}
		const mode = resolver === 'primary' ? opts.primary : opts.fallback;
		if (mode === 'http503') return new Response('upstream unavailable', { status: 503 });
		if (mode === 'timeout') throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
		return dohAnswer(name, type, zone.get(`${name}|${type}`) ?? []);
	}) as unknown as typeof fetch;
	return {
		queries,
		hungQueries: () => hung,
		fallbackQueries: () => queries.filter((q) => q.resolver !== 'primary'),
	};
}

// ---------------------------------------------------------------------------
// Result projections
// ---------------------------------------------------------------------------

/** category → checkStatus ('measured' when the check completed normally). */
function statusByCategory(result: ScanDomainResult): Record<string, string> {
	return Object.fromEntries(result.checks.map((c) => [c.category, c.checkStatus ?? 'measured']));
}

function scoredCategories(result: ScanDomainResult): string[] {
	return Object.keys(result.score.categoryScores).sort();
}

function withoutCategory(scores: Record<string, number>, drop: string): Record<string, number> {
	return Object.fromEntries(Object.entries(scores).filter(([category]) => category !== drop));
}

/** Findings that DECLARE a missing control. The abstention shape must never carry this flag. */
function declaredMissingControls(result: ScanDomainResult): string[] {
	return result.checks.flatMap((c) =>
		c.findings.filter((f) => f.metadata?.missingControl === true).map((f) => `${c.category}: ${f.title}`),
	);
}

/** Scan categories that resolve through DoH: everything except the two raw-`fetch` checks. */
async function dnsBackedCategories(): Promise<CheckCategory[]> {
	const { SCAN_CATEGORIES, CHECKS_WITHOUT_DNS_POOL } = await import('../../src/tools/scan-domain');
	return SCAN_CATEGORIES.filter((category) => !CHECKS_WITHOUT_DNS_POOL.has(category));
}

/**
 * DNS-backed categories that do NOT abstain when every DoH query fails (measured
 * 2026-09-24). Each catches its own failed query and returns a COMPLETED result:
 *  - dane_https: packages/dns-checks check-dane-https.ts catch, a `low` finding (score 95)
 *  - svcb_https: packages/dns-checks check-svcb-https.ts catch, a `low` finding (score 95)
 *  - subdomailing: extractSpfIncludeChain swallows the failed SPF lookup. The check then
 *    reads that as "no SPF published" and returns an `info` finding (score 100). Its own
 *    not-assessed catch in check-subdomailing.ts is never reached.
 */
const FAIL_OPEN_UNDER_OUTAGE: ReadonlyArray<{ category: CheckCategory; findingTitle: string }> = [
	{ category: 'dane_https', findingTitle: 'DANE HTTPS query failed' },
	{ category: 'svcb_https', findingTitle: 'HTTPS record query failed' },
	{ category: 'subdomailing', findingTitle: 'No SPF record' },
];

const OUTAGE_MODES: ReadonlyArray<{ label: string; mode: ResolverMode }> = [
	{ label: 'returns HTTP 503', mode: 'http503' },
	{ label: 'times out', mode: 'timeout' },
];

// ---------------------------------------------------------------------------
// H1: total DoH outage
// ---------------------------------------------------------------------------

describe('chaos: scan_domain under a total DoH outage (H1)', () => {
	const domain = 'example.org';

	it.each(OUTAGE_MODES)(
		'Given every DoH resolver $label for every query, scan_domain should abstain: ungraded (displayGradeFor null, never an F), maturity indeterminate, no declared missingControl, and each abstaining DNS-backed category errored and absent from categoryScores',
		async ({ mode }) => {
			const net = installNetwork({ domain, primary: mode, fallback: mode });
			const { scanDomain } = await import('../../src/tools/scan-domain');
			const { displayGradeFor } = await import('../../src/lib/ungraded-display');

			const result = await scanDomain(domain, undefined, { secondaryDoh: SECONDARY_DOH });

			// Positive control: the scan really probed DNS and nothing answered.
			expect(net.queries.length).toBeGreaterThan(0);

			expect(result.score.overall).toBeNull();
			expect(result.score.grade).toBeNull();
			expect(displayGradeFor(result.score)).toBeNull();
			expect(result.score.evidenceInsufficient).toBe(true);
			expect(result.maturity.indeterminate).toBe(true);
			expect(declaredMissingControls(result)).toEqual([]);

			const failOpen = new Set<string>(FAIL_OPEN_UNDER_OUTAGE.map((entry) => entry.category));
			const abstaining = (await dnsBackedCategories()).filter((category) => !failOpen.has(category));
			const statuses = statusByCategory(result);
			const scored = new Set(scoredCategories(result));
			const observed = Object.fromEntries(
				abstaining.map((category) => [
					category,
					{
						status: statuses[category],
						passed: result.checks.find((c) => c.category === category)?.passed,
						inCategoryScores: scored.has(category),
					},
				]),
			);
			const expected = Object.fromEntries(
				abstaining.map((category) => [category, { status: 'error', passed: false, inCategoryScores: false }]),
			);
			expect(observed).toEqual(expected);
		},
	);

	it('FALSIFIED: Given every DoH resolver fails, dane_https, svcb_https and subdomailing should abstain like the other DNS-backed checks. Instead they report COMPLETED (no checkStatus), are scored into categoryScores, and count as measured evidence', async () => {
		installNetwork({ domain, primary: 'http503', fallback: 'http503' });
		const { scanDomain, SCAN_CATEGORIES, CHECKS_WITHOUT_DNS_POOL } = await import('../../src/tools/scan-domain');

		const result = await scanDomain(domain, undefined, { secondaryDoh: SECONDARY_DOH });

		const statuses = statusByCategory(result);
		const scored = new Set(scoredCategories(result));
		for (const { category, findingTitle } of FAIL_OPEN_UNDER_OUTAGE) {
			const check = result.checks.find((c) => c.category === category);
			expect(statuses[category], `${category} checkStatus`).toBe('measured');
			expect(scored.has(category), `${category} in categoryScores`).toBe(true);
			expect(result.score.categoryScores[category], `${category} score`).toBeGreaterThan(0);
			expect(check?.findings.map((f) => f.title)).toContain(findingTitle);
		}

		// Completed evidence = the two raw-fetch checks plus the three that failed open.
		// The rest of the matrix abstained, so the evidence gate still withholds the grade.
		// That gate is the only reason this outage does not publish a score.
		const completed = CHECKS_WITHOUT_DNS_POOL.size + FAIL_OPEN_UNDER_OUTAGE.length;
		expect(result.score.evidence).toEqual({
			attempted: SCAN_CATEGORIES.length,
			completed,
			ratio: completed / SCAN_CATEGORIES.length,
		});
	});

	it('Given every DoH resolver fails, scan_domain should NOT write the ungraded result to the 5-min scan cache, so a second call re-probes DNS instead of replaying the outage verdict', async () => {
		const net = installNetwork({ domain, primary: 'http503', fallback: 'http503' });
		const { scanDomain } = await import('../../src/tools/scan-domain');

		const first = await scanDomain(domain, undefined, { secondaryDoh: SECONDARY_DOH });
		expect(first.cached).toBe(false);
		expect(first.score.overall).toBeNull();
		const queriesAfterFirst = net.queries.length;
		expect(queriesAfterFirst).toBeGreaterThan(0);

		// The ungraded outage result must NOT have been admitted to the top-level scan key.
		const stored = await cacheGet<ScanDomainResult>(buildScanCacheKey(domain));
		expect(stored).toBeUndefined();

		// ...so the next call within the TTL re-probes DNS instead of replaying the outage.
		const second = await scanDomain(domain, undefined, { secondaryDoh: SECONDARY_DOH });
		expect(second.cached).toBe(false);
		expect(net.queries.length).toBeGreaterThan(queriesAfterFirst);
	});
});

// ---------------------------------------------------------------------------
// H2: the primary resolver fails but the fallback resolvers answer
// ---------------------------------------------------------------------------

describe('chaos: scan_domain when only the primary DoH resolver fails (H2)', () => {
	const domain = 'example.net';

	it('FALSIFIED: Given the primary DoH resolver returns 5xx while the fallbacks (bv-dns, Google) answer, scan_domain should score the same categories as a healthy run. Instead it never queries a fallback and degrades exactly like a total outage: ungraded, with the DNS-backed categories errored', async () => {
		const { scanDomain, SCAN_CATEGORIES } = await import('../../src/tools/scan-domain');

		// Healthy control, in the same test and against the same zone fixture.
		installNetwork({ domain, primary: 'healthy', fallback: 'healthy' });
		const healthy = await scanDomain(domain, undefined, { secondaryDoh: SECONDARY_DOH });
		expect(typeof healthy.score.overall).toBe('number');
		expect(scoredCategories(healthy)).toEqual([...SCAN_CATEGORIES].sort());

		IN_MEMORY_CACHE.clear();
		const net = installNetwork({ domain, primary: 'http503', fallback: 'healthy' });
		const degraded = await scanDomain(domain, undefined, { secondaryDoh: SECONDARY_DOH });

		// The measured cause. Scan context sets `skipSecondaryConfirmation: true`
		// (scan-domain.ts). Even without that flag, dns-transport.ts consults bv-dns or
		// Google only to confirm an EMPTY primary answer. It never fails over from a
		// primary that returned 5xx or timed out.
		expect(net.queries.filter((q) => q.resolver === 'primary').length).toBeGreaterThan(0);
		expect(net.fallbackQueries()).toEqual([]);

		// The degradation: an outage scan, not a healthy one.
		expect(degraded.score.overall).toBeNull();
		expect(scoredCategories(degraded)).not.toEqual(scoredCategories(healthy));
		const statuses = statusByCategory(degraded);
		for (const category of ['spf', 'dmarc', 'dkim', 'dnssec', 'mx', 'ns', 'caa'] as const) {
			expect(statuses[category], `${category} checkStatus`).toBe('error');
			expect(degraded.score.categoryScores, `${category} in categoryScores`).not.toHaveProperty(category);
		}
	});
});

// ---------------------------------------------------------------------------
// H3: exactly one check's DoH query hangs past the per-check budget
// ---------------------------------------------------------------------------

describe('chaos: scan_domain when one check’s DoH query hangs (H3)', () => {
	const domain = 'example.com';
	/**
	 * BIMI's selector record. It is read by the bimi check only: hanging it leaves every
	 * other category byte-identical to the healthy control (measured). A shared name
	 * would not isolate one check. For example, `_smtp._tls.<domain>` is also read by
	 * mta_sts, so hanging it times out both tlsrpt AND mta_sts.
	 */
	const hungName = `default._bimi.${domain}`;
	/** Shrunk via the shipped knob so the test waits 2s, not the 8s default. */
	const perCheckTimeoutMs = 2_000;

	it('Given exactly one check’s DoH query (bimi) hangs past the per-check budget, scan_domain should finish inside the 15s scan budget with only bimi marked timeout by its per-check budget, and every other category scored exactly as in a healthy run', async () => {
		const { scanDomain } = await import('../../src/tools/scan-domain');
		const { resolveScanTimeoutBudget } = await import('../../src/tools/scan/timeouts');
		const options = { secondaryDoh: SECONDARY_DOH, perCheckTimeoutMs };
		const { scanTimeoutMs } = resolveScanTimeoutBudget(options);

		// Healthy control, in the same test and with the same options.
		installNetwork({ domain, primary: 'healthy', fallback: 'healthy' });
		const healthy = await scanDomain(domain, undefined, options);
		expect(typeof healthy.score.overall).toBe('number');
		expect(healthy.score.categoryScores).toHaveProperty('bimi');

		IN_MEMORY_CACHE.clear();
		const net = installNetwork({ domain, primary: 'healthy', fallback: 'healthy', hangName: hungName });
		const started = Date.now();
		const result = await scanDomain(domain, undefined, options);
		const elapsed = Date.now() - started;

		// Positive control: the hang was actually hit.
		expect(net.hungQueries()).toBeGreaterThan(0);

		// The scan finished inside its budget, and the per-check budget cut the check.
		// If the per-check guard were missing, only the scan-level timer could end it.
		expect(elapsed).toBeLessThan(scanTimeoutMs);
		const bimi = result.checks.find((c) => c.category === 'bimi');
		expect(bimi?.checkStatus).toBe('timeout');
		expect(bimi?.passed).toBe(false);
		expect(bimi?.findings.map((f) => f.detail).join(' ')).toContain('per-check time limit');
		expect(result.score.categoryScores).not.toHaveProperty('bimi');

		// Exactly one abstention. Every other category matches the healthy control.
		const statuses = statusByCategory(result);
		expect(Object.entries(statuses).filter(([, status]) => status !== 'measured')).toEqual([['bimi', 'timeout']]);
		expect(result.score.categoryScores).toEqual(withoutCategory(healthy.score.categoryScores, 'bimi'));
		expect(typeof result.score.overall).toBe('number');
	}, 30_000);
});
