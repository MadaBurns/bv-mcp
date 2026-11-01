// SPDX-License-Identifier: BUSL-1.1

/**
 * US-16 T10 (SQ-484): scan_domain's NON-SCORING `webPosture` section.
 *
 * The load-bearing test is the negative control: the SAME mocked DNS/HTTP fixture is scanned with
 * the `WEB_POSTURE_ENABLED` kill switch on and off, and score, grade, category scores, finding
 * counts and evidence must be identical, while the "on" run carries web posture findings that
 * would have moved the score had they been scored.
 *
 * SQ-487: the section is opt-in (`webPosture: true`, passed only by the scan_domain tool), starts
 * after the scored fan-out, holds at most 2 fetches at once, and never holds the scored result more
 * than WEB_POSTURE_GRACE_MS past scored completion.
 *
 * Only modules that exist without this change are imported statically, so reverting the source
 * fails these tests on their assertions rather than at collection.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, createDohResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { INFLIGHT_CLEANUP_MS } from '../src/lib/config';
import { buildCheckResult, createFinding } from '../src/lib/scoring';
import type { CheckResult } from '../src/lib/scoring';
import type { ScanDomainResult } from '../src/tools/scan-domain';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => {
	restore();
	IN_MEMORY_CACHE.clear();
});

const DOMAIN = 'example.com';
const DAY_MS = 86_400_000;
const WEB_CATEGORIES = ['web_content', 'csp_quality', 'hsts_preload', 'http_redirect', 'security_txt', 'cert_posture'];
const HEADING = 'Not graded: web posture';

const PAGE_HTML =
	'<html><head><script src="https://cdn.example.net/app.js"></script></head>' +
	'<body><img src="http://img.example.net/a.png"><a href="http://partner.example.org/">partner</a></body></html>';

function pageHeaders(): Headers {
	const headers = new Headers({
		'content-type': 'text/html; charset=utf-8',
		'content-security-policy': "default-src 'self' 'unsafe-inline'; script-src *",
		'strict-transport-security': 'max-age=300',
	});
	headers.append('set-cookie', 'sid=abc123; Path=/');
	return headers;
}

function urlOf(input: string | URL | Request): string {
	return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
}

function dohAnswer(url: string): Response {
	if (url.includes('type=TXT') || url.includes('type=16')) {
		if (url.includes('_dmarc.')) return txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']);
		if (url.includes('_domainkey.')) return txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']);
		if (url.includes('_mta-sts.')) return txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']);
		return txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']);
	}
	if (url.includes('type=NS') || url.includes('type=2&')) return nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']);
	if (url.includes('type=CAA') || url.includes('type=257')) return caaResponse('example.com', ['0 issue "letsencrypt.org"']);
	if (url.includes('type=A&') || url.endsWith('type=A') || url.includes('type=1&')) return dnssecResponse('example.com', true);
	return createDohResponse([], []);
}

/** Rejects only when the request is aborted, like a real fetch to a server that never answers. */
function hangUntilAborted(signal: AbortSignal | null | undefined): Promise<Response> {
	return new Promise((_, reject) => {
		const fail = () => reject(signal?.reason ?? new DOMException('aborted', 'AbortError'));
		if (signal?.aborted) fail();
		signal?.addEventListener('abort', fail, { once: true });
	});
}

interface SiteOptions {
	/** Every request to the scanned apex/www hangs until aborted. */
	hang?: boolean;
	/** Location for the plain-HTTP redirect (default: the same URL over https). */
	httpRedirectTo?: string;
	/** Requests only the section makes (www host, hstspreload.org, security.txt) never settle, even when aborted. */
	sectionOnlyNeverAnswers?: boolean;
}

function installSite(options: SiteOptions = {}) {
	const mock = vi.fn((input: string | URL | Request, init?: RequestInit) => {
		const url = urlOf(input);
		if (url.includes('cloudflare-dns.com') || url.includes('dns.google')) return Promise.resolve(dohAnswer(url));
		if (options.sectionOnlyNeverAnswers && isSectionOnlyRequest(url)) return new Promise<Response>(() => {});
		const { hostname, pathname, protocol } = new URL(url);
		if (options.hang && (hostname === DOMAIN || hostname === `www.${DOMAIN}`)) {
			return hangUntilAborted(init?.signal ?? (input instanceof Request ? input.signal : undefined));
		}
		if (hostname === 'hstspreload.org') return Promise.resolve(Response.json({ name: DOMAIN, status: 'unknown' }));
		if (hostname.startsWith('mta-sts.')) {
			return Promise.resolve(new Response('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400', { status: 200 }));
		}
		if (pathname === '/robots.txt' || pathname.startsWith('/.well-known/'))
			return Promise.resolve(new Response('not found', { status: 404 }));
		if (protocol === 'http:') {
			const location = options.httpRedirectTo ?? url.replace(/^http:/, 'https:');
			return Promise.resolve(new Response(null, { status: 301, headers: { location } }));
		}
		return Promise.resolve(new Response(PAGE_HTML, { status: 200, headers: pageHeaders() }));
	});
	globalThis.fetch = mock as unknown as typeof fetch;
	return mock;
}

function isoFromNow(ms: number): string {
	return new Date(Date.now() + ms).toISOString();
}

/** A bv-ct-index /cert-meta body: issuer is a bare CN, coverage is the owned forward-from index. */
function certMetaRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		domain: DOMAIN,
		issuer: 'R11',
		firstSeen: isoFromNow(-85 * DAY_MS),
		notBefore: isoFromNow(-85 * DAY_MS),
		notAfter: isoFromNow(5 * DAY_MS),
		wildcard: false,
		serial: '0abc',
		keyType: 'rsa',
		keyBits: 1024,
		sigAlg: 'sha256WithRSAEncryption',
		sanCount: 2,
		coverage: {
			source: 'bv-ct-index',
			indexStartedAt: isoFromNow(-30 * DAY_MS),
			freshThrough: isoFromNow(-10 * 60_000),
			historyWindow: 'forward-from',
			truncated: false,
		},
		...overrides,
	};
}

function certstreamBinding(body: Record<string, unknown>): { fetch: typeof fetch } {
	return { fetch: vi.fn(async () => Response.json(body)) as unknown as typeof fetch };
}

async function scan(options: Record<string, unknown> = {}): Promise<ScanDomainResult> {
	const { scanDomain } = await import('../src/tools/scan-domain');
	return scanDomain(DOMAIN, undefined, { forceRefresh: true, ...options });
}

/** A scan that opts in to the section, as the scan_domain tool handler does. */
function scanWithSection(options: Record<string, unknown> = {}): Promise<ScanDomainResult> {
	return scan({ webPosture: true, ...options });
}

/**
 * URLs only the web posture section requests: the www homepage GET, hstspreload.org and
 * security.txt. (The scored subdomain_takeover check does probe the www host, but as
 * `https://www.example.com` with no path, so that exact homepage URL stays section-only.)
 */
function isSectionOnlyRequest(url: string): boolean {
	const { hostname, pathname } = new URL(url);
	return url === `https://www.${DOMAIN}/` || hostname === 'hstspreload.org' || pathname === '/.well-known/security.txt';
}

function isDohRequest(url: string): boolean {
	return url.includes('cloudflare-dns.com') || url.includes('dns.google');
}

/** Everything the score is made of: these must not move when the web posture section runs. */
async function scoredView(result: ScanDomainResult) {
	const { buildStructuredScanResult } = await import('../src/tools/scan-domain');
	const structured = buildStructuredScanResult(result);
	return {
		overall: result.score.overall,
		grade: result.score.grade,
		categoryScores: result.score.categoryScores,
		findingCounts: structured.findingCounts,
		evidence: result.score.evidence,
		findings: result.score.findings.map((f) => `${f.category}|${f.severity}|${f.title}`),
		checkCategories: result.checks.map((c) => c.category),
	};
}

function webResult(result: ScanDomainResult, category: string): CheckResult | undefined {
	return result.webPosture?.results.find((r) => r.category === category);
}

describe('scan_domain webPosture — negative control: non-scoring holds end to end', () => {
	it('score, grade, categoryScores, findingCounts and evidence are identical with the kill switch on vs off', async () => {
		const mock = installSite();
		const apexGets = () => mock.mock.calls.filter(([input]) => urlOf(input) === 'https://example.com/').length;
		const certstream = certstreamBinding(certMetaRow());
		const on = await scan({ certstream, webPosture: true, webPostureEnabled: true });
		const onApexGets = apexGets();
		IN_MEMORY_CACHE.clear();
		const off = await scan({ certstream, webPosture: true, webPostureEnabled: false });
		const offApexGets = apexGets() - onApexGets;

		// One shared homepage GET serves web_content, csp_quality and hsts_preload. The other two
		// section requests to that URL are http_redirect's own walks (the https:// chain start, and the
		// http:// chain's hop), which by design ignore `pages`. Unshared pages would make this 5.
		expect(onApexGets - offApexGets).toBe(3);

		// The section ran, is flagged non-scoring, and carries real issues that WOULD move a score.
		expect(on.webPosture?.nonScoring).toBe(true);
		expect(on.webPosture?.results.map((r) => r.category)).toEqual(WEB_CATEGORIES);
		const webIssues = on.webPosture!.results.flatMap((r) => r.findings).filter((f) => f.severity !== 'info');
		expect(webIssues.some((f) => f.severity === 'high')).toBe(true);
		expect(webIssues.length).toBeGreaterThanOrEqual(3);
		expect(off.webPosture).toBeUndefined();

		const onView = await scoredView(on);
		const offView = await scoredView(off);
		console.info('[SQ-484 negative control]', JSON.stringify({ on: onView, off: offView, webIssues: webIssues.length }));
		expect(onView.overall).not.toBeNull();
		expect(onView).toEqual(offView);
		// No web posture category leaks into the scored structures.
		for (const category of WEB_CATEGORIES) {
			expect(onView.checkCategories).not.toContain(category);
			expect(Object.keys(on.score.categoryScores)).not.toContain(category);
			expect(on.score.findings.some((f) => f.category === category)).toBe(false);
		}
	});

	it('a hanging homepage leaves the scored result unchanged and marks the web checks not assessed', async () => {
		installSite({ hang: true });
		const budget = { scanTimeoutMs: 6_000, perCheckTimeoutMs: 1_000 };
		const on = await scan({ ...budget, webPosture: true, webPostureEnabled: true });
		IN_MEMORY_CACHE.clear();
		const off = await scan({ ...budget, webPosture: true, webPostureEnabled: false });

		expect(await scoredView(on)).toEqual(await scoredView(off));
		expect(on.webPosture?.results.map((r) => r.category)).toEqual(WEB_CATEGORIES);
		for (const result of on.webPosture!.results) {
			expect(['timeout', 'error'], `${result.category} must not read as completed`).toContain(result.checkStatus);
			expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
			expect(result.findings.some((f) => f.metadata?.notAssessed === true)).toBe(true);
		}
		// The homepage-dependent checks were cut off, by the section deadline (fetchBudgetFor(1000) =
		// 1000 ms) or by the grace after the score was ready, whichever came first.
		expect(webResult(on, 'web_content')?.checkStatus).toBe('timeout');
		expect(webResult(on, 'http_redirect')?.checkStatus).toBe('timeout');
	});
});

/** The real setTimeout, captured before any test fakes timers. */
const realSetTimeout = globalThis.setTimeout.bind(globalThis);

function realTurn(): Promise<void> {
	return new Promise((resolve) => {
		realSetTimeout(resolve, 0);
	});
}

/**
 * Drive `promise` under fake timers: give every chain that is not waiting on a timer a few real
 * turns to run, then advance fake time by `stepMs`, until it settles. Returns the fake clock reading
 * at the moment it settled.
 */
async function settleUnderFakeTime<T>(promise: Promise<T>, stepMs: number, limitMs = 20_000): Promise<{ value: T; settledAt: number }> {
	let settledAt: number | undefined;
	const tracked = promise.then((value) => {
		settledAt = Date.now();
		return value;
	});
	const start = Date.now();
	while (settledAt === undefined && Date.now() - start < limitMs) {
		for (let turn = 0; turn < 3 && settledAt === undefined; turn++) await realTurn();
		if (settledAt === undefined) await vi.advanceTimersByTimeAsync(stepMs);
	}
	return { value: await tracked, settledAt: settledAt ?? Number.NaN };
}

describe('scan_domain webPosture — never delays or starves the scored result (SQ-487)', () => {
	afterEach(() => vi.useRealTimers());

	it('a section host that never answers holds the result at most WEB_POSTURE_GRACE_MS past scored completion', async () => {
		const { WEB_POSTURE_GRACE_MS } = await import('../src/tools/scan/web-posture');
		// The scored reference runs against the answering site: scored checks never request the
		// section-only URLs, so their results match, and nothing is left hanging under real timers.
		installSite();
		const off = await scan();
		IN_MEMORY_CACHE.clear();
		installSite({ sectionOnlyNeverAnswers: true });

		const STEP_MS = 10;
		let scoredAt: number | undefined;
		// scanDomain emits this once the scored fan-out has settled: the scored-completion anchor.
		const analytics = {
			emitDohPrimarySummary: () => {
				scoredAt = Date.now();
			},
		};
		vi.useFakeTimers();
		const startedAt = Date.now();
		const { value: on, settledAt } = await settleUnderFakeTime(scanWithSection({ analytics }), STEP_MS);
		const timing = { scoredMs: (scoredAt ?? Number.NaN) - startedAt, resolvedMs: settledAt - startedAt };
		console.info('[SQ-487 latency]', JSON.stringify({ ...timing, graceMs: WEB_POSTURE_GRACE_MS }));

		// The checks left running hold per-check in-flight entries that never settle (their fetches
		// ignore aborts). Let fake time pass their cleanup so later tests on this domain cannot join them.
		await vi.advanceTimersByTimeAsync(INFLIGHT_CLEANUP_MS + 1_000);

		// Before SQ-487 the result waited for the section's own deadline: 7250 ms at the default budget.
		// The bound is the ticket's 750 ms literal, so it measures the timing even without the constant.
		const CONTRACT_GRACE_MS = 750;
		expect(timing.resolvedMs - timing.scoredMs).toBeLessThanOrEqual(CONTRACT_GRACE_MS + 10 * STEP_MS);
		expect(WEB_POSTURE_GRACE_MS).toBe(CONTRACT_GRACE_MS);
		expect(await scoredView(on)).toEqual(await scoredView(off));
		expect(on.webPosture?.results.map((r) => r.category)).toEqual(WEB_CATEGORIES);
		for (const category of ['web_content', 'csp_quality', 'hsts_preload']) {
			const result = webResult(on, category);
			expect(result?.checkStatus, category).toBe('timeout');
			expect(
				result?.findings.some((f) => f.metadata?.notAssessed === true && f.metadata?.notAssessedReason === 'deadline'),
				category,
			).toBe(true);
			expect(
				result?.findings.every((f) => f.severity === 'info'),
				category,
			).toBe(true);
		}
	});

	it('never has more than WEB_POSTURE_MAX_CONCURRENT_FETCHES section fetches in flight', async () => {
		const site = installSite();
		let inFlight = 0;
		let maxInFlight = 0;
		let sectionFetches = 0;
		globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
			if (isDohRequest(urlOf(input))) return site(input, init);
			sectionFetches++;
			inFlight++;
			maxInFlight = Math.max(maxInFlight, inFlight);
			try {
				await new Promise((resolve) => setTimeout(resolve, 5));
				return await site(input, init);
			} finally {
				inFlight--;
			}
		}) as typeof fetch;
		const { startWebPosture, WEB_POSTURE_MAX_CONCURRENT_FETCHES } = await import('../src/tools/scan/web-posture');

		const section = await startWebPosture(DOMAIN).section;
		console.info('[SQ-487 concurrency]', JSON.stringify({ sectionFetches, maxInFlight }));

		expect(section.results.map((r) => r.category)).toEqual(WEB_CATEGORIES);
		expect(sectionFetches).toBeGreaterThan(WEB_POSTURE_MAX_CONCURRENT_FETCHES);
		expect(maxInFlight).toBe(WEB_POSTURE_MAX_CONCURRENT_FETCHES);
	});

	it('runs only for a caller that opts in: without webPosture: true a scan makes zero section requests', async () => {
		const mock = installSite();
		const sectionRequests = () => mock.mock.calls.filter(([input]) => isSectionOnlyRequest(urlOf(input))).length;
		const plain = await scan();
		const withoutOptIn = sectionRequests();
		IN_MEMORY_CACHE.clear();
		const optedIn = await scanWithSection();
		const withOptIn = sectionRequests() - withoutOptIn;
		console.info('[SQ-487 caller control]', JSON.stringify({ withoutOptIn, withOptIn }));

		expect(plain.webPosture).toBeUndefined();
		expect(withoutOptIn).toBe(0);
		// Negative control: the same scan with the opt-in does make section requests.
		expect(withOptIn).toBeGreaterThan(0);
		expect(optedIn.webPosture?.results).toHaveLength(6);
		expect(await scoredView(plain)).toEqual(await scoredView(optedIn));
	});

	it('at the tool boundary only scan_domain runs it: batch_scan makes zero section requests', async () => {
		const mock = installSite();
		const count = (predicate: (url: string) => boolean) => mock.mock.calls.filter(([input]) => predicate(urlOf(input))).length;
		const { handleToolsCall } = await import('../src/handlers/tools');

		const batch = (await handleToolsCall({ name: 'batch_scan', arguments: { domains: [DOMAIN], force_refresh: true } }, undefined, {})) as {
			isError?: boolean;
		};
		const batchSection = count(isSectionOnlyRequest);
		const batchDns = count(isDohRequest);
		IN_MEMORY_CACHE.clear();
		await handleToolsCall({ name: 'scan_domain', arguments: { domain: DOMAIN, force_refresh: true } }, undefined, {});
		const scanDomainSection = count(isSectionOnlyRequest) - batchSection;
		console.info('[SQ-487 tool boundary]', JSON.stringify({ batchScan: batchSection, scanDomain: scanDomainSection }));

		// batch_scan really scanned (its scored checks made DNS queries), yet made no section request.
		expect(batch.isError).toBeFalsy();
		expect(batchDns).toBeGreaterThan(0);
		expect(batchSection).toBe(0);
		expect(scanDomainSection).toBeGreaterThan(0);
	});

	it('scan_domain rescans rather than replay an entry cached without the section; other callers never get one', async () => {
		installSite();
		const { scanDomain } = await import('../src/tools/scan-domain');

		// e.g. compare_baseline: no opt-in, so the cached entry has no section.
		const plain = await scanDomain(DOMAIN, undefined, {});
		expect(plain.webPosture).toBeUndefined();

		const optedIn = await scanDomain(DOMAIN, undefined, { webPosture: true });
		expect(optedIn.cached).toBe(false);
		expect(optedIn.webPosture?.results).toHaveLength(6);
		expect(optedIn.score).toEqual(plain.score);

		const hit = await scanDomain(DOMAIN, undefined, { webPosture: true });
		expect(hit.cached).toBe(true);
		expect(hit.webPosture).toEqual(optedIn.webPosture);

		// The entry now carries the section, but a caller that did not opt in has it stripped.
		const other = await scanDomain(DOMAIN, undefined, {});
		expect(other.cached).toBe(true);
		expect(other.webPosture).toBeUndefined();
		expect(other.score).toEqual(optedIn.score);
	});
});

describe('scan_domain webPosture — http_redirect cause is never blamed on the target (SQ-489)', () => {
	afterEach(() => {
		vi.useRealTimers();
		vi.restoreAllMocks();
	});

	const SECTION_DEADLINE_MS = 7_250;
	const delay = (ms: number): Promise<void> =>
		new Promise((resolve) => {
			setTimeout(resolve, ms);
		});

	/** `AbortSignal.timeout` runs on the platform clock; put it on the fake one so queue wait can be simulated. */
	function timeoutSignalsOnFakeClock(): void {
		vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms: number) => {
			const controller = new AbortController();
			setTimeout(() => controller.abort(new DOMException('The operation timed out.', 'TimeoutError')), ms);
			return controller.signal;
		});
	}

	/** Wrap the site stub: each URL `rule` names answers after its delay, or throws its error. */
	function withRules(rule: (url: string) => { ms?: number; fail?: Error } | undefined, siteOptions: SiteOptions = {}): void {
		const site = installSite(siteOptions);
		globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
			const url = urlOf(input);
			const applied = isDohRequest(url) ? undefined : rule(url);
			// Like a real fetch: an already-aborted signal rejects at once, and an abort ends the wait.
			init?.signal?.throwIfAborted();
			if (applied?.ms) await delay(applied.ms);
			init?.signal?.throwIfAborted();
			if (applied?.fail) throw applied.fail;
			return site(input, init);
		}) as typeof fetch;
	}

	const redirectResult = (section: { results: CheckResult[] }): CheckResult => section.results.find((r) => r.category === 'http_redirect')!;

	it('a hop that waited in the shared fetch queue is still measured: all four chains end final', async () => {
		timeoutSignalsOnFakeClock();
		// Two slots are held for 6 s by a slow security.txt and a slow hstspreload.org status call, both queued
		// ahead of the redirect hops that follow the first response. Every redirect hop itself answers in 50 ms.
		const SLOW_MS = 6_000;
		withRules((url) => {
			const { hostname, pathname } = new URL(url);
			return { ms: hostname === 'hstspreload.org' || pathname === '/.well-known/security.txt' ? SLOW_MS : 50 };
		});
		const { startWebPosture } = await import('../src/tools/scan/web-posture');
		vi.useFakeTimers();
		const { value: section } = await settleUnderFakeTime(startWebPosture(DOMAIN, { deadlineMs: SECTION_DEADLINE_MS }).section, 10, 30_000);

		const redirects = redirectResult(section);
		expect(redirects.metadata).toMatchObject({
			apex: { http: { end: 'final' }, https: { end: 'final' } },
			www: { http: { end: 'final' }, https: { end: 'final' } },
		});
		expect(redirects.findings.some((f) => f.metadata?.errorKind === 'chain_interrupted' || f.metadata?.cause === 'deadline')).toBe(false);
		expect(redirects.checkStatus).not.toBe('timeout');
		// security.txt waited as long and is held to the same rule: answered (404 -> absent), not a self-inflicted abort.
		expect(section.results.find((r) => r.category === 'security_txt')?.findings.some((f) => f.metadata?.inconclusive === true)).toBe(false);
	});

	it('a follow-up hop that refuses the connection ends the chain as a network failure, not a deadline', async () => {
		withRules((url) => (url === 'https://example.com/landing' ? { fail: new TypeError('fetch failed') } : undefined), {
			httpRedirectTo: 'https://example.com/landing',
		});
		const { startWebPosture } = await import('../src/tools/scan/web-posture');
		const section = await startWebPosture(DOMAIN, { deadlineMs: SECTION_DEADLINE_MS }).section;

		const finding = redirectResult(section).findings.find((f) => f.title === 'Redirect chain not fully assessed (apex)');
		expect(finding?.detail).toContain('failed with a network or TLS error');
		expect(finding?.detail).not.toContain('time limit');
		expect(finding?.metadata).toMatchObject({ inconclusive: true, errorKind: 'chain_interrupted', cause: 'network' });
		expect(redirectResult(section).metadata).toMatchObject({ apex: { http: { end: 'interrupted' } } });
	});

	it('the section deadline firing mid-walk is "not assessed within the time limit", never the target failing', async () => {
		timeoutSignalsOnFakeClock();
		const site = installSite({ httpRedirectTo: 'https://example.com/landing' });
		globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
			const url = urlOf(input);
			if (url === 'https://example.com/landing') return hangUntilAborted(init?.signal);
			return site(input, init);
		}) as typeof fetch;
		const { startWebPosture } = await import('../src/tools/scan/web-posture');
		vi.useFakeTimers();
		const { value: section } = await settleUnderFakeTime(startWebPosture(DOMAIN, { deadlineMs: 1_000 }).section, 10, 30_000);

		const redirects = redirectResult(section);
		const detail = redirects.findings.map((f) => f.detail).join('\n');
		expect(detail).toContain('time limit');
		expect(detail).not.toMatch(/failed|could not be fetched/);
		expect(redirects.findings.every((f) => f.severity === 'info' && f.metadata?.missingControl === undefined)).toBe(true);
	});
});

describe('scan_domain webPosture — cert_posture from BV_CERTSTREAM /cert-meta', () => {
	it('maps a CN-only issuer ("R11") to Let\'s Encrypt and compares it with CAA', async () => {
		installSite();
		const result = await scanWithSection({ certstream: certstreamBinding(certMetaRow()) });
		const cert = webResult(result, 'cert_posture');
		expect(cert?.checkStatus ?? 'completed').toBe('completed');
		const caa = cert?.findings.find((f) => f.metadata?.caaOutcome !== undefined);
		expect(caa?.metadata?.issuingCa).toBe('letsencrypt');
		expect(caa?.metadata?.caaOutcome).toBe('honoured');
		// keyType/keyBits from CERT_DETAILS are banded; 1024-bit RSA is weak.
		expect(cert?.findings.some((f) => f.metadata?.keyStrengthBand === 'weak')).toBe(true);
	});

	it('an unmapped CN stays not assessed, never an unauthorised-CA mismatch', async () => {
		installSite();
		const result = await scanWithSection({ certstream: certstreamBinding(certMetaRow({ issuer: 'Example Private Issuing CA 7' })) });
		const findings = webResult(result, 'cert_posture')?.findings ?? [];
		const caa = findings.find((f) => f.metadata?.caaOutcome !== undefined);
		expect(caa?.metadata?.caaOutcome).toBe('unmapped');
		expect(caa?.metadata?.notAssessed).toBe(true);
		expect(findings.some((f) => f.metadata?.caaOutcome === 'unauthorised')).toBe(false);
	});

	it('no exact-name row in the forward-from index is not assessed, never "no certificate"', async () => {
		installSite();
		const noRow = certMetaRow({
			issuer: null,
			firstSeen: null,
			notBefore: null,
			notAfter: null,
			keyType: null,
			keyBits: null,
			sigAlg: null,
		});
		const cert = webResult(await scanWithSection({ certstream: certstreamBinding(noRow) }), 'cert_posture');
		expect(cert?.checkStatus).toBe('error');
		expect(cert?.findings.every((f) => f.metadata?.notAssessed === true)).toBe(true);
	});

	it('a stale index answer is not assessed (a renewal it has not seen must not read as expiring)', async () => {
		installSite();
		const stale = certMetaRow({ coverage: { ...(certMetaRow().coverage as object), freshThrough: isoFromNow(-2 * DAY_MS) } });
		const cert = webResult(await scanWithSection({ certstream: certstreamBinding(stale) }), 'cert_posture');
		expect(cert?.checkStatus).toBe('error');
		expect(cert?.findings.every((f) => f.metadata?.notAssessed === true)).toBe(true);
	});

	it('without the binding cert_posture abstains', async () => {
		installSite();
		const cert = webResult(await scanWithSection(), 'cert_posture');
		expect(cert?.checkStatus).toBe('error');
		expect(cert?.findings.every((f) => f.metadata?.notAssessed === true)).toBe(true);
	});
});

describe('scan_domain webPosture — fetch routing', () => {
	it('fetches plain HTTP to the scanned host raw but refuses a plain-HTTP hop to a foreign host', async () => {
		const mock = installSite({ httpRedirectTo: 'http://evil.example.net/landing' });
		const result = await scanWithSection();
		const fetched = mock.mock.calls.map(([input]) => urlOf(input));
		expect(fetched).toContain('http://example.com/');
		expect(fetched.some((url) => url.startsWith('http://evil.example.net'))).toBe(false);
		expect(webResult(result, 'http_redirect')).toBeDefined();
		// The refused hop reads as our guard's refusal, never as the target failing (SQ-489).
		const interrupted = webResult(result, 'http_redirect')?.findings.find((f) => f.metadata?.errorKind === 'request_refused');
		expect(interrupted?.detail).toContain("outbound-request guard refused the URL");
		// hstspreload.org was reached (through safeFetch), so the section did not abstain wholesale.
		expect(fetched.some((url) => url.startsWith('https://hstspreload.org/api/v2/status'))).toBe(true);
	});
});

describe('scan_domain webPosture — cache, force_refresh and the kill switch', () => {
	it('caches the section with the result, strips it on a cache hit when the switch is off, and re-runs it on force_refresh', async () => {
		const mock = installSite();
		const homepageGets = () => mock.mock.calls.filter(([input]) => urlOf(input) === 'https://www.example.com/').length;
		const { scanDomain } = await import('../src/tools/scan-domain');

		const first = await scanDomain(DOMAIN, undefined, { webPosture: true });
		expect(first.cached).toBe(false);
		expect(first.webPosture?.results).toHaveLength(6);
		const getsAfterFirst = homepageGets();
		expect(getsAfterFirst).toBeGreaterThan(0);

		const hit = await scanDomain(DOMAIN, undefined, { webPosture: true });
		expect(hit.cached).toBe(true);
		expect(hit.webPosture).toEqual(first.webPosture);
		expect(homepageGets()).toBe(getsAfterFirst);

		const switchedOff = await scanDomain(DOMAIN, undefined, { webPosture: true, webPostureEnabled: false });
		expect(switchedOff.cached).toBe(true);
		expect(switchedOff.webPosture).toBeUndefined();
		expect(switchedOff.score).toEqual(first.score);

		const refreshed = await scanDomain(DOMAIN, undefined, { webPosture: true, forceRefresh: true });
		expect(refreshed.cached).toBe(false);
		expect(refreshed.webPosture?.results).toHaveLength(6);
		expect(homepageGets()).toBe(2 * getsAfterFirst);
	});

	it('the kill switch omits the section and makes no web posture requests', async () => {
		const mock = installSite();
		const result = await scanWithSection({ webPostureEnabled: false, certstream: certstreamBinding(certMetaRow()) });
		expect(result.webPosture).toBeUndefined();
		const fetched = mock.mock.calls.map(([input]) => urlOf(input));
		expect(fetched.some((url) => url.includes('hstspreload.org'))).toBe(false);
		expect(fetched.some((url) => url.includes('/.well-known/security.txt'))).toBe(false);
		expect(fetched).not.toContain('https://www.example.com/');
	});

	it('parses WEB_POSTURE_ENABLED: default on, only "false" turns it off', async () => {
		const { parseWebPostureEnabled } = await import('../src/tools/scan/web-posture');
		expect(parseWebPostureEnabled(undefined)).toBe(true);
		expect(parseWebPostureEnabled('true')).toBe(true);
		expect(parseWebPostureEnabled('')).toBe(true);
		expect(parseWebPostureEnabled('false')).toBe(false);
		expect(parseWebPostureEnabled(' FALSE ')).toBe(false);
	});
});

describe('scan_domain webPosture — output', () => {
	function notAssessed(category: string, detail: string, status: 'timeout' | 'error'): CheckResult {
		const finding = createFinding(category as CheckResult['category'], `${category} not assessed`, 'info', detail, { notAssessed: true });
		return {
			category: category as CheckResult['category'],
			findings: [finding],
			score: 0,
			passed: false,
			partial: true,
			checkStatus: status,
		};
	}

	const SECTION = {
		nonScoring: true as const,
		results: [
			buildCheckResult('web_content', [
				createFinding('web_content', 'Cookie sid lacks the Secure flag', 'medium', 'The cookie can travel over plain HTTP.'),
			]),
			buildCheckResult('csp_quality', [createFinding('csp_quality', 'CSP enforced', 'info', 'A policy is enforced.')]),
			notAssessed('hsts_preload', 'hstspreload.org did not answer.', 'timeout'),
			buildCheckResult('http_redirect', []),
			notAssessed('security_txt', 'No page could be fetched.', 'error'),
			buildCheckResult('cert_posture', [
				createFinding('cert_posture', 'Certificate expires within 7 days', 'high', 'The newest certificate expires in 5 day(s).'),
				createFinding('cert_posture', 'Certificate key strength not assessed', 'info', 'No key details.', { notAssessed: true }),
			]),
		],
	};

	it('renders a "Not graded: web posture" section after the scored findings (full and compact snapshots)', async () => {
		installSite();
		const { formatScanReport } = await import('../src/tools/scan-domain');
		const result: ScanDomainResult = { ...(await scan({ webPostureEnabled: false })), webPosture: SECTION };

		const full = formatScanReport(result, 'full');
		expect(full).toContain(
			[
				'',
				'Not graded: web posture',
				'------------------------------',
				'These checks are informational only. They do not affect the score or grade above.',
				'  ⚠ WEB_CONTENT    1 issue',
				'    [MEDIUM] Cookie sid lacks the Secure flag',
				'      The cookie can travel over plain HTTP.',
				'  ✓ CSP_QUALITY    no issues found',
				'  ∅ HSTS_PRELOAD   not assessed — hstspreload.org did not answer.',
				'  ✓ HTTP_REDIRECT  no issues found',
				'  ∅ SECURITY_TXT   not assessed — No page could be fetched.',
				'  ⚠ CERT_POSTURE   1 issue',
				'    [HIGH] Certificate expires within 7 days',
				'      The newest certificate expires in 5 day(s).',
				'    Not assessed: Certificate key strength not assessed',
			].join('\n'),
		);
		const lines = full.split('\n');
		const findingsAt = lines.findIndex((l) => l === 'Findings:' || l === 'No security issues found.');
		const headingAt = lines.indexOf(HEADING);
		const footerAt = lines.findIndex((l) => l.startsWith('Scan completed:'));
		expect(findingsAt).toBeGreaterThan(-1);
		expect(headingAt).toBeGreaterThan(findingsAt);
		expect(footerAt).toBeGreaterThan(headingAt);

		expect(formatScanReport(result, 'compact')).toContain(
			[
				'',
				'Not graded: web posture (does not affect the score or grade)',
				'  WEB_CONTENT: 1 issue — [MEDIUM] Cookie sid lacks the Secure flag',
				'  CSP_QUALITY: no issues found',
				'  HSTS_PRELOAD: not assessed',
				'  HTTP_REDIRECT: no issues found',
				'  SECURITY_TXT: not assessed',
				'  CERT_POSTURE: 1 issue — [HIGH] Certificate expires within 7 days',
			].join('\n'),
		);
		// No section, no heading.
		expect(formatScanReport({ ...result, webPosture: undefined }, 'full')).not.toContain(HEADING);
	});

	it('scan_domain structuredContent carries webPosture; the kill switch removes it from text and structure', async () => {
		installSite();
		const { handleToolsCall } = await import('../src/handlers/tools');
		const on = (await handleToolsCall({ name: 'scan_domain', arguments: { domain: DOMAIN, force_refresh: true } }, undefined, {})) as {
			content: Array<{ text: string }>;
			structuredContent?: Record<string, unknown>;
		};
		const section = on.structuredContent?.webPosture as { nonScoring: boolean; results: CheckResult[] } | undefined;
		expect(section?.nonScoring).toBe(true);
		expect(section?.results.map((r) => r.category)).toEqual(WEB_CATEGORIES);
		expect(on.content[0].text).toContain(HEADING);

		IN_MEMORY_CACHE.clear();
		const off = (await handleToolsCall({ name: 'scan_domain', arguments: { domain: DOMAIN, force_refresh: true } }, undefined, {
			webPostureEnabled: false,
		})) as { content: Array<{ text: string }>; structuredContent?: Record<string, unknown> };
		expect(off.structuredContent?.webPosture).toBeUndefined();
		expect(off.content[0].text).not.toContain(HEADING);
		expect(off.structuredContent?.score).toEqual(on.structuredContent?.score);
	});

	it('buildStructuredScanResult emits webPosture only when the caller opts in', async () => {
		installSite();
		const { buildStructuredScanResult } = await import('../src/tools/scan-domain');
		const result: ScanDomainResult = { ...(await scan({ webPostureEnabled: false })), webPosture: SECTION };
		expect(buildStructuredScanResult(result, { includeWebPosture: true }).webPosture).toEqual(SECTION);
		expect(buildStructuredScanResult(result).webPosture).toBeUndefined();
	});
});
