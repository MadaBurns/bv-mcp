// SPDX-License-Identifier: BUSL-1.1

/**
 * US-16 T10 (SQ-484): scan_domain's NON-SCORING `webPosture` section.
 *
 * The load-bearing test is the negative control: the SAME mocked DNS/HTTP fixture is scanned with
 * the `WEB_POSTURE_ENABLED` kill switch on and off, and score, grade, category scores, finding
 * counts and evidence must be identical, while the "on" run carries web posture findings that
 * would have moved the score had they been scored.
 *
 * Only modules that exist without this change are imported statically, so reverting the source
 * fails these tests on their assertions rather than at collection.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, createDohResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
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
}

function installSite(options: SiteOptions = {}) {
	const mock = vi.fn((input: string | URL | Request, init?: RequestInit) => {
		const url = urlOf(input);
		if (url.includes('cloudflare-dns.com') || url.includes('dns.google')) return Promise.resolve(dohAnswer(url));
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
		const on = await scan({ certstream, webPostureEnabled: true });
		const onApexGets = apexGets();
		IN_MEMORY_CACHE.clear();
		const off = await scan({ certstream, webPostureEnabled: false });
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
		const on = await scan({ ...budget, webPostureEnabled: true });
		IN_MEMORY_CACHE.clear();
		const off = await scan({ ...budget, webPostureEnabled: false });

		expect(await scoredView(on)).toEqual(await scoredView(off));
		expect(on.webPosture?.results.map((r) => r.category)).toEqual(WEB_CATEGORIES);
		for (const result of on.webPosture!.results) {
			expect(['timeout', 'error'], `${result.category} must not read as completed`).toContain(result.checkStatus);
			expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
			expect(result.findings.some((f) => f.metadata?.notAssessed === true)).toBe(true);
		}
		// The homepage-dependent checks were cut off by the section deadline (fetchBudgetFor(1000) = 1000 ms).
		expect(webResult(on, 'web_content')?.checkStatus).toBe('timeout');
		expect(webResult(on, 'http_redirect')?.checkStatus).toBe('timeout');
	});
});

describe('scan_domain webPosture — cert_posture from BV_CERTSTREAM /cert-meta', () => {
	it('maps a CN-only issuer ("R11") to Let\'s Encrypt and compares it with CAA', async () => {
		installSite();
		const result = await scan({ certstream: certstreamBinding(certMetaRow()) });
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
		const result = await scan({ certstream: certstreamBinding(certMetaRow({ issuer: 'Example Private Issuing CA 7' })) });
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
		const cert = webResult(await scan({ certstream: certstreamBinding(noRow) }), 'cert_posture');
		expect(cert?.checkStatus).toBe('error');
		expect(cert?.findings.every((f) => f.metadata?.notAssessed === true)).toBe(true);
	});

	it('a stale index answer is not assessed (a renewal it has not seen must not read as expiring)', async () => {
		installSite();
		const stale = certMetaRow({ coverage: { ...(certMetaRow().coverage as object), freshThrough: isoFromNow(-2 * DAY_MS) } });
		const cert = webResult(await scan({ certstream: certstreamBinding(stale) }), 'cert_posture');
		expect(cert?.checkStatus).toBe('error');
		expect(cert?.findings.every((f) => f.metadata?.notAssessed === true)).toBe(true);
	});

	it('without the binding cert_posture abstains', async () => {
		installSite();
		const cert = webResult(await scan(), 'cert_posture');
		expect(cert?.checkStatus).toBe('error');
		expect(cert?.findings.every((f) => f.metadata?.notAssessed === true)).toBe(true);
	});
});

describe('scan_domain webPosture — fetch routing', () => {
	it('fetches plain HTTP to the scanned host raw but refuses a plain-HTTP hop to a foreign host', async () => {
		const mock = installSite({ httpRedirectTo: 'http://evil.example.net/landing' });
		const result = await scan();
		const fetched = mock.mock.calls.map(([input]) => urlOf(input));
		expect(fetched).toContain('http://example.com/');
		expect(fetched.some((url) => url.startsWith('http://evil.example.net'))).toBe(false);
		expect(webResult(result, 'http_redirect')).toBeDefined();
		// hstspreload.org was reached (through safeFetch), so the section did not abstain wholesale.
		expect(fetched.some((url) => url.startsWith('https://hstspreload.org/api/v2/status'))).toBe(true);
	});
});

describe('scan_domain webPosture — cache, force_refresh and the kill switch', () => {
	it('caches the section with the result, strips it on a cache hit when the switch is off, and re-runs it on force_refresh', async () => {
		const mock = installSite();
		const homepageGets = () => mock.mock.calls.filter(([input]) => urlOf(input) === 'https://www.example.com/').length;
		const { scanDomain } = await import('../src/tools/scan-domain');

		const first = await scanDomain(DOMAIN, undefined, {});
		expect(first.cached).toBe(false);
		expect(first.webPosture?.results).toHaveLength(6);
		const getsAfterFirst = homepageGets();
		expect(getsAfterFirst).toBeGreaterThan(0);

		const hit = await scanDomain(DOMAIN, undefined, {});
		expect(hit.cached).toBe(true);
		expect(hit.webPosture).toEqual(first.webPosture);
		expect(homepageGets()).toBe(getsAfterFirst);

		const switchedOff = await scanDomain(DOMAIN, undefined, { webPostureEnabled: false });
		expect(switchedOff.cached).toBe(true);
		expect(switchedOff.webPosture).toBeUndefined();
		expect(switchedOff.score).toEqual(first.score);

		const refreshed = await scanDomain(DOMAIN, undefined, { forceRefresh: true });
		expect(refreshed.cached).toBe(false);
		expect(refreshed.webPosture?.results).toHaveLength(6);
		expect(homepageGets()).toBe(2 * getsAfterFirst);
	});

	it('the kill switch omits the section and makes no web posture requests', async () => {
		const mock = installSite();
		const result = await scan({ webPostureEnabled: false, certstream: certstreamBinding(certMetaRow()) });
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
