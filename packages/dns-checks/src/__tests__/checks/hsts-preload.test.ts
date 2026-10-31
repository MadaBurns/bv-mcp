// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { checkHstsPreload } from '../../checks/check-hsts-preload';
import { analyzeHstsPreload, assessPreloadEligibility, httpRedirectsToHttps, observeHsts, parsePreloadStatus } from '../../checks/hsts-preload-analysis';
import type { PreloadMembership, PreloadStatus } from '../../checks/hsts-preload-analysis';
import type { CappedPage } from '../../checks/page-fetch';
import type { FetchFunction, Finding } from '../../types';

const DOMAIN = 'example.com';
const GOOD_HEADER = 'max-age=63072000; includeSubDomains; preload';
const API_URL = `https://hstspreload.org/api/v2/status?domain=${DOMAIN}`;

function page(overrides: Partial<CappedPage> & { headerPairs?: [string, string][] } = {}): CappedPage {
	const { headerPairs, ...rest } = overrides;
	return {
		requestedUrl: 'https://example.com/',
		finalUrl: 'https://example.com/',
		status: 200,
		headers: new Headers(headerPairs ?? []),
		setCookies: [],
		body: null,
		truncated: false,
		redirects: [],
		...rest,
	};
}

function hstsPage(header: string | null, over: Partial<CappedPage> = {}): CappedPage {
	return page({ headerPairs: header === null ? [] : [['strict-transport-security', header]], ...over });
}

const titles = (findings: Finding[]) => findings.map((f) => f.title);
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const apiStatus = (status: string) => () => json({ name: DOMAIN, status });

/** A fetch mock answering from a URL table; every other URL throws like an unreachable host. */
function routes(table: Record<string, () => Response>): FetchFunction & ReturnType<typeof vi.fn> {
	return vi.fn(async (url: string) => {
		const answer = table[url];
		if (!answer) throw new TypeError(`unreachable ${url}`);
		return answer();
	}) as FetchFunction & ReturnType<typeof vi.fn>;
}

const httpsOk = (header: string | null) => () => new Response('', { status: 200, headers: header === null ? {} : { 'strict-transport-security': header } });
const httpRedirect = (location: string) => () => new Response(null, { status: 301, headers: { location } });

/** Live-site table: apex answers over https with `header`; plain http redirects to https on the apex. */
function liveSite(header: string | null, status: string): Record<string, () => Response> {
	return {
		'https://example.com/': httpsOk(header),
		'http://example.com/': httpRedirect('https://example.com/'),
		[API_URL]: apiStatus(status),
	};
}

describe('assessPreloadEligibility', () => {
	const NO_REDIRECT_INFO = { redirectsToHttps: null };

	it('accepts a header meeting every rule (redirect measured)', () => {
		expect(assessPreloadEligibility(GOOD_HEADER, { redirectsToHttps: true })).toMatchObject({
			headerPresent: true,
			maxAge: 63072000,
			includeSubDomains: true,
			preload: true,
			missing: [],
			eligible: true,
		});
	});

	it('is eligible: null (not true) when the header is fine but the redirect was not measured', () => {
		expect(assessPreloadEligibility(GOOD_HEADER, NO_REDIRECT_INFO)).toMatchObject({ missing: [], eligible: null });
	});

	it('accepts the exact one-year boundary and a quoted max-age', () => {
		expect(assessPreloadEligibility('max-age=31536000; includeSubDomains; preload', { redirectsToHttps: true }).eligible).toBe(true);
		expect(assessPreloadEligibility('max-age="31536000"; includeSubDomains; preload', { redirectsToHttps: true }).eligible).toBe(true);
	});

	it('is case-insensitive and tolerates directive order and whitespace', () => {
		expect(assessPreloadEligibility('PRELOAD ;  INCLUDESUBDOMAINS ; Max-Age = 31536000', { redirectsToHttps: true }).eligible).toBe(true);
	});

	it.each([
		['max-age one second short', 'max-age=31535999; includeSubDomains; preload', 'a max-age of at least 31536000 seconds (it is 31535999)'],
		['no includeSubDomains', 'max-age=63072000; preload', 'the includeSubDomains directive'],
		['no preload', 'max-age=63072000; includeSubDomains', 'the preload directive'],
		['no max-age', 'includeSubDomains; preload', 'a valid max-age directive'],
		['a malformed max-age', 'max-age=abc; includeSubDomains; preload', 'a valid max-age directive'],
	])('rejects %s and names the missing part', (_label, header, missing) => {
		const result = assessPreloadEligibility(header, { redirectsToHttps: true });
		expect(result.eligible).toBe(false);
		expect(result.missing).toEqual([missing]);
	});

	it('does not count a directive token nested inside another directive', () => {
		const result = assessPreloadEligibility('max-age=63072000; x-includeSubDomains; x-preload', { redirectsToHttps: true });
		expect(result.includeSubDomains).toBe(false);
		expect(result.preload).toBe(false);
		expect(result.eligible).toBe(false);
	});

	it('lists every missing requirement for an absent header', () => {
		const result = assessPreloadEligibility(null, { redirectsToHttps: true });
		expect(result).toMatchObject({ headerPresent: false, maxAge: null, eligible: false, missing: ['a Strict-Transport-Security header'] });
	});

	it('fails a known-bad redirect even when the header is perfect', () => {
		const result = assessPreloadEligibility(GOOD_HEADER, { redirectsToHttps: false });
		expect(result.eligible).toBe(false);
		expect(result.missing).toEqual(['an HTTP-to-HTTPS redirect on the same host']);
	});

	it('an unmeasured redirect never hides a header failure', () => {
		expect(assessPreloadEligibility('max-age=60; preload', NO_REDIRECT_INFO).eligible).toBe(false);
	});
});

describe('observeHsts / httpRedirectsToHttps', () => {
	it('reads the header off the apex page', () => {
		expect(observeHsts(hstsPage(GOOD_HEADER), DOMAIN)).toEqual({ measured: true, header: GOOD_HEADER });
		expect(observeHsts(hstsPage(null), DOMAIN)).toEqual({ measured: true, header: null });
	});

	it('does not read a missing page, or a blocked answer without the header, as "no HSTS"', () => {
		expect(observeHsts(null, DOMAIN)).toMatchObject({ measured: false });
		expect(observeHsts(hstsPage(null, { status: 403 }), DOMAIN)).toMatchObject({ measured: false });
		expect(observeHsts(hstsPage(null, { status: 503 }), DOMAIN)).toMatchObject({ measured: false });
		// a blocked answer that DID carry the header is still a measurement
		expect(observeHsts(hstsPage(GOOD_HEADER, { status: 403 }), DOMAIN)).toEqual({ measured: true, header: GOOD_HEADER });
	});

	it('requires the FIRST http hop to land on https of the same host', () => {
		const redirect = (location: string, status = 301) => page({ status, headerPairs: [['location', location]] });
		expect(httpRedirectsToHttps(redirect('https://example.com/'), DOMAIN)).toBe(true);
		expect(httpRedirectsToHttps(redirect('https://EXAMPLE.com/path', 308), DOMAIN)).toBe(true);
		expect(httpRedirectsToHttps(redirect('/login'), DOMAIN)).toBe(false); // relative: stays on http
		expect(httpRedirectsToHttps(redirect('https://www.example.com/'), DOMAIN)).toBe(false);
		expect(httpRedirectsToHttps(redirect('http://example.com/other'), DOMAIN)).toBe(false);
		expect(httpRedirectsToHttps(page({ status: 200 }), DOMAIN)).toBe(false);
		expect(httpRedirectsToHttps(page({ status: 301 }), DOMAIN)).toBe(false); // redirect with no Location
	});

	it('is unmeasured (null) when the plain-http leg failed or was blocked', () => {
		expect(httpRedirectsToHttps(null, DOMAIN)).toBeNull();
		expect(httpRedirectsToHttps(page({ status: 403 }), DOMAIN)).toBeNull();
	});
});

describe('parsePreloadStatus', () => {
	it.each(['preloaded', 'pending', 'unknown', 'rejected'] as PreloadStatus[])('maps %s', (status) => {
		expect(parsePreloadStatus(JSON.stringify({ name: DOMAIN, status }), DOMAIN)).toEqual({ status });
	});

	it('accepts a response without a name', () => {
		expect(parsePreloadStatus('{"status":"preloaded"}', DOMAIN)).toEqual({ status: 'preloaded' });
	});

	it.each([
		['not JSON', '<html>502</html>'],
		['an array', '[]'],
		['null', 'null'],
		['no status', '{"name":"example.com"}'],
		['an unrecognised status', '{"name":"example.com","status":"removed"}'],
		['a non-string status', '{"name":"example.com","status":1}'],
		['another domain', '{"name":"other.com","status":"preloaded"}'],
	])('is not_assessed for %s, never "unknown"', (_label, text) => {
		expect(parsePreloadStatus(text, DOMAIN)).toMatchObject({ status: 'not_assessed' });
	});
});

describe('analyzeHstsPreload findings', () => {
	const measured = (header: string | null) => ({ measured: true as const, header });
	const member = (status: PreloadStatus): PreloadMembership => ({ status });

	it('unknown + eligible: info, with how to submit', () => {
		const findings = analyzeHstsPreload(DOMAIN, measured(GOOD_HEADER), true, member('unknown'));
		expect(titles(findings)).toEqual(['Eligible for the HSTS preload list, not submitted']);
		expect(findings[0]).toMatchObject({ severity: 'info' });
		expect(findings[0].detail).toContain('https://hstspreload.org/?domain=example.com');
	});

	it('unknown + eligible header but unmeasured redirect: still info, and says the redirect needs a manual check', () => {
		const [found] = analyzeHstsPreload(DOMAIN, measured(GOOD_HEADER), null, member('unknown'));
		expect(found.severity).toBe('info');
		expect(found.detail).toContain('redirect could not be measured');
	});

	it('unknown + not eligible: one low finding naming exactly what is missing, no invitation to submit', () => {
		const findings = analyzeHstsPreload(DOMAIN, measured('max-age=300'), true, member('unknown'));
		expect(titles(findings)).toEqual(['Not eligible for the HSTS preload list']);
		expect(findings[0].severity).toBe('low');
		expect(findings[0].detail).toContain('a max-age of at least 31536000 seconds (it is 300)');
		expect(findings[0].detail).toContain('the includeSubDomains directive');
		expect(findings[0].detail).toContain('the preload directive');
		expect(findings[0].detail).not.toContain('?domain=');
	});

	it('preloaded + header still meets the rules: info pass', () => {
		const findings = analyzeHstsPreload(DOMAIN, measured(GOOD_HEADER), true, member('preloaded'));
		expect(titles(findings)).toEqual(['Domain is on the HSTS preload list']);
		expect(findings[0]).toMatchObject({ severity: 'info', metadata: { pass: true } });
	});

	it.each([
		['lost the header', null, 'a Strict-Transport-Security header'],
		['lost preload', 'max-age=63072000; includeSubDomains', 'the preload directive'],
		['lost includeSubDomains', 'max-age=63072000; preload', 'the includeSubDomains directive'],
		['short max-age', 'max-age=86400; includeSubDomains; preload', 'a max-age of at least 31536000 seconds (it is 86400)'],
	])('preloaded + header %s: a single medium removal-risk finding', (_label, header, missing) => {
		const findings = analyzeHstsPreload(DOMAIN, measured(header), true, member('preloaded'));
		expect(titles(findings)).toEqual(['HSTS preload removal risk']);
		expect(findings[0].severity).toBe('medium');
		expect(findings[0].detail).toContain(missing);
	});

	it('preloaded + an unmeasured header is a pass plus a not-assessed finding, never a removal risk', () => {
		const findings = analyzeHstsPreload(DOMAIN, { measured: false, reason: 'timed out' }, null, member('preloaded'));
		expect(titles(findings)).toEqual(['HSTS header not assessed', 'Domain is on the HSTS preload list']);
	});

	it('pending: info', () => {
		const findings = analyzeHstsPreload(DOMAIN, measured(GOOD_HEADER), true, member('pending'));
		expect(titles(findings)).toEqual(['HSTS preload submission pending']);
		expect(findings[0].severity).toBe('info');
	});

	it('pending with a failing header also flags the ineligibility', () => {
		expect(titles(analyzeHstsPreload(DOMAIN, measured(null), true, member('pending')))).toEqual(['Not eligible for the HSTS preload list', 'HSTS preload submission pending']);
	});

	it('rejected: low', () => {
		const findings = analyzeHstsPreload(DOMAIN, measured(GOOD_HEADER), true, member('rejected'));
		expect(titles(findings)).toEqual(['HSTS preload submission rejected']);
		expect(findings[0].severity).toBe('low');
	});

	it('findings never claim a control is absent when something was not measured', () => {
		const findings = analyzeHstsPreload(DOMAIN, { measured: false, reason: 'x' }, null, { status: 'not_assessed', reason: 'y' });
		expect(findings.every((f) => f.metadata?.missingControl !== true && f.metadata?.inconclusive === true)).toBe(true);
	});
});

describe('checkHstsPreload', () => {
	it('eligible header + unknown status: eligible-not-submitted, structured metadata', async () => {
		const result = await checkHstsPreload(DOMAIN, routes(liveSite(GOOD_HEADER, 'unknown')));
		expect(result.category).toBe('hsts_preload');
		expect(titles(result.findings)).toEqual(['Eligible for the HSTS preload list, not submitted']);
		expect(result.checkStatus).toBeUndefined();
		expect(result.metadata).toMatchObject({ membership: 'unknown', eligible: true, maxAge: 63072000, includeSubDomains: true, preload: true, redirectsToHttps: true });
	});

	it.each([
		['preloaded', 'Domain is on the HSTS preload list'],
		['pending', 'HSTS preload submission pending'],
		['rejected', 'HSTS preload submission rejected'],
	])('maps the API status %s end to end', async (status, title) => {
		const result = await checkHstsPreload(DOMAIN, routes(liveSite(GOOD_HEADER, status)));
		expect(titles(result.findings)).toEqual([title]);
		expect(result.metadata).toMatchObject({ membership: status });
	});

	it('preloaded but the live header lost its directives: removal risk', async () => {
		const result = await checkHstsPreload(DOMAIN, routes(liveSite('max-age=300', 'preloaded')));
		expect(titles(result.findings)).toEqual(['HSTS preload removal risk']);
	});

	it('queries the API with the encoded apex through the injected fetch, bounded by a 5 s signal', async () => {
		const fetchFn = routes(liveSite(GOOD_HEADER, 'unknown'));
		await checkHstsPreload('Example.COM', fetchFn);
		const apiCall = fetchFn.mock.calls.find(([url]) => String(url).startsWith('https://hstspreload.org/'));
		expect(apiCall?.[0]).toBe(API_URL);
		expect(apiCall?.[1]).toMatchObject({ method: 'GET', redirect: 'manual' });
		expect((apiCall?.[1] as RequestInit).signal).toBeInstanceOf(AbortSignal);
	});

	it('NEGATIVE: hstspreload.org down (network error) is not_assessed, never "not preloaded"', async () => {
		const table = liveSite(GOOD_HEADER, 'unknown');
		delete table[API_URL];
		const result = await checkHstsPreload(DOMAIN, routes(table));
		expect(titles(result.findings)).toEqual(['HSTS preload status not assessed']);
		expect(result.findings[0].metadata).toMatchObject({ inconclusive: true, errorKind: 'membership_unmeasured' });
		expect(result.metadata).toMatchObject({ membership: 'not_assessed' });
	});

	it.each([
		['HTTP 503', () => new Response('down', { status: 503 })],
		['HTTP 429', () => new Response('slow down', { status: 429 })],
		['a non-JSON body', () => new Response('<html>hi</html>', { status: 200 })],
		['an unexpected status value', () => json({ name: DOMAIN, status: 'banana' })],
		['an unexpected shape', () => json(['preloaded'])],
	])('NEGATIVE: %s from the API is not_assessed, not an inferred negative', async (_label, answer) => {
		const result = await checkHstsPreload(DOMAIN, routes({ ...liveSite(GOOD_HEADER, 'unknown'), [API_URL]: answer }));
		expect(titles(result.findings)).toEqual(['HSTS preload status not assessed']);
		expect(titles(result.findings)).not.toContain('Eligible for the HSTS preload list, not submitted');
	});

	it('a failed API lookup still reports the header ineligibility it did measure', async () => {
		const table = liveSite('max-age=300', 'unknown');
		delete table[API_URL];
		const result = await checkHstsPreload(DOMAIN, routes(table));
		expect(titles(result.findings)).toEqual(['Not eligible for the HSTS preload list', 'HSTS preload status not assessed']);
	});

	it('apex unreachable but the API answers: header not assessed, membership kept', async () => {
		const result = await checkHstsPreload(DOMAIN, routes({ [API_URL]: apiStatus('preloaded') }));
		expect(titles(result.findings)).toEqual(['HSTS header not assessed', 'Domain is on the HSTS preload list']);
		expect(result.checkStatus).toBeUndefined();
	});

	it('NEGATIVE: nothing reachable gives the whole-result not-assessed shape', async () => {
		const result = await checkHstsPreload(DOMAIN, routes({}));
		expect(result).toMatchObject({ category: 'hsts_preload', score: 0, passed: false, partial: true, checkStatus: 'error' });
		expect(result.findings[0].metadata).toMatchObject({ inconclusive: true });
		expect(result.findings[0].metadata?.missingControl).toBeUndefined();
	});

	it('NEGATIVE: a plain fetch that always throws abstains rather than reporting a pass', async () => {
		const result = await checkHstsPreload(DOMAIN, async () => {
			throw new Error('boom');
		});
		expect(result).toMatchObject({ score: 0, passed: false, partial: true, checkStatus: 'error' });
	});

	it('uses a supplied apex page instead of fetching it again', async () => {
		const fetchFn = routes({ 'http://example.com/': httpRedirect('https://example.com/'), [API_URL]: apiStatus('unknown') });
		const result = await checkHstsPreload(DOMAIN, fetchFn, { pages: { apex: hstsPage(GOOD_HEADER) } });
		expect(titles(result.findings)).toEqual(['Eligible for the HSTS preload list, not submitted']);
		expect(fetchFn.mock.calls.some(([url]) => url === 'https://example.com/')).toBe(false);
	});

	it('a supplied apex page that redirected to www is not the apex header: the apex is re-fetched for its first hop only', async () => {
		const fetchFn = routes({
			'https://example.com/': () => new Response(null, { status: 301, headers: { location: 'https://www.example.com/', 'strict-transport-security': GOOD_HEADER } }),
			'http://example.com/': httpRedirect('https://example.com/'),
			[API_URL]: apiStatus('unknown'),
		});
		const wwwPage = hstsPage('max-age=1', { finalUrl: 'https://www.example.com/', redirects: ['https://www.example.com/'] });
		const result = await checkHstsPreload(DOMAIN, fetchFn, { pages: { apex: wwwPage } });
		expect(result.metadata).toMatchObject({ maxAge: 63072000, eligible: true });
		expect(fetchFn.mock.calls.some(([url]) => url === 'https://www.example.com/')).toBe(false);
	});

	it('a supplied null apex (caller fetch failed) is not retried', async () => {
		const fetchFn = routes({ 'http://example.com/': httpRedirect('https://example.com/'), [API_URL]: apiStatus('unknown') });
		const result = await checkHstsPreload(DOMAIN, fetchFn, { pages: { apex: null } });
		expect(titles(result.findings)).toEqual(['HSTS header not assessed', 'Not on the HSTS preload list']);
		expect(fetchFn.mock.calls.some(([url]) => url === 'https://example.com/')).toBe(false);
	});

	it('http that does not redirect to https makes a perfect header ineligible', async () => {
		const table = { ...liveSite(GOOD_HEADER, 'unknown'), 'http://example.com/': () => new Response('hi', { status: 200 }) };
		const result = await checkHstsPreload(DOMAIN, routes(table));
		expect(titles(result.findings)).toEqual(['Not eligible for the HSTS preload list']);
		expect(result.findings[0].detail).toContain('an HTTP-to-HTTPS redirect on the same host');
	});

	it('an unreachable plain-http leg leaves eligibility undecided (null), not failed', async () => {
		const table = liveSite(GOOD_HEADER, 'unknown');
		delete table['http://example.com/'];
		const result = await checkHstsPreload(DOMAIN, routes(table));
		expect(result.metadata).toMatchObject({ eligible: null, redirectsToHttps: null });
		expect(titles(result.findings)).toEqual(['Eligible for the HSTS preload list, not submitted']);
	});
});
