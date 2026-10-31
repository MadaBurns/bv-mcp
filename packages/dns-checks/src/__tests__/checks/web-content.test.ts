// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { checkWebContent } from '../../checks/check-web-content';
import { analyzeWebContentPage, parseSetCookie, MAX_COOKIE_FINDINGS } from '../../checks/web-content-analysis';
import type { CappedPage } from '../../checks/page-fetch';
import type { FetchFunction, Finding } from '../../types';

const DOMAIN = 'example.com';

function page(overrides: Partial<CappedPage> & { html?: string; headerPairs?: [string, string][] } = {}): CappedPage {
	const { html, headerPairs, ...rest } = overrides;
	const headers = new Headers([['content-type', 'text/html; charset=utf-8'], ...(headerPairs ?? [])]);
	return {
		requestedUrl: 'https://example.com/',
		finalUrl: 'https://example.com/',
		status: 200,
		headers,
		setCookies: headers.getSetCookie(),
		body: html ?? '<html><body>hello</body></html>',
		truncated: false,
		redirects: [],
		...rest,
	};
}

function titles(findings: Finding[]): string[] {
	return findings.map((f) => f.title);
}

function bySeverity(findings: Finding[], title: string): Finding | undefined {
	return findings.find((f) => f.title === title);
}

/** A fetch mock answering from a URL table; every other URL throws like an unreachable host. */
function routes(table: Record<string, () => Response>): FetchFunction & ReturnType<typeof vi.fn> {
	return vi.fn(async (url: string) => {
		const answer = table[url];
		if (!answer) throw new TypeError(`unreachable ${url}`);
		return answer();
	}) as FetchFunction & ReturnType<typeof vi.fn>;
}

describe('parseSetCookie', () => {
	it('reads the flags and discards the value', () => {
		const cookie = parseSetCookie('sid=SECRET123; Path=/app; Secure; HttpOnly; SameSite=Lax; Domain=example.com');
		expect(cookie).toEqual({ name: 'sid', secure: true, httpOnly: true, sameSite: 'lax', path: '/app', hasDomain: true });
		expect(JSON.stringify(cookie)).not.toContain('SECRET123');
	});

	it('is case-insensitive on attribute names and returns null without a name', () => {
		expect(parseSetCookie('a=1; SECURE; httponly; SAMESITE=None')).toMatchObject({ secure: true, httpOnly: true, sameSite: 'none' });
		expect(parseSetCookie('=value; Secure')).toBeNull();
	});
});

describe('analyzeWebContentPage: cookies', () => {
	const cookieFinding = (cookie: string, over: Partial<CappedPage> = {}) =>
		analyzeWebContentPage(page({ headerPairs: [['set-cookie', cookie]], ...over }), DOMAIN).find((f) => f.metadata?.cookie !== undefined);

	it('flags a missing Secure flag on an https response as medium', () => {
		const found = cookieFinding('theme=dark; HttpOnly; SameSite=Lax');
		expect(found).toMatchObject({ severity: 'medium', category: 'web_content' });
		expect(found?.metadata?.issues).toEqual(['missing_secure']);
	});

	it('does not demand Secure when the page itself is http', () => {
		const found = cookieFinding('theme=dark; HttpOnly; SameSite=Lax', { requestedUrl: 'http://example.com/', finalUrl: 'http://example.com/' });
		expect(found).toBeUndefined();
	});

	it('grades a missing HttpOnly medium on a session-looking name and low otherwise', () => {
		expect(cookieFinding('PHPSESSID=x; Secure; SameSite=Lax')).toMatchObject({ severity: 'medium' });
		expect(cookieFinding('auth_token=x; Secure; SameSite=Lax')?.metadata?.issues).toEqual(['missing_httponly']);
		expect(cookieFinding('theme=dark; Secure; SameSite=Lax')).toMatchObject({ severity: 'low' });
	});

	it('flags an absent SameSite as low', () => {
		const found = cookieFinding('theme=dark; Secure; HttpOnly');
		expect(found).toMatchObject({ severity: 'low' });
		expect(found?.metadata?.issues).toEqual(['samesite_absent']);
	});

	it('flags SameSite=None without Secure as medium', () => {
		const found = cookieFinding('t=1; HttpOnly; SameSite=None', { requestedUrl: 'http://example.com/', finalUrl: 'http://example.com/' });
		expect(found).toMatchObject({ severity: 'medium' });
		expect(found?.metadata?.issues).toEqual(['samesite_none_insecure']);
	});

	it('flags __Host- cookies that lack Secure, Path=/ or carry Domain, and __Secure- cookies that lack Secure', () => {
		const host = cookieFinding('__Host-id=1; Secure; HttpOnly; SameSite=Lax; Path=/app; Domain=example.com');
		expect(host).toMatchObject({ severity: 'medium' });
		expect(host?.metadata?.issues).toEqual(['host_prefix']);
		expect(host?.detail).toContain('Path=/');
		expect(host?.detail).toContain('no Domain attribute');
		const secure = cookieFinding('__Secure-id=1; HttpOnly; SameSite=Lax; Path=/', { requestedUrl: 'http://example.com/', finalUrl: 'http://example.com/' });
		expect(secure?.metadata?.issues).toEqual(['secure_prefix']);
	});

	it('accepts a well-formed __Host- cookie', () => {
		expect(cookieFinding('__Host-id=1; Secure; HttpOnly; SameSite=Strict; Path=/')).toBeUndefined();
	});

	it('emits ONE finding per cookie with the highest severity, naming issues by code', () => {
		const findings = analyzeWebContentPage(page({ headerPairs: [['set-cookie', 'sessionid=abc']] }), DOMAIN).filter((f) => f.metadata?.cookie === 'sessionid');
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('medium');
		expect(findings[0].metadata?.issues).toEqual(['missing_secure', 'missing_httponly', 'samesite_absent']);
	});

	it('never echoes a cookie value', () => {
		const findings = analyzeWebContentPage(page({ headerPairs: [['set-cookie', 'sessionid=TOP-SECRET-VALUE-9f3a']] }), DOMAIN);
		expect(JSON.stringify(findings)).not.toContain('TOP-SECRET-VALUE-9f3a');
	});

	it('caps itemized cookies at 20 and folds the rest into one summary at the highest omitted severity', () => {
		const pairs: [string, string][] = Array.from({ length: 25 }, (_, i) => ['set-cookie', `c${i}=1; Secure; HttpOnly`] as [string, string]);
		const findings = analyzeWebContentPage(page({ headerPairs: pairs }), DOMAIN);
		expect(findings.filter((f) => typeof f.metadata?.cookie === 'string')).toHaveLength(MAX_COOKIE_FINDINGS);
		const summary = bySeverity(findings, 'More cookies with weak attributes');
		expect(summary).toMatchObject({ severity: 'low' });
		expect(summary?.metadata?.omittedCookies).toBe(5);
	});
});

describe('analyzeWebContentPage: mixed content', () => {
	const html = (body: string) => page({ html: `<html><body>${body}</body></html>` });

	it('reports http scripts, stylesheets and frames on an https page as high active mixed content', () => {
		const findings = analyzeWebContentPage(
			html(
				`<script src="http://example.com/a.js"></script>
				 <link rel="stylesheet" href="http://example.com/a.css">
				 <iframe src="http://example.com/frame"></iframe>`,
			),
			DOMAIN,
		);
		const active = bySeverity(findings, 'Active mixed content');
		expect(active).toMatchObject({ severity: 'high' });
		expect(active?.metadata?.count).toBe(3);
		expect(active?.detail).toContain('http://example.com/a.js');
	});

	it('reports http images and media as low passive mixed content', () => {
		const findings = analyzeWebContentPage(html(`<img src="http://example.com/a.png"><video poster="http://example.com/p.jpg"></video>`), DOMAIN);
		expect(bySeverity(findings, 'Passive mixed content')).toMatchObject({ severity: 'low' });
		expect(bySeverity(findings, 'Active mixed content')).toBeUndefined();
	});

	it('strips queries from listed URLs and lists at most 10', () => {
		const imgs = Array.from({ length: 12 }, (_, i) => `<img src="http://example.com/i${i}.png?token=SECRETQ">`).join('');
		const found = bySeverity(analyzeWebContentPage(html(imgs), DOMAIN), 'Passive mixed content');
		expect(found?.detail).not.toContain('SECRETQ');
		expect(found?.detail).toContain('(+2 more)');
		expect(found?.metadata?.count).toBe(12);
	});

	it('is exempt, and says so, when the page itself is http', () => {
		const findings = analyzeWebContentPage(
			page({ html: '<img src="http://example.com/a.png">', requestedUrl: 'http://example.com/', finalUrl: 'http://example.com/' }),
			DOMAIN,
		);
		expect(bySeverity(findings, 'Passive mixed content')).toBeUndefined();
		expect(bySeverity(findings, 'Mixed-content analysis skipped')?.detail).toContain('served over http');
	});
});

describe('analyzeWebContentPage: Subresource Integrity', () => {
	const html = (body: string) => page({ html: `<html><head>${body}</head></html>` });

	it('flags cross-origin scripts and stylesheets without integrity as ONE low finding', () => {
		const findings = analyzeWebContentPage(
			html(`<script src="https://cdn.other.net/a.js"></script><link rel="stylesheet" href="https://fonts.other.org/s.css">`),
			DOMAIN,
		);
		const found = findings.filter((f) => f.title === 'Cross-origin resource without Subresource Integrity');
		expect(found).toHaveLength(1);
		expect(found[0]).toMatchObject({ severity: 'low' });
		expect(found[0].metadata?.count).toBe(2);
	});

	it('does not treat the page host, the apex or its subdomains as cross-origin', () => {
		const findings = analyzeWebContentPage(
			html(`<script src="/local.js"></script><script src="https://cdn.example.com/a.js"></script><script src="https://example.com/b.js"></script>`),
			DOMAIN,
		);
		expect(bySeverity(findings, 'Cross-origin resource without Subresource Integrity')).toBeUndefined();
	});

	it('treats a look-alike host that merely ends with the domain as cross-origin', () => {
		const findings = analyzeWebContentPage(html(`<script src="https://evilexample.com/a.js"></script>`), DOMAIN);
		expect(bySeverity(findings, 'Cross-origin resource without Subresource Integrity')).toBeDefined();
	});

	it('flags an integrity value without a sha256/384/512 hash as medium, wherever it loads from', () => {
		const findings = analyzeWebContentPage(
			html(`<script src="/a.js" integrity="md5-abc"></script><link rel="stylesheet" href="https://cdn.other.net/s.css" integrity="notahash" crossorigin="anonymous">`),
			DOMAIN,
		);
		expect(bySeverity(findings, 'Malformed integrity attribute')).toMatchObject({ severity: 'medium' });
		expect(bySeverity(findings, 'Malformed integrity attribute')?.metadata?.count).toBe(2);
	});

	it('accepts sha256, sha384 and sha512 integrity values', () => {
		const findings = analyzeWebContentPage(
			html(
				`<script src="https://cdn.other.net/1.js" integrity="sha256-abc123+/=" crossorigin="anonymous"></script>
				 <script src="https://cdn.other.net/2.js" integrity="sha384-abc123" crossorigin="anonymous"></script>
				 <script src="https://cdn.other.net/3.js" integrity="sha512-abc123 sha384-xyz" crossorigin></script>`,
			),
			DOMAIN,
		);
		expect(findings.every((f) => f.severity === 'info')).toBe(true);
	});

	it('flags a cross-origin script with integrity but no crossorigin attribute as low', () => {
		const findings = analyzeWebContentPage(html(`<script src="https://cdn.other.net/a.js" integrity="sha384-abc"></script>`), DOMAIN);
		expect(bySeverity(findings, 'Cross-origin script has integrity but no crossorigin attribute')).toMatchObject({ severity: 'low' });
		expect(bySeverity(findings, 'Cross-origin resource without Subresource Integrity')).toBeUndefined();
	});

	it('treats a blank integrity attribute as no integrity, not as malformed', () => {
		const findings = analyzeWebContentPage(html(`<script src="https://cdn.other.net/a.js" integrity=" "></script>`), DOMAIN);
		expect(bySeverity(findings, 'Malformed integrity attribute')).toBeUndefined();
		expect(bySeverity(findings, 'Cross-origin resource without Subresource Integrity')).toBeDefined();
	});
});

describe('analyzeWebContentPage: outbound http links', () => {
	it('flags forms that submit to http as medium and counts http anchors as info', () => {
		const findings = analyzeWebContentPage(
			page({
				html: `<form action="http://example.com/login"></form><form action="/ok"></form><a href="http://other.net/a">x</a><a href="https://other.net/b">y</a><a href="mailto:a@b.c">m</a>`,
			}),
			DOMAIN,
		);
		expect(bySeverity(findings, 'Form submits to an http URL')).toMatchObject({ severity: 'medium' });
		const anchors = bySeverity(findings, 'Links to http URLs');
		expect(anchors).toMatchObject({ severity: 'info' });
		expect(anchors?.metadata?.count).toBe(1);
	});
});

describe('analyzeWebContentPage: coverage notes and non-pages', () => {
	it('adds an info finding when the body was truncated', () => {
		const findings = analyzeWebContentPage(page({ html: 'x'.repeat(2048), truncated: true }), DOMAIN);
		const found = bySeverity(findings, 'Page analysis truncated');
		expect(found).toMatchObject({ severity: 'info' });
		expect(found?.detail).toContain('first 2 KiB');
	});

	it('emits an all-clear info finding for a clean page (positive control)', () => {
		const findings = analyzeWebContentPage(
			page({
				headerPairs: [['set-cookie', '__Host-session=1; Secure; HttpOnly; SameSite=Strict; Path=/']],
				html: `<script src="/app.js"></script><img src="/a.png"><a href="https://other.net/">x</a><form action="/go"></form>`,
			}),
			DOMAIN,
		);
		expect(titles(findings)).toEqual(['No web content issues found']);
		expect(findings[0]).toMatchObject({ severity: 'info' });
	});

	it('does not emit the all-clear when there are issues', () => {
		const findings = analyzeWebContentPage(page({ html: '<img src="http://example.com/a.png">' }), DOMAIN);
		expect(bySeverity(findings, 'No web content issues found')).toBeUndefined();
	});

	it('analyses cookies only, and says so, when the response is not HTML', () => {
		const json = page({ html: '{"a":"<img src=http://example.com/x.png>"}', headerPairs: [['set-cookie', 'theme=dark; Secure; HttpOnly; SameSite=Lax']] });
		json.headers.set('content-type', 'application/json');
		const findings = analyzeWebContentPage(json, DOMAIN);
		expect(titles(findings)).toEqual(['No web content issues found']);
		expect(findings[0].detail).toContain('no HTML body');
	});

	it.each([
		[403, 'edge, WAF'],
		[429, 'rate-limit'],
		[202, 'edge, WAF'],
		[503, 'server-error'],
		[204, 'no content'],
		[301, 'redirect chain stopped'],
	])('reports HTTP %i as not assessed, never as clean', (status, phrase) => {
		const findings = analyzeWebContentPage(page({ status, html: '<img src="http://example.com/a.png">' }), DOMAIN);
		expect(titles(findings)).toEqual(['Web content not assessed']);
		expect(findings[0].detail).toContain(phrase);
		expect(findings[0].metadata).toMatchObject({ inconclusive: true });
		expect(findings[0].metadata?.missingControl).toBeUndefined();
	});

	it('still analyses an ordinary 404 page', () => {
		const findings = analyzeWebContentPage(page({ status: 404, html: '<img src="http://example.com/a.png">' }), DOMAIN);
		expect(bySeverity(findings, 'Passive mixed content')).toBeDefined();
	});
});

describe('checkWebContent', () => {
	const cleanBody = '<html><body>hi</body></html>';
	const ok = (body = cleanBody, cookie?: string) => () => {
		const headers = new Headers([['content-type', 'text/html']]);
		if (cookie) headers.append('set-cookie', cookie);
		return new Response(body, { status: 200, headers });
	};

	it('fetches https://<apex>/ and https://www.<apex>/ and reports both hosts', async () => {
		const fetchFn = routes({
			'https://example.com/': ok('<img src="http://example.com/a.png">'),
			'https://www.example.com/': ok(),
		});
		const result = await checkWebContent(DOMAIN, fetchFn);
		expect(fetchFn.mock.calls.map((c) => c[0]).sort()).toEqual(['https://example.com/', 'https://www.example.com/']);
		expect(result.category).toBe('web_content');
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.find((f) => f.title === 'Passive mixed content')?.metadata?.host).toBe('example.com');
		expect(result.findings.find((f) => f.title === 'No web content issues found')?.metadata?.host).toBe('www.example.com');
	});

	it('reports an unreachable host as not assessed while still analysing the other', async () => {
		const result = await checkWebContent(DOMAIN, routes({ 'https://example.com/': ok() }));
		const www = result.findings.find((f) => f.metadata?.host === 'www.example.com');
		expect(www).toMatchObject({ title: 'Web content not assessed', severity: 'info' });
		expect(www?.metadata).toMatchObject({ inconclusive: true, errorKind: 'fetch_failed' });
		expect(result.findings.some((f) => f.metadata?.host === 'example.com' && f.title === 'No web content issues found')).toBe(true);
	});

	it('returns the not-assessed shape when neither host can be fetched', async () => {
		const result = await checkWebContent(DOMAIN, routes({}));
		expect(result).toMatchObject({ category: 'web_content', score: 0, passed: false, partial: true, checkStatus: 'error' });
		expect(result.findings).toHaveLength(1);
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
	});

	it('uses supplied pages instead of fetching, and does not refetch a supplied null', async () => {
		const fetchFn = routes({});
		const result = await checkWebContent(DOMAIN, fetchFn, { pages: { apex: page(), www: null } });
		expect(fetchFn).not.toHaveBeenCalled();
		expect(result.findings.find((f) => f.metadata?.host === 'www.example.com')?.metadata?.errorKind).toBe('fetch_failed');
		expect(result.findings.some((f) => f.title === 'No web content issues found')).toBe(true);
	});

	it('fetches only the host whose page was not supplied', async () => {
		const fetchFn = routes({ 'https://www.example.com/': ok() });
		await checkWebContent(DOMAIN, fetchFn, { pages: { apex: page() } });
		expect(fetchFn.mock.calls.map((c) => c[0])).toEqual(['https://www.example.com/']);
	});

	it('analyses a page once when both hosts land on the same URL', async () => {
		const fetchFn = routes({
			'https://example.com/': () => new Response(null, { status: 301, headers: { location: 'https://www.example.com/' } }),
			'https://www.example.com/': ok('<img src="http://www.example.com/a.png">'),
		});
		const result = await checkWebContent(DOMAIN, fetchFn);
		expect(result.findings.filter((f) => f.title === 'Passive mixed content')).toHaveLength(1);
		expect(result.findings.find((f) => f.title === 'Same page as the other host')?.metadata?.host).toBe('www.example.com');
	});

	it('probes only the given host when the domain already starts with www.', async () => {
		const fetchFn = routes({ 'https://www.example.com/': ok() });
		await checkWebContent('www.example.com', fetchFn);
		expect(fetchFn.mock.calls.map((c) => c[0])).toEqual(['https://www.example.com/']);
	});

	it('passes the timeout through to the page fetch', async () => {
		const fetchFn = routes({ 'https://example.com/': ok(), 'https://www.example.com/': ok() });
		await checkWebContent(DOMAIN, fetchFn, { timeout: 1234 });
		expect((fetchFn.mock.calls[0][1] as RequestInit).signal).toBeInstanceOf(AbortSignal);
	});

	it('reads Set-Cookie headers off the live Response (getSetCookie)', async () => {
		const fetchFn = routes({ 'https://example.com/': ok(cleanBody, 'sessionid=abc'), 'https://www.example.com/': ok() });
		const result = await checkWebContent(DOMAIN, fetchFn);
		expect(result.findings.find((f) => f.metadata?.cookie === 'sessionid')).toMatchObject({ severity: 'medium' });
	});
});
