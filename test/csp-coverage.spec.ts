// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import type { FetchFunction } from '@blackveil/dns-checks';

const OBSERVED_AT = '2026-09-05T00:00:00.000Z';

function siteFetch(pages: Record<string, { body?: string; status?: number; headers?: Record<string, string> }>): FetchFunction {
	return vi.fn(async (url: string, _init?: RequestInit) => {
		if (url === 'https://example.com/robots.txt') return new Response(null, { status: 404 });
		const page = pages[url];
		if (!page) return new Response(null, { status: 404 });
		return new Response(page.body ?? '', {
			status: page.status ?? 200,
			headers: { 'content-type': 'text/html; charset=utf-8', ...(page.headers ?? {}) },
		});
	}) as FetchFunction;
}

describe('sampled CSP coverage audit', () => {
	it('performs a deterministic same-origin breadth-first crawl and compares headers', async () => {
		const fetchFn = siteFetch({
			'https://example.com/': {
				body: '<a href="/z">z</a><a href="/a">a</a><a href="https://other.example/path">off</a><a href="/skip?q=1">query</a>',
				headers: { 'content-security-policy': "default-src   'self'; script-src 'self'" },
			},
			'https://example.com/a': {
				body: '<a href="/nested">nested</a>',
				headers: { 'content-security-policy': "default-src 'self'; script-src 'self'" },
			},
			'https://example.com/z': { headers: { 'content-security-policy': "default-src 'self'; script-src 'unsafe-inline'" } },
			'https://example.com/nested': { headers: { 'content-security-policy': "default-src 'self'; script-src 'self'" } },
		});
		const { auditCspCoverage } = await import('../src/tools/audit-csp-coverage');
		const result = await auditCspCoverage('EXAMPLE.COM.', { fetchFn, now: () => OBSERVED_AT });
		const pageCalls = vi.mocked(fetchFn).mock.calls.filter(([url]) => !url.endsWith('/robots.txt'));

		expect(pageCalls.map(([url]) => url)).toEqual([
			'https://example.com/',
			'https://example.com/a',
			'https://example.com/z',
			'https://example.com/nested',
		]);
		expect(pageCalls.every(([, init]) => init?.redirect === 'manual' && init.credentials === 'omit')).toBe(true);
		expect(result.status).toBe('measured');
		expect(result.scope).toBe('sampled_same_origin');
		expect(result.nonScoring).toBe(true);
		expect(result.summary).toMatchObject({ measuredPages: 4, distinctHeaderProfiles: 2, headersConsistent: false });
		expect(result.summary?.unsafeTokens).toEqual(["'unsafe-inline'"]);
	});

	it('returns not-assessed when robots.txt disallows the seed', async () => {
		const fetchFn = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) return new Response('User-agent: *\nDisallow: /', { status: 200 });
			throw new Error('page fetch must not run');
		}) as FetchFunction;
		const { auditCspCoverage } = await import('../src/tools/audit-csp-coverage');
		const result = await auditCspCoverage('example.com', { fetchFn, now: () => OBSERVED_AT });

		expect(result.status).toBe('not-assessed');
		expect(result.pages[0]).toMatchObject({ status: 'not-assessed', notAssessedReason: 'robots_disallowed' });
		expect(fetchFn).toHaveBeenCalledTimes(1);
	});

	it('marks a robots fail-open result partial instead of fully measured', async () => {
		const fetchFn = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) return new Response(null, { status: 503 });
			return new Response('', { status: 200, headers: { 'content-type': 'text/html', 'content-security-policy': "default-src 'self'" } });
		}) as FetchFunction;
		const { auditCspCoverage } = await import('../src/tools/audit-csp-coverage');
		const result = await auditCspCoverage('example.com', { fetchFn, now: () => OBSERVED_AT });

		expect(result.status).toBe('partial');
		expect(result.partialReasons).toContain('robots_fail_open');
		expect(result.robotsResolution).toMatchObject({ resolution: 'unreachable', failOpen: true, status: 503 });
	});

	it('refuses cross-origin redirects without fetching the destination', async () => {
		const fetchFn = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) return new Response(null, { status: 404 });
			return new Response(null, { status: 302, headers: { location: 'https://attacker.example/' } });
		}) as FetchFunction;
		const { auditCspCoverage } = await import('../src/tools/audit-csp-coverage');
		const result = await auditCspCoverage('example.com', { fetchFn, now: () => OBSERVED_AT });

		expect(result.status).toBe('not-assessed');
		expect(result.pages[0]?.notAssessedReason).toBe('redirect_invalid');
		expect(fetchFn).toHaveBeenCalledTimes(2);
	});

	it('caps the sample at ten pages and labels the truncated result partial', async () => {
		const links = Array.from({ length: 12 }, (_, index) => `<a href="/p${String(index).padStart(2, '0')}">p</a>`).join('');
		const pages: Record<string, { body?: string; headers?: Record<string, string> }> = {
			'https://example.com/': { body: links, headers: { 'content-security-policy': "default-src 'self'" } },
		};
		for (let index = 0; index < 12; index++) {
			pages[`https://example.com/p${String(index).padStart(2, '0')}`] = { headers: { 'content-security-policy': "default-src 'self'" } };
		}
		const { auditCspCoverage, CSP_CRAWL_LIMITS } = await import('../src/tools/audit-csp-coverage');
		const result = await auditCspCoverage('example.com', { fetchFn: siteFetch(pages), now: () => OBSERVED_AT });

		expect(result.pages).toHaveLength(CSP_CRAWL_LIMITS.maxPages);
		expect(result.status).toBe('partial');
		expect(result.partialReasons).toContain('max_pages_reached');
	});

	it('keeps measured headers but marks oversized HTML discovery not-assessed', async () => {
		const { auditCspCoverage, CSP_CRAWL_LIMITS } = await import('../src/tools/audit-csp-coverage');
		const fetchFn = siteFetch({
			'https://example.com/': {
				body: 'x',
				headers: {
					'content-security-policy': "default-src 'self'",
					'content-length': String(CSP_CRAWL_LIMITS.maxPageBytes + 1),
				},
			},
		});
		const result = await auditCspCoverage('example.com', { fetchFn, now: () => OBSERVED_AT });

		expect(result.pages[0]).toMatchObject({
			status: 'measured',
			enforcingPolicy: "default-src 'self'",
			discovery: { status: 'not-assessed', notAssessedReason: 'body_too_large' },
		});
		expect(result.status).toBe('partial');
	});

	it('charges chunked overflow bytes against the aggregate body budget', async () => {
		const { auditCspCoverage, CSP_CRAWL_LIMITS } = await import('../src/tools/audit-csp-coverage');
		const links = Array.from({ length: 9 }, (_, index) => `<a href="/large-${index}">large</a>`).join('');
		const fetchFn = vi.fn(async (url: string) => {
			if (url.endsWith('/robots.txt')) return new Response(null, { status: 404 });
			if (url === 'https://example.com/') {
				return new Response(links, { status: 200, headers: { 'content-type': 'text/html' } });
			}
			const chunk = new Uint8Array(64 * 1024);
			let emitted = 0;
			return new Response(
				new ReadableStream<Uint8Array>({
					pull(controller) {
						if (emitted++ < 5) controller.enqueue(chunk);
						else controller.close();
					},
				}),
				{ status: 200, headers: { 'content-type': 'text/html' } },
			);
		}) as FetchFunction;
		const result = await auditCspCoverage('example.com', { fetchFn, now: () => OBSERVED_AT });
		const pageCalls = vi.mocked(fetchFn).mock.calls.filter(([url]) => !url.endsWith('/robots.txt'));

		expect(pageCalls.length).toBeLessThan(CSP_CRAWL_LIMITS.maxPages);
		expect(result.partialReasons).toEqual(expect.arrayContaining(['body_too_large', 'body_budget_exhausted']));
		expect(result.status).toBe('partial');
	});

	it('rejects invalid domains before any fetch', async () => {
		const { auditCspCoverage } = await import('../src/tools/audit-csp-coverage');
		await expect(auditCspCoverage('127.0.0.1')).rejects.toThrow(/^Invalid domain:/u);
	});
});
