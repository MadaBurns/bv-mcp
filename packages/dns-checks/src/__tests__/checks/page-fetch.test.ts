// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { fetchPageCapped } from '../../checks/page-fetch';
import type { FetchFunction } from '../../types';

function redirect(status: number, location: string): Response {
	return new Response(null, { status, headers: { location } });
}

/** A fetch mock that answers from a URL → Response table and records every request. */
function routes(table: Record<string, () => Response>): FetchFunction & ReturnType<typeof vi.fn> {
	return vi.fn(async (url: string) => {
		const answer = table[url];
		if (!answer) throw new TypeError(`unexpected fetch ${url}`);
		return answer();
	}) as FetchFunction & ReturnType<typeof vi.fn>;
}

describe('fetchPageCapped', () => {
	it('GETs the page once with manual redirects, the scanner UA and a timeout signal, and returns status, headers and body', async () => {
		const fetchFn = routes({ 'https://example.com/': () => new Response('<html>ok</html>', { status: 200, headers: { 'content-type': 'text/html' } }) });
		const page = await fetchPageCapped('https://example.com/', fetchFn);

		expect(fetchFn).toHaveBeenCalledTimes(1);
		const init = fetchFn.mock.calls[0][1] as RequestInit;
		expect(init.method).toBe('GET');
		expect(init.redirect).toBe('manual');
		expect((init.headers as Record<string, string>)['User-Agent']).toMatch(/BlackVeil/i);
		expect(init.signal).toBeInstanceOf(AbortSignal);
		expect(page).toMatchObject({
			requestedUrl: 'https://example.com/',
			finalUrl: 'https://example.com/',
			status: 200,
			body: '<html>ok</html>',
			truncated: false,
			redirects: [],
			setCookies: [],
		});
		expect(page?.headers.get('content-type')).toBe('text/html');
	});

	it('follows HTTPS redirects, resolving a relative Location against the requested URL', async () => {
		const fetchFn = routes({
			'http://example.com/': () => redirect(301, 'https://example.com/'),
			'https://example.com/': () => redirect(302, '/home'),
			'https://example.com/home': () => new Response('home', { status: 200 }),
		});
		const page = await fetchPageCapped('http://example.com/', fetchFn);

		expect(page).toMatchObject({
			requestedUrl: 'http://example.com/',
			finalUrl: 'https://example.com/home',
			status: 200,
			body: 'home',
			redirects: ['https://example.com/', 'https://example.com/home'],
		});
	});

	it('stops at the redirect cap and returns the last redirect response', async () => {
		let hop = 0;
		const fetchFn = vi.fn(async () => redirect(302, `https://example.com/loop/${++hop}`));
		const page = await fetchPageCapped('https://example.com/', fetchFn);

		expect(fetchFn).toHaveBeenCalledTimes(4);
		expect(page?.status).toBe(302);
		expect(page?.redirects).toEqual(['https://example.com/loop/1', 'https://example.com/loop/2', 'https://example.com/loop/3']);
		expect(page?.finalUrl).toBe('https://example.com/loop/3');
		expect(page?.headers.get('location')).toBe('https://example.com/loop/4');
	});

	it('honours a custom maxRedirects', async () => {
		const fetchFn = vi.fn(async () => redirect(307, 'https://example.com/next'));
		const page = await fetchPageCapped('https://example.com/', fetchFn, { maxRedirects: 1 });

		expect(fetchFn).toHaveBeenCalledTimes(2);
		expect(page?.redirects).toEqual(['https://example.com/next']);
	});

	it('refuses an http:// downgrade hop and returns the redirect that named it', async () => {
		const fetchFn = routes({ 'https://example.com/': () => redirect(301, 'http://example.com/insecure') });
		const page = await fetchPageCapped('https://example.com/', fetchFn);

		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(page).toMatchObject({ finalUrl: 'https://example.com/', status: 301, redirects: [] });
		expect(page?.headers.get('location')).toBe('http://example.com/insecure');
	});

	it('treats a redirect with no Location, or a non-redirect status with one, as the final page', async () => {
		const noLocation = await fetchPageCapped('https://a.example/', vi.fn(async () => new Response(null, { status: 302 })));
		expect(noLocation).toMatchObject({ status: 302, redirects: [], body: null });

		const created = await fetchPageCapped(
			'https://b.example/',
			vi.fn(async () => new Response('made', { status: 201, headers: { location: 'https://b.example/item' } })),
		);
		expect(created).toMatchObject({ status: 201, redirects: [], body: 'made' });
	});

	it('truncates a 2 MB body to the first 524288 bytes instead of returning null', async () => {
		const huge = 'a'.repeat(2 * 1024 * 1024);
		const page = await fetchPageCapped('https://example.com/', vi.fn(async () => new Response(huge, { status: 200 })));

		expect(page).not.toBeNull();
		expect(page?.truncated).toBe(true);
		expect(page?.body).toHaveLength(524_288);
		expect(page?.body).toBe(huge.slice(0, 524_288));
	});

	it('keeps a body exactly at the cap whole, and drops a multi-byte character split by a smaller cap', async () => {
		const exact = await fetchPageCapped('https://example.com/', vi.fn(async () => new Response('abcd')), { maxBytes: 4 });
		expect(exact).toMatchObject({ body: 'abcd', truncated: false });

		// '€' is 3 bytes: 10 bytes hold three whole characters and one stray byte.
		const split = await fetchPageCapped('https://example.com/', vi.fn(async () => new Response('€€€€€')), { maxBytes: 10 });
		expect(split).toMatchObject({ body: '€€€', truncated: true });
	});

	it('returns every Set-Cookie header separately', async () => {
		const headers = new Headers();
		headers.append('set-cookie', 'session=abc; Secure; HttpOnly');
		headers.append('set-cookie', 'theme=dark; Path=/');
		const page = await fetchPageCapped('https://example.com/', vi.fn(async () => new Response('x', { headers })));

		expect(page?.setCookies).toEqual(['session=abc; Secure; HttpOnly', 'theme=dark; Path=/']);
	});

	it('falls back to no cookies where Headers has no getSetCookie', async () => {
		const bare = { status: 200, url: '', body: null, headers: { get: () => null } } as unknown as Response;
		const page = await fetchPageCapped('https://example.com/', vi.fn(async () => bare));

		expect(page).toMatchObject({ status: 200, setCookies: [], body: null });
	});

	it('returns null when the fetch throws, on the first request or on a redirect hop', async () => {
		expect(await fetchPageCapped('https://example.com/', vi.fn(async () => Promise.reject(new TypeError('network down'))))).toBeNull();

		const hopFails = routes({ 'https://example.com/': () => redirect(301, 'https://elsewhere.example/') });
		expect(await fetchPageCapped('https://example.com/', hopFails)).toBeNull();
		expect(hopFails).toHaveBeenCalledTimes(2);
	});

	it('returns null when the body stream fails mid-read', async () => {
		const failing = new ReadableStream<Uint8Array>({
			pull(controller) {
				controller.error(new Error('connection reset'));
			},
		});
		expect(await fetchPageCapped('https://example.com/', vi.fn(async () => new Response(failing)))).toBeNull();
	});
});
