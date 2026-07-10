// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

// `checkHttpSecurity`'s module-scope `gatedFetch`/`gatedSafeFetch` memoize each
// hostname's robots.txt group for the lifetime of the module instance — reset
// modules between tests so each test's dynamic import gets a fresh gate (and
// fresh cache), not a robots.txt verdict cached by a previous test's mock.
afterEach(() => {
	restore();
	vi.resetModules();
});

describe('checkHttpSecurity tool — robots.txt', () => {
	async function run(domain = 'example.com') {
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		return checkHttpSecurity(domain);
	}

	it('excludes the category when robots.txt disallows the primary probe, without ever reaching the origin', async () => {
		let originProbed = false;
		globalThis.fetch = (async (url: string | URL | Request) => {
			const href = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;
			if (href.endsWith('/robots.txt')) return new Response('User-agent: *\nDisallow: /\n', { status: 200 });
			originProbed = true;
			return new Response(null, { status: 200 });
		}) as typeof fetch;

		const result = await run();
		expect(originProbed).toBe(false);
		expect(result.checkStatus).toBe('error');
	});

	it('sends the real scanner User-Agent on the primary probe', async () => {
		let capturedUA: string | null = null;
		globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
			const href = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;
			if (href.endsWith('/robots.txt')) return new Response('User-agent: *\n', { status: 200 });
			capturedUA = new Headers(init?.headers).get('User-Agent');
			return new Response(null, { status: 200 });
		}) as typeof fetch;

		await run();
		expect(capturedUA).toBe(
			'BlackVeil-Security-Scanner/1.0 (+https://www.blackveilsecurity.com/bot-policy; security@blackveilsecurity.com)',
		);
	});
});
