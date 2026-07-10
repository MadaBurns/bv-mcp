// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('checkSubdomainTakeover tool — robots.txt', () => {
	async function run(domain: string, subdomains?: string[]) {
		const { checkSubdomainTakeover } = await import('../src/tools/check-subdomain-takeover');
		return checkSubdomainTakeover(domain, { subdomains });
	}

	it('does not throw and produces no false takeover finding when robots.txt disallows the probe', async () => {
		globalThis.fetch = vi.fn().mockImplementation((url: string | URL | Request) => {
			const href = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;
			if (href.endsWith('/robots.txt'))
				return Promise.resolve(new Response('User-agent: *\nDisallow: /\n', { status: 200 }));
			return Promise.resolve(new Response('should not be reached', { status: 200 }));
		});

		const result = await run('example.com', ['www']);
		expect(result.category).toBe('subdomain_takeover');
	});

	it('sends the real scanner User-Agent on the HTTP probe', async () => {
		let capturedUA: string | null = null;
		globalThis.fetch = vi.fn().mockImplementation(async (url: string | URL | Request, init?: RequestInit) => {
			const href = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;
			// DNS queries (DoH) — simulate a CNAME pointing to Heroku so HTTP probe happens
			if (href.includes('cloudflare-dns.com') || href.includes('type=')) {
				if (href.includes('CNAME') || href.includes('type=5')) {
					if (href.includes('www.example.com')) {
						return Promise.resolve(new Response(JSON.stringify({
							Status: 0,
							TC: false,
							RD: true,
							RA: true,
							AD: false,
							CD: false,
							Question: [{ name: 'www.example.com', type: 5 }],
							Answer: [{
								name: 'www.example.com',
								type: 5,
								TTL: 300,
								data: 'www-app.herokuapp.com.'
							}],
						}), { status: 200 }));
					}
				} else if (href.includes('A') || href.includes('type=1')) {
					// A-record for the Heroku CNAME target resolves successfully
					if (href.includes('www-app.herokuapp.com')) {
						return Promise.resolve(new Response(JSON.stringify({
							Status: 0,
							TC: false,
							RD: true,
							RA: true,
							AD: false,
							CD: false,
							Question: [{ name: 'www-app.herokuapp.com', type: 1 }],
							Answer: [{
								name: 'www-app.herokuapp.com',
								type: 1,
								TTL: 300,
								data: '1.2.3.4'
							}],
						}), { status: 200 }));
					}
				}
				// Default: empty response
				return Promise.resolve(new Response(JSON.stringify({
					Status: 0,
					TC: false,
					RD: true,
					RA: true,
					AD: false,
					CD: false,
					Question: [],
					Answer: [],
				}), { status: 200 }));
			}
			// robots.txt requests should have the UA set
			if (href.endsWith('/robots.txt')) {
				const ua = new Headers(init?.headers).get('User-Agent');
				if (ua && ua.includes('BlackVeil')) {
					capturedUA = ua;
				}
				return Promise.resolve(new Response('User-agent: *\n', { status: 200 }));
			}
			// Other requests (like the actual HTTP probes to www-app.herokuapp.com)
			return Promise.resolve(new Response('', { status: 200 }));
		});

		await run('example.com', ['www']);
		expect(capturedUA).toBe(
			'BlackVeil-Security-Scanner/1.0 (+https://www.blackveilsecurity.com/bot-policy; security@blackveilsecurity.com)'
		);
	});
});
