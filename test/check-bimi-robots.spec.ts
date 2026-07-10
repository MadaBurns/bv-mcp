// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('checkBimi tool — robots.txt', () => {
	async function run(domain = 'example.com') {
		const { checkBimi } = await import('../src/tools/check-bimi');
		return checkBimi(domain);
	}

	it('reports a neutral info finding when robots.txt disallows the logo fetch, without ever reaching the logo URL', async () => {
		let logoProbed = false;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.endsWith('/robots.txt')) {
				return Promise.resolve(new Response('User-agent: *\nDisallow: /\n', { status: 200 }));
			}
			if (url.endsWith('.svg')) {
				logoProbed = true;
				return Promise.resolve(new Response('should not be reached', { status: 200 }));
			}
			const parsed = new URL(url);
			const name = parsed.searchParams.get('name') ?? '';
			if (name === 'default._bimi.example.com') {
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 16 }],
						[
							{
								name,
								type: 16,
								TTL: 300,
								data: '"v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"',
							},
						],
					),
				);
			}
			return Promise.resolve(createDohResponse([{ name, type: 16 }], []));
		});

		const result = await run();

		expect(logoProbed).toBe(false);
		const robotsFinding = result.findings.find((f) => f.title.includes('robots.txt'));
		expect(robotsFinding).toBeDefined();
		expect(robotsFinding!.severity).toBe('info');
	});
});
