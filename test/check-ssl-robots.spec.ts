// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { checkSsl } from '../src/tools/check-ssl';

describe('checkSsl tool — robots.txt', () => {
	it('is gated: a global fetch stub serving Disallow: / excludes the ssl category', async () => {
		const originalFetch = globalThis.fetch;
		globalThis.fetch = (async (url: string | URL | Request) => {
			const href = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;
			if (href.endsWith('/robots.txt'))
				return new Response('User-agent: *\nDisallow: /\n', { status: 200 });
			return new Response(null, { status: 200 });
		}) as typeof fetch;
		try {
			const result = await checkSsl('example.com');
			expect(result.checkStatus).toBe('error');
			expect(result.findings[0]!.detail).toContain('robots.txt');
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
});
