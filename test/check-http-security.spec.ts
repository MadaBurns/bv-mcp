// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('checkHttpSecurity', () => {
	async function run(domain = 'example.com') {
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		return checkHttpSecurity(domain);
	}

	it('should return info finding when all headers present', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			headers: new Headers({
				'content-security-policy': "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
				'x-frame-options': 'DENY',
				'x-content-type-options': 'nosniff',
				'permissions-policy': 'camera=(), microphone=()',
				'referrer-policy': 'strict-origin-when-cross-origin',
				'cross-origin-resource-policy': 'same-origin',
				'cross-origin-opener-policy': 'same-origin',
				'cross-origin-embedder-policy': 'require-corp',
			}),
		});
		const result = await run();
		expect(result.category).toBe('http_security');
		expect(result.passed).toBe(true);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toBe('HTTP security headers well configured');
	});

	it('should return high finding for missing CSP', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			headers: new Headers({
				'x-frame-options': 'DENY',
				'x-content-type-options': 'nosniff',
				'permissions-policy': 'camera=()',
				'referrer-policy': 'no-referrer',
				'cross-origin-resource-policy': 'same-origin',
				'cross-origin-opener-policy': 'same-origin',
			}),
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'No Content-Security-Policy');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
	});

	it('should return medium finding on connection timeout', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('The operation was aborted due to timeout'));
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('medium');
		expect(result.findings[0].title).toMatch(/connection timed out/i);
	});

	it('should return medium finding on connection failure', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('medium');
		expect(result.findings[0].title).toMatch(/connection failed/i);
	});

	it('should return medium finding on server 500 error', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 500,
			headers: new Headers(),
		});
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('medium');
		expect(result.findings[0].title).toBe('Server error');
		expect(result.findings[0].detail).toContain('500');
	});

	it('should analyze headers on redirect responses (3xx)', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 301,
			headers: new Headers({
				location: 'https://www.example.com/',
				'content-security-policy': "default-src 'self'",
			}),
		});
		const result = await run();
		// Should still analyze — 301 is < 500
		expect(result.findings.length).toBeGreaterThan(0);
		// CSP is present so no CSP finding, but other headers are missing
		const cspFinding = result.findings.find((f) => f.title === 'No Content-Security-Policy');
		expect(cspFinding).toBeUndefined();
	});

	it('should return multiple findings when multiple headers missing', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			headers: new Headers({}),
		});
		const result = await run();
		// Missing CSP (high), XFO (medium), XCTO (low), PP (low), RP (low), CORP (info), COOP (info), COEP (info) = 8
		expect(result.findings).toHaveLength(8);
		expect(result.score).toBeLessThan(100);
	});

	it('should reflect score penalties from findings', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			headers: new Headers({}),
		});
		const result = await run();
		// high(-25) + medium(-15) + 3*low(-5) + 2*info(0) = -55 → score = 45
		expect(result.score).toBe(45);
		expect(result.passed).toBe(false);
	});

	it('should use HEAD method, manual redirect, and User-Agent header', async () => {
		const fetchSpy = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			headers: new Headers({
				'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
				'x-frame-options': 'DENY',
				'x-content-type-options': 'nosniff',
				'permissions-policy': 'camera=()',
				'referrer-policy': 'no-referrer',
				'cross-origin-resource-policy': 'same-origin',
				'cross-origin-opener-policy': 'same-origin',
			}),
		});
		globalThis.fetch = fetchSpy;
		await run();
		expect(fetchSpy).toHaveBeenCalledWith(
			'https://example.com',
			expect.objectContaining({
				method: 'HEAD',
				redirect: 'manual',
				headers: expect.objectContaining({ 'User-Agent': expect.stringContaining('BlackVeilDNSScanner') }),
			}),
		);
	});

	it('should return blocked finding when 403 HEAD and 403 GET', async () => {
		const fetchSpy = vi.fn().mockResolvedValue({
			ok: false,
			status: 403,
			headers: new Headers(),
		});
		globalThis.fetch = fetchSpy;
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toBe('HTTP check blocked by security appliance');
		expect(result.findings[0].severity).toBe('info');
		expect(result.passed).toBe(false);
		// HEAD + GET = 2 calls
		expect(fetchSpy).toHaveBeenCalledTimes(2);
	});

	it('should analyze real headers when 403 HEAD succeeds with GET', async () => {
		const fullHeaders = new Headers({
			'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
			'cross-origin-embedder-policy': 'require-corp',
		});
		const fetchSpy = vi
			.fn()
			.mockResolvedValueOnce({ ok: false, status: 403, headers: new Headers() })
			.mockResolvedValueOnce({ ok: true, status: 200, headers: fullHeaders });
		globalThis.fetch = fetchSpy;
		const result = await run();
		expect(result.passed).toBe(true);
		expect(result.findings[0].title).toBe('HTTP security headers well configured');
		expect(fetchSpy).toHaveBeenCalledTimes(2);
		expect(fetchSpy).toHaveBeenNthCalledWith(2, 'https://example.com', expect.objectContaining({ method: 'GET' }));
	});

	it('should fall back to GET when HEAD returns 405 Method Not Allowed', async () => {
		const fullHeaders = new Headers({
			'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const fetchSpy = vi
			.fn()
			.mockResolvedValueOnce({ ok: false, status: 405, headers: new Headers() })
			.mockResolvedValueOnce({ ok: true, status: 200, headers: fullHeaders });
		globalThis.fetch = fetchSpy;
		const result = await run();
		expect(result.passed).toBe(true);
		expect(fetchSpy).toHaveBeenNthCalledWith(2, 'https://example.com', expect.objectContaining({ method: 'GET' }));
	});

	it('should return auth finding for 401 response', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 401, headers: new Headers() });
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toBe('HTTP check requires authentication');
		expect(result.findings[0].severity).toBe('info');
		expect(result.passed).toBe(false);
	});

	it('should return rejected finding for other 4xx responses', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 429, headers: new Headers() });
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toBe('HTTP request rejected');
		expect(result.findings[0].severity).toBe('medium');
		expect(result.passed).toBe(false);
	});
});

describe('checkHttpSecurity CDN detection', () => {
	function mockHttpResponse(status: number, headers: Record<string, string>, body = 'OK') {
		globalThis.fetch = vi.fn().mockImplementation(() =>
			Promise.resolve(new Response(body, { status, headers })),
		);
	}

	it('adds INFO finding with Cloudflare as cdnProvider when cf-ray header present', async () => {
		mockHttpResponse(200, {
			'cf-ray': '7a2b3c4d5e6f7a8b-SYD',
			'content-security-policy': "default-src 'self'",
		});
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		const result = await checkHttpSecurity('example.com');
		const cdnFinding = result.findings.find((f) => f.metadata?.cdnProvider);
		expect(cdnFinding).toBeDefined();
		expect(cdnFinding!.severity).toBe('info');
		expect(cdnFinding!.metadata!.cdnProvider).toBe('Cloudflare');
		expect(cdnFinding!.title).toContain('Cloudflare');
	});

	it('adds INFO finding for Vercel via x-vercel-id header', async () => {
		mockHttpResponse(200, { 'x-vercel-id': 'syd1::abc123' });
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		const result = await checkHttpSecurity('example.com');
		const cdnFinding = result.findings.find((f) => f.metadata?.cdnProvider);
		expect(cdnFinding!.metadata!.cdnProvider).toBe('Vercel');
	});

	it('does NOT add CDN finding when no CDN headers present', async () => {
		mockHttpResponse(200, {
			'content-security-policy': "default-src 'self'",
			'x-frame-options': 'SAMEORIGIN',
		});
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		const result = await checkHttpSecurity('example.com');
		const cdnFinding = result.findings.find((f) => f.metadata?.cdnProvider);
		expect(cdnFinding).toBeUndefined();
	});

	it('adds cloudflare finding when server header contains cloudflare', async () => {
		mockHttpResponse(200, { server: 'cloudflare' });
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		const result = await checkHttpSecurity('example.com');
		const cdnFinding = result.findings.find((f) => f.metadata?.cdnProvider === 'Cloudflare');
		expect(cdnFinding).toBeDefined();
	});
});
