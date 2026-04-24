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
		// Dual-fetch fires 2 parallel HEAD probes (both 403 → unusable, returns null),
		// then the package runs its own HEAD + GET fallback = 4 calls total.
		expect(fetchSpy).toHaveBeenCalledTimes(4);
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
		// With dual-fetch, HEAD is called multiple times (2 parallel probes + package HEAD).
		// Route by method: all HEADs return 403, GET returns the full headers.
		const fetchSpy = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
			if (init?.method === 'GET') {
				return Promise.resolve({ ok: true, status: 200, headers: fullHeaders });
			}
			return Promise.resolve({ ok: false, status: 403, headers: new Headers() });
		});
		globalThis.fetch = fetchSpy;
		const result = await run();
		expect(result.passed).toBe(true);
		expect(result.findings[0].title).toBe('HTTP security headers well configured');
		// At least one GET call must have been made as the package's fallback.
		const getCalls = fetchSpy.mock.calls.filter((call: unknown[]) => {
			const init = call[1] as RequestInit | undefined;
			return init?.method === 'GET';
		});
		expect(getCalls.length).toBeGreaterThanOrEqual(1);
		expect(getCalls[0][0]).toBe('https://example.com');
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
		// Dual-fetch fires 2 HEAD probes before the package runs. Route by method:
		// all HEADs return 405, GET returns the full headers.
		const fetchSpy = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
			if (init?.method === 'GET') {
				return Promise.resolve({ ok: true, status: 200, headers: fullHeaders });
			}
			return Promise.resolve({ ok: false, status: 405, headers: new Headers() });
		});
		globalThis.fetch = fetchSpy;
		const result = await run();
		expect(result.passed).toBe(true);
		const getCalls = fetchSpy.mock.calls.filter((call: unknown[]) => {
			const init = call[1] as RequestInit | undefined;
			return init?.method === 'GET';
		});
		expect(getCalls.length).toBeGreaterThanOrEqual(1);
		expect(getCalls[0][0]).toBe('https://example.com');
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

	it('returns inconclusive when response matches a WAF/CDN challenge fingerprint', async () => {
		const { restore } = setupFetchMock();
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			headers: new Headers({
				'cf-ray': '88abc123-SFO',
				server: 'cloudflare',
				'content-type': 'text/html; charset=UTF-8',
			}),
			text: async () => '<html><head><title>Just a moment...</title></head><body></body></html>',
		} as unknown as Response);
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		const result = await checkHttpSecurity('example.com');
		// WAF challenge → error/inconclusive status
		expect(result.checkStatus).toBe('error');
		// Single finding identifying the WAF interception
		expect(result.findings.some((f) => f.metadata?.wafChallenge !== undefined)).toBe(true);
		// No header-missing findings — they'd be about the WAF, not the site
		expect(
			result.findings.some(
				(f) =>
					f.title.startsWith('No ') ||
					f.title.toLowerCase().includes('missing') ||
					f.title.toLowerCase().includes('header'),
			),
		).toBe(false);
		restore();
	});
});

describe('checkHttpSecurity — dual-fetch header union', () => {
	async function run(domain = 'example.com') {
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		return checkHttpSecurity(domain);
	}

	it('merges headers from two fetches (union): no missing-XCTO or missing-XFO findings', async () => {
		// First fetch has CSP (no frame-ancestors) + XCTO but no XFO.
		// Second fetch has CSP (no frame-ancestors) + XFO but no XCTO.
		// Without union, the first fetch's headers would trigger a missing-XFO finding;
		// the second fetch's headers alone would trigger missing-XCTO. Union resolves both.
		let callCount = 0;
		globalThis.fetch = vi.fn().mockImplementation(() => {
			callCount++;
			if (callCount <= 1) {
				return Promise.resolve({
					ok: true,
					status: 200,
					type: 'basic',
					headers: new Headers({
						'content-security-policy': "default-src 'self'",
						'x-content-type-options': 'nosniff',
						'permissions-policy': 'camera=()',
						'referrer-policy': 'no-referrer',
						'cross-origin-resource-policy': 'same-origin',
						'cross-origin-opener-policy': 'same-origin',
						'cross-origin-embedder-policy': 'require-corp',
					}),
				});
			}
			return Promise.resolve({
				ok: true,
				status: 200,
				type: 'basic',
				headers: new Headers({
					'content-security-policy': "default-src 'self'",
					'x-frame-options': 'DENY',
					'permissions-policy': 'camera=()',
					'referrer-policy': 'no-referrer',
					'cross-origin-resource-policy': 'same-origin',
					'cross-origin-opener-policy': 'same-origin',
					'cross-origin-embedder-policy': 'require-corp',
				}),
			});
		});
		const result = await run();
		// Union of headers means both XCTO and XFO are present → no findings for either
		const xctoFinding = result.findings.find((f) => f.title === 'No X-Content-Type-Options');
		const xfoFinding = result.findings.find((f) => f.title === 'No X-Frame-Options');
		expect(xctoFinding).toBeUndefined();
		expect(xfoFinding).toBeUndefined();
		// Should have "well configured" info finding
		expect(result.findings[0].title).toBe('HTTP security headers well configured');
	});

	it('uses single response when one fetch fails', async () => {
		let callCount = 0;
		globalThis.fetch = vi.fn().mockImplementation(() => {
			callCount++;
			if (callCount <= 1) {
				// First fetch: succeeds with some headers
				return Promise.resolve({
					ok: true,
					status: 200,
					type: 'basic',
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
			}
			// Second fetch: fails
			return Promise.reject(new Error('ECONNREFUSED'));
		});
		const result = await run();
		// Should still work with the first fetch's headers
		expect(result.category).toBe('http_security');
		const cspFinding = result.findings.find((f) => f.title === 'No Content-Security-Policy');
		expect(cspFinding).toBeUndefined(); // CSP was present in first fetch
	});

	it('falls through to error handling when both fetches fail', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('medium');
		expect(result.findings[0].title).toMatch(/connection failed/i);
	});

	it('produces identical result when both fetches return same headers', async () => {
		const headers = new Headers({
			'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
			'cross-origin-embedder-policy': 'require-corp',
		});
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			type: 'basic',
			headers,
		});
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toBe('HTTP security headers well configured');
	});

	// ---- Total-budget guard (production probe showed 28s outliers) ----

	it('caps total wall time even when every fetch hangs', async () => {
		// Every fetch hangs forever — package-internal sequential fetches would
		// otherwise compound to ≫ the per-fetch HTTPS_TIMEOUT_MS.
		globalThis.fetch = vi.fn().mockImplementation(
			() => new Promise<Response>(() => {/* never resolves */}),
		);

		const start = Date.now();
		const result = await run('slow.example.com');
		const elapsed = Date.now() - start;

		// Total-budget cap (implementation): 10_000 ms. Test tolerates 12s wall.
		expect(elapsed).toBeLessThan(12_000);
		expect(result.category).toBe('http_security');
		expect(result.checkStatus === 'timeout' || result.checkStatus === 'error').toBe(true);
		// Surfaced as a timeout finding
		const timeoutFinding = result.findings.find(
			(f) => /timed? out|total budget|could not complete/i.test(f.title),
		);
		expect(timeoutFinding).toBeDefined();
	}, 15_000);
});
