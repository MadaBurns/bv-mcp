import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('checkSsl', () => {
	async function run(domain = 'example.com') {
		const { checkSsl } = await import('../src/tools/check-ssl');
		return checkSsl(domain);
	}

	it('should return info finding when HTTPS connection succeeds with HSTS', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({
						'strict-transport-security': 'max-age=31536000; includeSubDomains',
						'expect-ct': 'max-age=86400, enforce',
					}),
				});
			}
			// HTTP redirect check
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		expect(result.category).toBe('ssl');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/properly configured/i);
		expect(result.passed).toBe(true);
	});

	it('should return critical finding when HTTPS redirects to HTTP', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: false,
					status: 301,
					headers: new Headers({ location: 'http://example.com/' }),
				});
			}
			return Promise.reject(new Error('HTTP blocked'));
		});
		const result = await run();
		const finding = result.findings.find((f) => /redirects to HTTP/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
	});

	it('should return high finding on connection timeout', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('The operation was aborted due to timeout'));
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('high');
		expect(result.findings[0].title).toMatch(/timeout/i);
	});

	it('should return critical finding on connection failure', async () => {
		mockFetchError(new Error('ECONNREFUSED'));
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('critical');
		expect(result.findings[0].title).toMatch(/failed/i);
	});

	it('should return medium finding when HSTS header is missing', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers(),
				});
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'No HSTS header');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should return low finding when HSTS max-age is too short', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=3600; includeSubDomains' }),
				});
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'HSTS max-age too short');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should return low finding when HSTS missing includeSubDomains', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000' }),
				});
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'HSTS missing includeSubDomains');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should not produce redirect finding when HTTP redirects to HTTPS', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
				});
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const redirectFinding = result.findings.find((f) => f.title.includes('redirect'));
		expect(redirectFinding).toBeUndefined();
	});

	it('should return medium finding when no HTTP to HTTPS redirect', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
				});
			}
			// HTTP returns 200 instead of redirect
			return Promise.resolve({
				ok: true,
				status: 200,
				headers: new Headers(),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'No HTTP to HTTPS redirect');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should NOT emit a redirect finding when the plain-HTTP probe returns a no-content 204 (issue #806)', async () => {
		// A 204 carried no page and measured nothing about redirect posture (observed live:
		// google.com's real http:// answer is a 301, yet a scan emitted "status 204").
		// The sub-probe is skipped, matching the silent-skip posture for a failed HTTP probe.
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
				});
			}
			// Anomalous no-content answer on the http:// probe
			return Promise.resolve({
				ok: true,
				status: 204,
				headers: new Headers(),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'No HTTP to HTTPS redirect');
		expect(finding).toBeUndefined();
	});

	it.each([[204], [205]])(
		'should NOT emit an HSTS finding when the https:// probe returns a no-content %d (issue #806 follow-up)',
		async (status) => {
			// A terminal 204/205 on the https:// leg satisfies neither the redirect nor the
			// error branch, so before the guard its EMPTY header set flowed into
			// getHttpsFindings() and produced a confident scored "No HSTS header" medium
			// finding from a response that delivered no page. Same family as the http:// leg
			// fixed in #819: withhold the verdict, exclude the category.
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.startsWith('https://')) {
					// Anomalous no-content answer on the https:// probe (robots.txt included —
					// an empty robots answer fails open, matching this file's other mocks).
					return Promise.resolve({
						url: 'https://example.com/',
						ok: true,
						status,
						headers: new Headers(),
					});
				}
				return Promise.resolve({
					ok: false,
					status: 301,
					headers: new Headers({ location: 'https://example.com/' }),
				});
			});
			const result = await run();
			expect(result.findings.find((f) => f.title === 'No HSTS header')).toBeUndefined();
			expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
			const marker = result.findings.find((f) => f.metadata?.inconclusive === true);
			expect(marker).toBeDefined();
			expect(marker!.metadata?.errorKind).toBe('no_content');
			expect(result.checkStatus).toBe('error');
		},
	);
});
