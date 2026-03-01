import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

function cnameResponse(name: string, cname: string) {
	return createDohResponse(
		[{ name, type: 5 }],
		[{ name, type: 5, TTL: 300, data: `${cname}.` }],
	);
}

function aResponse(name: string, ips: string[]) {
	return createDohResponse(
		[{ name, type: 1 }],
		ips.map((ip) => ({ name, type: 1, TTL: 300, data: ip })),
	);
}

function emptyResponse(name: string, type: number) {
	return createDohResponse([{ name, type }], []);
}

describe('checkSubdomainTakeover', () => {
	async function run(domain: string) {
		const { checkSubdomainTakeover } = await import('../src/tools/check-subdomain-takeover');
		return checkSubdomainTakeover(domain);
	}

	it('returns info when no CNAME records found on any subdomain', async () => {
		// All CNAME queries return empty
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=CNAME') || url.includes('type=5')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}
			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		expect(result.category).toBe('subdomain_takeover');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toContain('No dangling CNAME');
	});

	it('detects dangling CNAME to third-party service (critical finding)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				// staging.example.com has a CNAME pointing to herokuapp.com
				if (url.includes('staging.example.com')) {
					return Promise.resolve(cnameResponse('staging.example.com', 'old-app.herokuapp.com'));
				}
				// All other subdomains return empty
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			// A-record lookup for the CNAME target returns empty (dangling)
			if (url.includes('type=A') || url.includes('type=1')) {
				if (url.includes('old-app.herokuapp.com')) {
					return Promise.resolve(emptyResponse('old-app.herokuapp.com', 1));
				}
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		expect(result.category).toBe('subdomain_takeover');
		const critical = result.findings.find((f) => f.severity === 'critical');
		expect(critical).toBeDefined();
		expect(critical!.title).toContain('Dangling CNAME');
		expect(critical!.title).toContain('staging.example.com');
		expect(critical!.title).toContain('herokuapp.com');
		expect(critical!.detail).toContain('subdomain takeover');
	});

	it('does not flag third-party CNAME that resolves successfully', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes('app.example.com')) {
					return Promise.resolve(cnameResponse('app.example.com', 'my-app.herokuapp.com'));
				}
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			// A-record lookup resolves successfully
			if (url.includes('type=A') || url.includes('type=1')) {
				if (url.includes('my-app.herokuapp.com')) {
					return Promise.resolve(aResponse('my-app.herokuapp.com', ['54.243.123.45']));
				}
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		// Should only have the "no dangling CNAME" info finding
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
	});

	it('flags high severity when CNAME resolution fails (throws error)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes('portal.example.com')) {
					return Promise.resolve(cnameResponse('portal.example.com', 'old-site.azurewebsites.net'));
				}
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			// A-record lookup throws an error
			if (url.includes('type=A') || url.includes('type=1')) {
				if (url.includes('old-site.azurewebsites.net')) {
					return Promise.reject(new Error('DNS resolution failed'));
				}
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		const high = result.findings.find((f) => f.severity === 'high');
		expect(high).toBeDefined();
		expect(high!.title).toContain('CNAME resolution failed');
		expect(high!.detail).toContain('Manual review recommended');
	});

	it('ignores non-third-party CNAME records (no finding)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				// CNAME pointing to own infrastructure, not a third-party takeover service
				if (url.includes('www.example.com')) {
					return Promise.resolve(cnameResponse('www.example.com', 'lb.example.com'));
				}
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		// Non-third-party CNAME should not trigger any findings
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toContain('No dangling CNAME');
	});

	it('handles outer CNAME query failure gracefully', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				// All CNAME queries fail
				return Promise.reject(new Error('Network timeout'));
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		// Should gracefully handle failures — no dangling CNAME found
		expect(result.category).toBe('subdomain_takeover');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
	});

	it('detects multiple dangling CNAMEs across subdomains', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes('staging.example.com')) {
					return Promise.resolve(cnameResponse('staging.example.com', 'old.herokuapp.com'));
				}
				if (url.includes('api.example.com')) {
					return Promise.resolve(cnameResponse('api.example.com', 'dead.cloudfront.net'));
				}
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			// Both A-record lookups return empty
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 1));
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		const criticals = result.findings.filter((f) => f.severity === 'critical');
		expect(criticals).toHaveLength(2);
		expect(criticals.some((f) => f.title.includes('staging.example.com'))).toBe(true);
		expect(criticals.some((f) => f.title.includes('api.example.com'))).toBe(true);
	});
});
