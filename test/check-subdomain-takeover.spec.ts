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
		expect(result.findings[0].metadata?.verificationStatus).toBe('not_exploitable');
	});

	it('detects dangling CNAME to third-party service (high finding)', async () => {
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
		const high = result.findings.find((f) => f.severity === 'high');
		expect(high).toBeDefined();
		expect(high!.title).toContain('Dangling CNAME');
		expect(high!.title).toContain('staging.example.com');
		expect(high!.title).toContain('herokuapp.com');
		expect(high!.detail).toContain('subdomain takeover');
		expect(high!.metadata?.verificationStatus).toBe('potential');
	});

	it('does not flag third-party CNAME that resolves successfully and has no fingerprint', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNS-over-HTTPS queries go to cloudflare-dns.com
			if (url.includes('cloudflare-dns.com')) {
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
			}

			// HTTP fingerprint probe — return healthy page (no takeover fingerprint)
			return Promise.resolve(new Response('<html><body>Welcome to my app</body></html>', { status: 200 }));
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
		expect(high!.detail).toContain('manual verification');
		expect(high!.metadata?.verificationStatus).toBe('potential');
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

	it('abstains when every outer CNAME query fails (#948)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				// All CNAME queries fail
				return Promise.reject(new Error('Network timeout'));
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		// Nothing was measured, so the clean "no dangling CNAME" verdict must NOT be
		// issued: the category abstains and is excluded from scoring instead.
		expect(result.category).toBe('subdomain_takeover');
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.partial).toBe(true);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toContain('not assessed');
		expect(result.findings[0].metadata?.inconclusive).toBe(true);
		expect(result.findings[0].metadata?.errorKind).toBe('dns_error');
		// #638 law: an unmeasured probe may never claim the control is absent.
		expect(result.findings[0].metadata?.missingControl).toBeUndefined();
		expect((result.findings[0].metadata?.subdomainsUnmeasured as string[]).length).toBeGreaterThan(0);
	});

	it('keeps the clean verdict when only SOME subdomain probes fail (#948)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				// One subdomain's probe fails; every other answers empty.
				if (url.includes('www.example.com')) return Promise.reject(new Error('Network timeout'));
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		// A partial failure still emits the verdict — narrowed to what answered.
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toContain('No dangling CNAME');
		expect(result.findings[0].metadata?.subdomainsUnmeasured).toEqual(['www']);
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
		const highs = result.findings.filter((f) => f.severity === 'high');
		expect(highs).toHaveLength(2);
		expect(highs.some((f) => f.title.includes('staging.example.com'))).toBe(true);
		expect(highs.some((f) => f.title.includes('api.example.com'))).toBe(true);
	});

	it('detects HTTP fingerprint takeover signal on resolving CNAME (Heroku)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					if (url.includes('app.example.com')) {
						return Promise.resolve(cnameResponse('app.example.com', 'old-app.herokuapp.com'));
					}
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
					return Promise.resolve(emptyResponse(name, 5));
				}

				if (url.includes('type=A') || url.includes('type=1')) {
					if (url.includes('old-app.herokuapp.com')) {
						return Promise.resolve(aResponse('old-app.herokuapp.com', ['75.2.60.5']));
					}
				}

				return Promise.resolve(emptyResponse('unknown', 1));
			}

			// HTTP probe returns Heroku deprovisioned fingerprint
			return Promise.resolve(
				new Response('<html><head><title>no-such-app</title></head><body>No such app</body></html>', { status: 404 }),
			);
		});

		const result = await run('example.com');
		const finding = result.findings.find((f) => f.title.includes('Heroku'));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
		expect(finding!.title).toContain('possible takeover signal');
		expect(finding!.detail).toContain('deprovisioned');
		expect(finding!.detail).toContain('not proof of exploitability');
		expect(finding!.metadata?.verificationStatus).toBe('potential');
		expect(finding!.metadata?.evidenceStrength).toBe('provider_deprovisioned_fingerprint');
		expect(finding!.metadata?.proofRequired).toBe('authorized_proof_of_control');
	});

	it('detects HTTP fingerprint takeover signal on resolving CNAME (GitHub Pages)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					if (url.includes('docs.example.com')) {
						return Promise.resolve(cnameResponse('docs.example.com', 'example.github.io'));
					}
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
					return Promise.resolve(emptyResponse(name, 5));
				}

				if (url.includes('type=A') || url.includes('type=1')) {
					if (url.includes('example.github.io')) {
						return Promise.resolve(aResponse('example.github.io', ['185.199.108.153']));
					}
				}

				return Promise.resolve(emptyResponse('unknown', 1));
			}

			// HTTP probe returns GitHub Pages 404 fingerprint
			return Promise.resolve(
				new Response("<html><body>There isn't a GitHub Pages site here.</body></html>", { status: 404 }),
			);
		});

		const result = await run('example.com');
		const finding = result.findings.find((f) => f.title.includes('GitHub Pages'));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
		expect(finding!.title).toContain('possible takeover signal');
		expect(finding!.metadata?.verificationStatus).toBe('potential');
	});

	it('silently skips HTTP fingerprint probe on timeout/error', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					if (url.includes('blog.example.com')) {
						return Promise.resolve(cnameResponse('blog.example.com', 'example.ghost.io'));
					}
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
					return Promise.resolve(emptyResponse(name, 5));
				}

				if (url.includes('type=A') || url.includes('type=1')) {
					if (url.includes('example.ghost.io')) {
						return Promise.resolve(aResponse('example.ghost.io', ['178.128.1.2']));
					}
				}

				return Promise.resolve(emptyResponse('unknown', 1));
			}

			// HTTP probe fails with network error
			return Promise.reject(new Error('Connection refused'));
		});

		const result = await run('example.com');
		// Should not produce a critical finding since the probe errored out
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toContain('No dangling CNAME');
	});

	it('detects dangling CNAME to newly added service (Vercel)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes('staging.example.com')) {
					return Promise.resolve(cnameResponse('staging.example.com', 'cname.vercel-dns.com'));
				}
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			if (url.includes('type=A') || url.includes('type=1')) {
				if (url.includes('cname.vercel-dns.com')) {
					return Promise.resolve(emptyResponse('cname.vercel-dns.com', 1));
				}
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		const high = result.findings.find((f) => f.severity === 'high');
		expect(high).toBeDefined();
		expect(high!.title).toContain('Dangling CNAME');
		expect(high!.title).toContain('vercel-dns.com');
	});
});
