import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

// ── Response helpers ─────────────────────────────────────────────────────────

function txtResponse(name: string, records: string[]) {
	return createDohResponse(
		[{ name, type: 16 }],
		records.map((data) => ({ name, type: 16, TTL: 300, data: `"${data}"` })),
	);
}

function cnameResponse(name: string, cname: string) {
	return createDohResponse(
		[{ name, type: 5 }],
		[{ name, type: 5, TTL: 300, data: `${cname}.` }],
	);
}

function nsResponse(name: string, nameservers: string[]) {
	return createDohResponse(
		[{ name, type: 2 }],
		nameservers.map((ns) => ({ name, type: 2, TTL: 300, data: ns })),
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

// ── Tests ────────────────────────────────────────────────────────────────────

describe('checkSubdomailing', () => {
	async function run(domain = 'example.com') {
		const { checkSubdomailing } = await import('../src/tools/check-subdomailing');
		return checkSubdomailing(domain);
	}

	it('returns info when domain has no SPF record', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=TXT') || url.includes('type=16')) {
				return Promise.resolve(txtResponse('example.com', []));
			}
			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run();
		expect(result.category).toBe('subdomailing');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/No SPF record/i);
	});

	it('returns info when SPF has no includes or redirects', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=TXT') || url.includes('type=16')) {
				return Promise.resolve(txtResponse('example.com', ['v=spf1 ip4:192.0.2.0/24 -all']));
			}
			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run();
		expect(result.category).toBe('subdomailing');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/No external SPF includes/i);
	});

	it('returns info when all includes resolve cleanly', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('name=example.com')) {
					return Promise.resolve(txtResponse('example.com', ['v=spf1 include:spf.provider.com -all']));
				}
				if (url.includes('spf.provider.com')) {
					return Promise.resolve(txtResponse('spf.provider.com', ['v=spf1 ip4:203.0.113.0/24 -all']));
				}
				return Promise.resolve(txtResponse('unknown', []));
			}
			if (url.includes('type=CNAME') || url.includes('type=5')) {
				return Promise.resolve(emptyResponse('spf.provider.com', 5));
			}
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('spf.provider.com', ['ns1.provider.com.', 'ns2.provider.com.']));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(aResponse('ns1.provider.com', ['198.51.100.1']));
			}
			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run();
		expect(result.category).toBe('subdomailing');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/No SubdoMailing risk/i);
	});

	it('detects dangling CNAME in SPF include chain (critical)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('name=example.com')) {
					return Promise.resolve(txtResponse('example.com', ['v=spf1 include:mail.abandoned.com -all']));
				}
				// abandoned include domain has no SPF (but we'll detect CNAME first)
				return Promise.resolve(txtResponse('mail.abandoned.com', []));
			}
			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes('mail.abandoned.com')) {
					return Promise.resolve(cnameResponse('mail.abandoned.com', 'old-app.herokuapp.com'));
				}
				return Promise.resolve(emptyResponse('unknown', 5));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				// CNAME target does not resolve (dangling)
				if (url.includes('old-app.herokuapp.com')) {
					return Promise.resolve(emptyResponse('old-app.herokuapp.com', 1));
				}
				return Promise.resolve(aResponse('unknown', ['1.2.3.4']));
			}
			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run();
		expect(result.category).toBe('subdomailing');
		const critical = result.findings.find((f) => f.severity === 'critical');
		expect(critical).toBeDefined();
		expect(critical!.title).toContain('Dangling CNAME');
		expect(critical!.detail).toContain('herokuapp.com');
		expect(critical!.metadata?.riskType).toBe('dangling_cname');
	});

	it('detects dangling NS in SPF include chain (high)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('name=example.com')) {
					return Promise.resolve(txtResponse('example.com', ['v=spf1 include:mail.delegated.com -all']));
				}
				if (url.includes('mail.delegated.com')) {
					return Promise.resolve(txtResponse('mail.delegated.com', ['v=spf1 ip4:10.0.0.0/8 -all']));
				}
				return Promise.resolve(txtResponse('unknown', []));
			}
			if (url.includes('type=CNAME') || url.includes('type=5')) {
				return Promise.resolve(emptyResponse('mail.delegated.com', 5));
			}
			if (url.includes('type=NS') || url.includes('type=2')) {
				if (url.includes('mail.delegated.com')) {
					return Promise.resolve(nsResponse('mail.delegated.com', ['ns1.expired-provider.com.', 'ns2.expired-provider.com.']));
				}
				return Promise.resolve(emptyResponse('unknown', 2));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				// NS targets do not resolve
				if (url.includes('expired-provider.com')) {
					return Promise.resolve(emptyResponse('ns1.expired-provider.com', 1));
				}
				return Promise.resolve(aResponse('unknown', ['1.2.3.4']));
			}
			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run();
		expect(result.category).toBe('subdomailing');
		const high = result.findings.find((f) => f.severity === 'high');
		expect(high).toBeDefined();
		expect(high!.title).toContain('Dangling NS');
		expect(high!.detail).toContain('expired-provider.com');
		expect(high!.metadata?.riskType).toBe('dangling_ns');
	});

	it('detects void SPF include (low)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('name=example.com')) {
					return Promise.resolve(txtResponse('example.com', ['v=spf1 include:stale.vendor.com -all']));
				}
				// Included domain has no SPF record
				if (url.includes('stale.vendor.com')) {
					return Promise.resolve(txtResponse('stale.vendor.com', ['google-site-verification=abc123']));
				}
				return Promise.resolve(txtResponse('unknown', []));
			}
			if (url.includes('type=CNAME') || url.includes('type=5')) {
				return Promise.resolve(emptyResponse('stale.vendor.com', 5));
			}
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('stale.vendor.com', ['ns1.vendor.com.', 'ns2.vendor.com.']));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(aResponse('ns1.vendor.com', ['198.51.100.10']));
			}
			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run();
		expect(result.category).toBe('subdomailing');
		const low = result.findings.find((f) => f.severity === 'low');
		expect(low).toBeDefined();
		expect(low!.title).toContain('Void SPF include');
		expect(low!.metadata?.riskType).toBe('void_include');
	});

	it('handles mixed findings across multiple includes', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('name=example.com')) {
					return Promise.resolve(
						txtResponse('example.com', ['v=spf1 include:good.provider.com include:bad.abandoned.com -all']),
					);
				}
				if (url.includes('good.provider.com')) {
					return Promise.resolve(txtResponse('good.provider.com', ['v=spf1 ip4:203.0.113.0/24 -all']));
				}
				// bad.abandoned.com has no TXT at all
				return Promise.resolve(txtResponse('bad.abandoned.com', []));
			}
			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes('bad.abandoned.com')) {
					return Promise.resolve(cnameResponse('bad.abandoned.com', 'old.herokuapp.com'));
				}
				return Promise.resolve(emptyResponse('good.provider.com', 5));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				if (url.includes('old.herokuapp.com')) {
					return Promise.resolve(emptyResponse('old.herokuapp.com', 1));
				}
				return Promise.resolve(aResponse('unknown', ['1.2.3.4']));
			}
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('good.provider.com', ['ns1.provider.com.']));
			}
			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run();
		expect(result.category).toBe('subdomailing');
		// Should have at least one critical finding for the dangling CNAME
		const critical = result.findings.find((f) => f.severity === 'critical');
		expect(critical).toBeDefined();
		expect(critical!.metadata?.includeDomain).toBe('bad.abandoned.com');
	});

	it('handles DNS query failures gracefully', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

		const result = await run();
		expect(result.category).toBe('subdomailing');
		// When SPF fetch fails, check treats it as no SPF → info finding
		expect(result.findings.length).toBeGreaterThanOrEqual(1);
		expect(result.findings[0].severity).toBe('info');
	});

	it('follows SPF redirect mechanism', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('name=example.com')) {
					return Promise.resolve(txtResponse('example.com', ['v=spf1 redirect=_spf.redirected.com']));
				}
				if (url.includes('_spf.redirected.com')) {
					return Promise.resolve(txtResponse('_spf.redirected.com', ['v=spf1 ip4:198.51.100.0/24 -all']));
				}
				return Promise.resolve(txtResponse('unknown', []));
			}
			if (url.includes('type=CNAME') || url.includes('type=5')) {
				return Promise.resolve(emptyResponse('_spf.redirected.com', 5));
			}
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('_spf.redirected.com', ['ns1.redirected.com.']));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(aResponse('ns1.redirected.com', ['198.51.100.1']));
			}
			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run();
		expect(result.category).toBe('subdomailing');
		// redirect domain should be probed and clean
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
	});
});
