import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
});

/**
 * Build a DoH TXT response for a given domain.
 */
function txtResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 16 }],
		records.map((data) => ({ name: domain, type: 16, TTL: 300, data: `"${data}"` })),
	);
}

/**
 * Build a plain-text HTTP response (for the MTA-STS policy file).
 */
function policyResponse(body: string, status = 200) {
	return {
		ok: status >= 200 && status < 300,
		status,
		text: () => Promise.resolve(body),
	} as unknown as Response;
}

/**
 * Multi-dispatch fetch mock that routes based on the request URL.
 * - URLs containing "cloudflare-dns.com" with `name=_mta-sts.` → mtaStsDns
 * - URLs containing "cloudflare-dns.com" with `name=_smtp._tls.` → tlsrptDns
 * - URLs containing "mta-sts." and ".well-known" → policyFetch
 */
function mockMultiFetch(opts: {
	mtaStsDns?: Response;
	tlsrptDns?: Response;
	policyFetch?: Response;
	policyError?: Error;
	dnsError?: Error;
}) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('_mta-sts.')) {
				if (opts.dnsError) return Promise.reject(opts.dnsError);
				return Promise.resolve(opts.mtaStsDns ?? txtResponse('_mta-sts.example.com', []));
			}
			if (url.includes('_smtp._tls.')) {
				return Promise.resolve(opts.tlsrptDns ?? txtResponse('_smtp._tls.example.com', []));
			}
		}

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			if (opts.policyError) return Promise.reject(opts.policyError);
			return Promise.resolve(opts.policyFetch ?? policyResponse('', 404));
		}

		return Promise.reject(new Error(`Unexpected fetch URL: ${url}`));
	});
}

describe('checkMtaSts', () => {
	async function run(domain = 'example.com') {
		const { checkMtaSts } = await import('../src/tools/check-mta-sts');
		return checkMtaSts(domain);
	}

	it('returns medium finding when no MTA-STS TXT record found', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', []),
			tlsrptDns: txtResponse('_smtp._tls.example.com', []),
		});
		const r = await run();
		expect(r.category).toBe('mta_sts');
		const f = r.findings.find((f) => f.title.includes('No MTA-STS'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('returns info finding when MTA-STS is properly configured with enforce mode', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']),
			policyFetch: policyResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].title).toContain('properly configured');
		expect(r.findings[0].severity).toBe('info');
	});

	it('returns low finding when MTA-STS is in testing mode', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']),
			policyFetch: policyResponse('version: STSv1\nmode: testing\nmx: *.example.com\nmax_age: 86400'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('testing mode'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});

	it('returns medium finding when MTA-STS mode is none', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']),
			policyFetch: policyResponse('version: STSv1\nmode: none\nmx: *.example.com\nmax_age: 86400'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('disabled'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('returns medium finding for multiple MTA-STS records', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=abc', 'v=STSv1; id=def']),
			policyFetch: policyResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Multiple'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('returns medium finding when id tag is missing', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1']),
			policyFetch: policyResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('missing id'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('returns high finding when policy file is not accessible', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']),
			policyFetch: policyResponse('', 404),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('not accessible'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('returns high finding when policy is missing mode directive', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']),
			policyFetch: policyResponse('version: STSv1\nmx: *.example.com\nmax_age: 86400'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('missing mode'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('returns high finding when policy is missing MX entries', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']),
			policyFetch: policyResponse('version: STSv1\nmode: enforce\nmax_age: 86400'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('missing MX'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('returns low finding on DNS query failure', async () => {
		mockMultiFetch({
			dnsError: new Error('DNS timeout'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', []),
		});
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('DNS query failed'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});

	it('returns medium finding on policy fetch network error', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']),
			policyError: new Error('Network error'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('fetch failed'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('medium');
	});

	it('returns low finding when no TLSRPT record exists', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']),
			policyFetch: policyResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', []),
		});
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('TLS-RPT'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('low');
	});
});
