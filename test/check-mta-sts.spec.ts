import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

function txtResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 16 }],
		records.map((data) => ({ name: domain, type: 16, TTL: 300, data: `"${data}"` })),
	);
}

function policyResponse(body: string, status = 200) {
	return {
		ok: status >= 200 && status < 300,
		status,
		text: () => Promise.resolve(body),
	} as unknown as Response;
}

function mxResponse(domain: string, records: Array<{ priority: number; exchange: string }>) {
	return createDohResponse(
		[{ name: domain, type: 15 }],
		records.map((r) => ({ name: domain, type: 15, TTL: 300, data: `${r.priority} ${r.exchange}.` })),
	);
}

function mockMultiFetch(opts: {
	mtaStsDns?: Response;
	policyFetch?: Response;
	policyError?: Error;
	tlsrptDns?: Response;
	mxDns?: Response;
	dnsError?: Error;
}) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (opts.dnsError && url.includes('cloudflare-dns.com') && url.includes('_mta-sts.')) {
			return Promise.reject(opts.dnsError);
		}
		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('_mta-sts.') && opts.mtaStsDns) return Promise.resolve(opts.mtaStsDns);
			if (url.includes('_smtp._tls.') && opts.tlsrptDns) return Promise.resolve(opts.tlsrptDns);
			// MX queries hit the bare domain (no underscore prefix). Use `type=MX`
			// query-param sniffing so the catch-all NS/etc. queries return empty.
			if (url.includes('type=MX') && opts.mxDns) return Promise.resolve(opts.mxDns);
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			if (opts.policyError) return Promise.reject(opts.policyError);
			if (opts.policyFetch) return Promise.resolve(opts.policyFetch);
		}
		return Promise.resolve(policyResponse('', 404));
	});
}

describe('checkMtaSts', () => {
	async function run(domain = 'example.com') {
		const { checkMtaSts } = await import('../src/tools/check-mta-sts');
		return checkMtaSts(domain);
	}

	it('returns medium finding when no MTA-STS TXT record found and domain has MX records', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', []),
			tlsrptDns: txtResponse('_smtp._tls.example.com', []),
			mxDns: mxResponse('example.com', [{ priority: 10, exchange: 'mx1.example.com' }]),
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
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; bogus=value']),
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
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
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

describe('check-mta-sts copy for missing-MTA-STS finding (Defect K)', () => {
	async function run(domain = 'example.com') {
		const { checkMtaSts } = await import('../src/tools/check-mta-sts');
		return checkMtaSts(domain);
	}

	it('uses inbound-mail-active copy when domain has MX records (paypal/stripe pattern)', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', []),
			tlsrptDns: txtResponse('_smtp._tls.example.com', []),
			mxDns: mxResponse('example.com', [{ priority: 10, exchange: 'mx1.example.com' }]),
		});
		const r = await run();
		const missing = r.findings.find((f) => f.title.includes('No MTA-STS'));
		expect(missing).toBeDefined();
		expect(missing!.detail).toContain('accepts inbound email');
		expect(missing!.detail).not.toContain('do not accept inbound email');
		expect(missing!.severity).toBe('medium');
	});

	it('uses non-mail-domain copy when no MX records (gov.uk pattern)', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', []),
			tlsrptDns: txtResponse('_smtp._tls.example.com', []),
			// no mxDns → DoH default empty → no MX
		});
		const r = await run();
		const missing = r.findings.find((f) => f.title.includes('No MTA-STS'));
		expect(missing).toBeDefined();
		expect(missing!.detail).toContain('normal for domains that do not accept inbound email');
		expect(missing!.severity).toBe('low');
	});

	it('treats null MX (RFC 7505) as no inbound email — low severity', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', []),
			tlsrptDns: txtResponse('_smtp._tls.example.com', []),
			mxDns: mxResponse('example.com', [{ priority: 0, exchange: '' }]),
		});
		const r = await run();
		const missing = r.findings.find((f) => f.title.includes('No MTA-STS'));
		expect(missing).toBeDefined();
		expect(missing!.severity).toBe('low');
		expect(missing!.detail).toContain('do not accept inbound email');
	});
});
