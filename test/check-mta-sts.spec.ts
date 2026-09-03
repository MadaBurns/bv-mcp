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
	return new Response(body, { status });
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

	it('rejects a chunked policy at cap plus one and cancels the stream', async () => {
		const cancelled = vi.fn();
		let pull = 0;
		const policyFetch = new Response(
			new ReadableStream<Uint8Array>({
				pull(controller) {
					if (pull++ === 0) controller.enqueue(new Uint8Array(65_536));
					else if (pull === 2) controller.enqueue(new Uint8Array([1]));
					else if (pull === 3) controller.enqueue(new Uint8Array([2]));
					else controller.close();
				},
				cancel: cancelled,
			}),
			{ status: 200 },
		);
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']),
			policyFetch,
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});

		const result = await run();
		expect(result.findings.some((finding) => finding.title === 'MTA-STS policy file oversized')).toBe(true);
		expect(cancelled).toHaveBeenCalledOnce();
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

	it('a rejected _mta-sts DNS lookup is NOT ASSESSED (checkStatus error), not a scored low finding (#889)', async () => {
		mockMultiFetch({
			dnsError: new Error('DNS timeout'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		// Pre-#889: a `low` "MTA-STS DNS query failed" with no checkStatus → category 95, scored.
		expect(r.findings.some((f) => f.title.includes('DNS query failed'))).toBe(false);
		expect(r.checkStatus).toBe('error');
		expect(r.score).toBe(0);
		expect(r.passed).toBe(false);
		expect(r.partial).toBe(true);
		const f = r.findings.find((f) => f.metadata?.inconclusive === true);
		expect(f?.severity).toBe('info');
		expect(f?.metadata?.notAssessedReason).toBe('dns_query_failed');
		// Unknown, never a fabricated absence.
		expect(r.recordPresent).toBeUndefined();
		expect(r.controlPresent).toBeUndefined();
	});

	it('a policy fetch network error is NOT ASSESSED (checkStatus error, retryable), not a scored medium finding (#889)', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']),
			policyError: Object.assign(new TypeError('Network error'), { name: 'TypeError' }),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		// Pre-#889: a `medium` "MTA-STS policy fetch failed" with no checkStatus → category 85, scored.
		expect(r.findings.some((f) => f.title.includes('fetch failed'))).toBe(false);
		expect(r.findings.some((f) => f.severity === 'medium' || f.severity === 'high')).toBe(false);
		expect(r.checkStatus).toBe('error');
		expect(r.score).toBe(0);
		expect(r.partial).toBe(true);
		expect(r.findings.find((f) => f.metadata?.inconclusive === true)?.severity).toBe('info');
		// The _mta-sts record WAS observed — still credited.
		expect(r.controlPresent).toBe(true);
		expect(r.recordPresent).toBe(true);
	});

	it('a rejected _smtp._tls DNS lookup is NOT ASSESSED, never recorded as a measured TLS-RPT absence (#889)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				if (url.includes('_smtp._tls.')) return Promise.reject(new Error('SERVFAIL'));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('mta-sts.') && url.includes('.well-known')) {
				return Promise.resolve(policyResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
			}
			return Promise.resolve(policyResponse('', 404));
		});
		const r = await run();
		expect(r.findings.some((f) => f.title === 'TLS-RPT DNS query failed')).toBe(false);
		expect(r.findings.some((f) => f.title === 'TLS-RPT record missing')).toBe(false);
		expect(r.checkStatus).toBe('error');
		expect(r.score).toBe(0);
		expect(r.partial).toBe(true);
		expect(r.findings.find((f) => f.metadata?.inconclusive === true)?.metadata?.notAssessedReason).toBe('dns_query_failed');
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

/**
 * Scoring model 1.6.0 — MTA-STS absence is GRADED, not category-zeroing.
 *
 * Corpus evidence (2026-08-03, 1,000 domains): the `mta_sts` category scored a mean of 3.3
 * with 96.5% of the 687 measured domains at exactly 0. Zeroing on absence made MTA-STS a flat
 * constant penalty on ~3 of the ~80 base points rather than a discriminator, so the absence
 * paths dropped `missingControl: true`. Weight (3, protective), tier and severities unchanged.
 *
 * The invariant these lock: ABSENCE grades; DEPLOYED-BUT-BROKEN still penalises confidently.
 */
describe('checkMtaSts — absence is graded, not category-zeroing (scoring model 1.6.0)', () => {
	async function run(domain = 'example.com') {
		const { checkMtaSts } = await import('../src/tools/check-mta-sts');
		return checkMtaSts(domain);
	}

	it('MX present, no MTA-STS and no TLS-RPT: medium finding, score 85, passed, no missingControl', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', []),
			tlsrptDns: txtResponse('_smtp._tls.example.com', []),
			mxDns: mxResponse('example.com', [{ priority: 10, exchange: 'mx1.example.com' }]),
		});
		const r = await run();
		const missing = r.findings.find((f) => f.title.includes('No MTA-STS'));
		expect(missing).toBeDefined();
		expect(missing!.severity).toBe('medium');
		expect(missing!.metadata?.missingControl).not.toBe(true);
		expect(r.score).toBe(85);
		expect(r.passed).toBe(true);
	});

	it('MX present, TLS-RPT present but no MTA-STS record: medium finding, no missingControl', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', []),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
			mxDns: mxResponse('example.com', [{ priority: 10, exchange: 'mx1.example.com' }]),
		});
		const r = await run();
		const missing = r.findings.find((f) => f.title === 'No MTA-STS record found');
		expect(missing).toBeDefined();
		expect(missing!.severity).toBe('medium');
		expect(r.findings.every((f) => f.metadata?.missingControl !== true)).toBe(true);
		expect(r.passed).toBe(true);
	});

	it('no MX at all: low finding, no missingControl (unchanged non-mail path)', async () => {
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', []),
			tlsrptDns: txtResponse('_smtp._tls.example.com', []),
		});
		const r = await run();
		const missing = r.findings.find((f) => f.title.includes('No MTA-STS'));
		expect(missing!.severity).toBe('low');
		expect(missing!.metadata?.missingControl).not.toBe(true);
		expect(r.score).toBe(95);
	});

	it('DEPLOYED-BUT-BROKEN policy still penalises confidently — absence relief must not leak to it', async () => {
		// Record published, policy file missing its `version:` and `mode:` → the package's
		// confident `high` findings. Those never carried `missingControl`, so 1.6.0 leaves them
		// untouched and they must still drive the category below a passing score.
		mockMultiFetch({
			mtaStsDns: txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']),
			policyFetch: policyResponse('max_age: 604800'),
			tlsrptDns: txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
		});
		const r = await run();
		expect(r.findings.some((f) => f.severity === 'high')).toBe(true);
		expect(r.findings.some((f) => f.title.includes('No MTA-STS'))).toBe(false);
		expect(r.score).toBeLessThan(60);
		expect(r.passed).toBe(false);
	});
});
