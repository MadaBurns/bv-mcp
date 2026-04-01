// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { checkTLSRPT } from '../../checks/check-tlsrpt';
import { checkBIMI } from '../../checks/check-bimi';
import { checkCAA } from '../../checks/check-caa';
import { checkMX } from '../../checks/check-mx';
import { checkNS } from '../../checks/check-ns';
import { checkSVCBHTTPS } from '../../checks/check-svcb-https';
import { checkDANEHTTPS } from '../../checks/check-dane-https';
import { checkDANE } from '../../checks/check-dane';
import { checkSSL } from '../../checks/check-ssl';
import { checkHTTPSecurity } from '../../checks/check-http-security';
import { checkSubdomainTakeover } from '../../checks/check-subdomain-takeover';
import { checkMTASTS } from '../../checks/check-mta-sts';
import type { DNSQueryFunction, FetchFunction } from '../../types';

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => {
		return records[domain] ?? [];
	});
}

describe('checkTLSRPT', () => {
	it('returns low when no TLS-RPT record found', async () => {
		const queryDNS = createMockDNS({ '_smtp._tls.example.com': [] });
		const result = await checkTLSRPT('example.com', queryDNS);
		expect(result.category).toBe('tlsrpt');
		expect(result.findings[0].title).toBe('No TLS-RPT record found');
	});

	it('returns info for valid TLS-RPT', async () => {
		const queryDNS = createMockDNS({
			'_smtp._tls.example.com': ['v=TLSRPTv1; rua=mailto:tls@example.com'],
		});
		const result = await checkTLSRPT('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'TLS-RPT record configured')).toBe(true);
	});
});

describe('checkBIMI', () => {
	it('returns info when no BIMI and no DMARC enforcement', async () => {
		const queryDNS = createMockDNS({
			'default._bimi.example.com': [],
			'_dmarc.example.com': ['v=DMARC1; p=none'],
		});
		const result = await checkBIMI('example.com', queryDNS);
		expect(result.findings[0].title).toBe('No BIMI record (DMARC not enforcing)');
	});

	it('returns low when no BIMI but DMARC is enforcing', async () => {
		const queryDNS = createMockDNS({
			'default._bimi.example.com': [],
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await checkBIMI('example.com', queryDNS);
		expect(result.findings[0].title).toBe('No BIMI record found');
		expect(result.findings[0].severity).toBe('low');
	});
});

describe('checkCAA', () => {
	it('returns medium when no CAA records', async () => {
		const queryDNS = createMockDNS({ 'example.com': [] });
		const result = await checkCAA('example.com', queryDNS);
		expect(result.findings[0].title).toBe('No CAA records');
		expect(result.passed).toBe(false);
		expect(result.score).toBe(0);
	});

	it('returns info for properly configured CAA', async () => {
		const queryDNS = createMockDNS({
			'example.com': [
				'0 issue "letsencrypt.org"',
				'0 issuewild "letsencrypt.org"',
				'0 iodef "mailto:security@example.com"',
			],
		});
		const result = await checkCAA('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'CAA properly configured')).toBe(true);
	});
});

describe('checkMX', () => {
	it('returns medium when no MX records', async () => {
		const queryDNS = createMockDNS({ 'example.com': [] });
		const result = await checkMX('example.com', queryDNS);
		expect(result.findings[0].title).toBe('No MX records found');
		expect(result.passed).toBe(false);
		expect(result.score).toBe(0);
	});

	it('detects null MX record', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['0 .'],
		});
		const result = await checkMX('example.com', queryDNS);
		expect(result.findings.some((f) => f.title.includes('Null MX'))).toBe(true);
	});

	it('detects single MX', async () => {
		const mockDNS: DNSQueryFunction = vi.fn(async (domain: string, type: string) => {
			if (domain === 'example.com' && type === 'MX') return ['10 mail.example.com'];
			if (domain === 'mail.example.com' && type === 'A') return ['1.2.3.4'];
			return [];
		});
		const result = await checkMX('example.com', mockDNS);
		expect(result.findings.some((f) => f.title === 'Single MX record')).toBe(true);
	});
});

describe('checkNS', () => {
	it('returns critical when NS query fails', async () => {
		const queryDNS: DNSQueryFunction = vi.fn(async () => { throw new Error('fail'); });
		const result = await checkNS('example.com', queryDNS);
		expect(result.findings[0].severity).toBe('critical');
	});

	it('detects single nameserver', async () => {
		const queryDNS = createMockDNS({ 'example.com': ['ns1.example.com.'] });
		const result = await checkNS('example.com', queryDNS);
		expect(result.findings.some((f) => f.title.includes('Single nameserver'))).toBe(true);
	});
});

describe('checkSVCBHTTPS', () => {
	it('returns low when no HTTPS records', async () => {
		const queryDNS = createMockDNS({ 'example.com': [] });
		const result = await checkSVCBHTTPS('example.com', queryDNS);
		expect(result.findings[0].title).toBe('No HTTPS record found');
		expect(result.passed).toBe(false);
		expect(result.score).toBe(0);
	});

	it('detects H3 ALPN', async () => {
		const queryDNS = createMockDNS({
			'example.com': ['1 . alpn="h2,h3"'],
		});
		const result = await checkSVCBHTTPS('example.com', queryDNS);
		expect(result.findings.some((f) => f.title.includes('HTTP/3'))).toBe(true);
	});
});

describe('checkDANEHTTPS', () => {
	it('returns low when no TLSA records', async () => {
		const queryDNS = createMockDNS({});
		const result = await checkDANEHTTPS('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'No DANE TLSA for HTTPS')).toBe(true);
	});
});

describe('checkDANE', () => {
	it('returns findings for absent DANE', async () => {
		const mockDNS: DNSQueryFunction = vi.fn(async (domain: string, type: string) => {
			if (type === 'MX') return ['10 mail.example.com'];
			return [];
		});
		const result = await checkDANE('example.com', mockDNS);
		expect(result.findings.some((f) => f.title === 'No DANE TLSA for MX servers')).toBe(true);
	});
});

describe('checkSSL', () => {
	it('reports HTTPS and HSTS configured for valid response', async () => {
		const fetchFn: FetchFunction = vi.fn(async (url: string) => {
			if (url.startsWith('https://')) {
				return new Response('', {
					status: 200,
					headers: { 'strict-transport-security': 'max-age=31536000; includeSubDomains' },
				});
			}
			// HTTP redirect to HTTPS
			return new Response('', {
				status: 301,
				headers: { 'location': 'https://example.com/' },
			});
		});
		const result = await checkSSL('example.com', fetchFn);
		expect(result.findings.some((f) => f.title === 'HTTPS and HSTS properly configured')).toBe(true);
	});

	it('reports connection failure', async () => {
		const fetchFn: FetchFunction = vi.fn(async () => { throw new Error('Connection failed'); });
		const result = await checkSSL('example.com', fetchFn);
		expect(result.findings.some((f) => f.title === 'HTTPS connection failed')).toBe(true);
	});
});

describe('checkHTTPSecurity', () => {
	it('reports missing security headers', async () => {
		const fetchFn: FetchFunction = vi.fn(async () => new Response('', { status: 200 }));
		const result = await checkHTTPSecurity('example.com', fetchFn);
		expect(result.findings.some((f) => f.title === 'No Content-Security-Policy')).toBe(true);
	});

	it('reports all headers configured', async () => {
		const fetchFn: FetchFunction = vi.fn(async () => new Response('', {
			status: 200,
			headers: {
				'content-security-policy': "default-src 'self'",
				'x-frame-options': 'DENY',
				'x-content-type-options': 'nosniff',
				'permissions-policy': 'geolocation=()',
				'referrer-policy': 'strict-origin-when-cross-origin',
				'cross-origin-resource-policy': 'same-origin',
				'cross-origin-opener-policy': 'same-origin',
			},
		}));
		const result = await checkHTTPSecurity('example.com', fetchFn);
		expect(result.findings.some((f) => f.title === 'HTTP security headers well configured')).toBe(true);
	});
});

describe('checkSubdomainTakeover', () => {
	it('returns info when no takeover vectors found', async () => {
		const queryDNS = createMockDNS({});
		const result = await checkSubdomainTakeover('example.com', queryDNS);
		expect(result.findings[0].title).toBe('No dangling CNAME records found');
	});

	it('detects dangling CNAME to takeover service', async () => {
		const mockDNS: DNSQueryFunction = vi.fn(async (domain: string, type: string) => {
			if (domain === 'staging.example.com' && type === 'CNAME') return ['example.herokuapp.com.'];
			if (domain === 'example.herokuapp.com' && type === 'A') return [];
			return [];
		});
		const result = await checkSubdomainTakeover('example.com', mockDNS);
		expect(result.findings.some((f) => f.title.includes('Dangling CNAME'))).toBe(true);
	});
});

describe('checkMTASTS', () => {
	it('reports missing MTA-STS and TLS-RPT records', async () => {
		const queryDNS = createMockDNS({
			'_mta-sts.example.com': [],
			'_smtp._tls.example.com': [],
		});
		const result = await checkMTASTS('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'No MTA-STS or TLS-RPT records found')).toBe(true);
		expect(result.passed).toBe(false);
		expect(result.score).toBe(0);
	});
});
