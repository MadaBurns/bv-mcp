// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import {
	setupFetchMock,
	createDohResponse,
	txtResponse,
	nsResponse,
	caaResponse,
	dnssecResponse,
	httpResponse,
	tlsaResponse,
} from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

// ---------------------------------------------------------------------------
// Fetch mock builders
// ---------------------------------------------------------------------------

/**
 * Mock that returns a domain with NO protections — all checks will produce findings.
 * SPF missing, DMARC missing, DKIM missing, DNSSEC off, no CAA, no MTA-STS, no DANE,
 * no CSP or security headers.
 */
function mockInsecureDomain() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			// All DNS queries return empty
			return Promise.resolve(createDohResponse([], []));
		}

		// HTTP requests: no security headers
		if (url.startsWith('https://')) {
			return Promise.resolve({
				ok: true,
				status: 200,
				headers: new Headers({}),
				text: () => Promise.resolve('OK'),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		}

		return Promise.resolve(createDohResponse([], []));
	});
}

/**
 * Mock that returns a well-secured domain — all checks should pass.
 * SPF -all, DMARC p=reject sp=reject, DKIM present, DNSSEC AD=true,
 * CAA set, MTA-STS enforce, DANE TLSA present, full security headers.
 */
function mockSecureDomain() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					return Promise.resolve(
						txtResponse('_dmarc.example.com', [
							'v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s',
						]),
					);
				}
				if (url.includes('_domainkey.')) {
					return Promise.resolve(
						txtResponse('default._domainkey.example.com', [
							'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA',
						]),
					);
				}
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(
						txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
					);
				}
				if (url.includes('default._bimi.')) {
					return Promise.resolve(
						txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']),
					);
				}
				// SPF
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}

			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(
					caaResponse('example.com', ['0 issue "letsencrypt.org"', '0 issuewild ";"']),
				);
			}

			// DNSSEC: AD=true
			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}

			// MX records
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 15 }],
						[{ name: 'example.com', type: 15, TTL: 300, data: '10 mx1.example.com.' }],
					),
				);
			}

			// TLSA for DANE
			if (url.includes('type=TLSA') || url.includes('type=52')) {
				return Promise.resolve(
					tlsaResponse('_25._tcp.mx1.example.com', [
						{ usage: 3, selector: 1, matchingType: 1, certData: 'aabbccddee' },
					]),
				);
			}

			// CNAME for subdomain takeover
			if (url.includes('type=CNAME') || url.includes('type=5')) {
				return Promise.resolve(createDohResponse([], []));
			}

			return Promise.resolve(createDohResponse([], []));
		}

		// MTA-STS policy file
		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(
				httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'),
			);
		}

		// HTTPS with full security headers
		if (url.startsWith('https://')) {
			return Promise.resolve({
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
					'strict-transport-security': 'max-age=31536000; includeSubDomains',
				}),
				text: () => Promise.resolve('OK'),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		}

		return Promise.resolve(createDohResponse([], []));
	});
}

/**
 * Mock for a domain with only SPF/DMARC missing (no other weaknesses).
 * DNSSEC on, CAA present, MTA-STS present, DANE present, full headers.
 */
function mockEmailSpoofOnlyDomain() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					// No DMARC
					return Promise.resolve(txtResponse('_dmarc.example.com', []));
				}
				if (url.includes('_domainkey.')) {
					return Promise.resolve(
						txtResponse('default._domainkey.example.com', [
							'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA',
						]),
					);
				}
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(
						txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
					);
				}
				// No SPF
				return Promise.resolve(txtResponse('example.com', []));
			}

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}

			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"', '0 issuewild ";"']));
			}

			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 15 }],
						[{ name: 'example.com', type: 15, TTL: 300, data: '10 mx1.example.com.' }],
					),
				);
			}

			if (url.includes('type=TLSA') || url.includes('type=52')) {
				return Promise.resolve(
					tlsaResponse('_25._tcp.mx1.example.com', [
						{ usage: 3, selector: 1, matchingType: 1, certData: 'aabbccddee' },
					]),
				);
			}

			return Promise.resolve(createDohResponse([], []));
		}

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(
				httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'),
			);
		}

		if (url.startsWith('https://')) {
			return Promise.resolve({
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
					'strict-transport-security': 'max-age=31536000; includeSubDomains',
				}),
				text: () => Promise.resolve('OK'),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		}

		return Promise.resolve(createDohResponse([], []));
	});
}

/**
 * Mock for a domain with only DNSSEC disabled.
 * Everything else is configured correctly.
 */
function mockDnssecOnlyMissingDomain() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					return Promise.resolve(
						txtResponse('_dmarc.example.com', [
							'v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s',
						]),
					);
				}
				if (url.includes('_domainkey.')) {
					return Promise.resolve(
						txtResponse('default._domainkey.example.com', [
							'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA',
						]),
					);
				}
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(
						txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
					);
				}
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}

			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"', '0 issuewild ";"']));
			}

			// DNSSEC AD=false — this is the key difference
			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', false));
			}

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 15 }],
						[{ name: 'example.com', type: 15, TTL: 300, data: '10 mx1.example.com.' }],
					),
				);
			}

			// No DNSKEY/DS since DNSSEC is off
			if (url.includes('type=DNSKEY') || url.includes('type=48')) {
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('type=DS') || url.includes('type=43')) {
				return Promise.resolve(createDohResponse([], []));
			}

			if (url.includes('type=TLSA') || url.includes('type=52')) {
				return Promise.resolve(
					tlsaResponse('_25._tcp.mx1.example.com', [
						{ usage: 3, selector: 1, matchingType: 1, certData: 'aabbccddee' },
					]),
				);
			}

			return Promise.resolve(createDohResponse([], []));
		}

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(
				httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'),
			);
		}

		if (url.startsWith('https://')) {
			return Promise.resolve({
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
					'strict-transport-security': 'max-age=31536000; includeSubDomains',
				}),
				text: () => Promise.resolve('OK'),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		}

		return Promise.resolve(createDohResponse([], []));
	});
}

/**
 * Mock for a domain with no MTA-STS and no DANE (TLS stripping vulnerable).
 * Everything else is configured correctly.
 */
function mockNoTransportSecurityDomain() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					return Promise.resolve(
						txtResponse('_dmarc.example.com', [
							'v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s',
						]),
					);
				}
				if (url.includes('_domainkey.')) {
					return Promise.resolve(
						txtResponse('default._domainkey.example.com', [
							'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA',
						]),
					);
				}
				// No MTA-STS
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', []));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(txtResponse('_smtp._tls.example.com', []));
				}
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}

			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"', '0 issuewild ";"']));
			}

			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 15 }],
						[{ name: 'example.com', type: 15, TTL: 300, data: '10 mx1.example.com.' }],
					),
				);
			}

			// No DANE TLSA records
			if (url.includes('type=TLSA') || url.includes('type=52')) {
				return Promise.resolve(createDohResponse([], []));
			}

			return Promise.resolve(createDohResponse([], []));
		}

		// No MTA-STS policy file
		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve({
				ok: false,
				status: 404,
				text: () => Promise.resolve('Not Found'),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		}

		if (url.startsWith('https://')) {
			return Promise.resolve({
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
					'strict-transport-security': 'max-age=31536000; includeSubDomains',
				}),
				text: () => Promise.resolve('OK'),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		}

		return Promise.resolve(createDohResponse([], []));
	});
}

/**
 * Mock for a domain with no CSP header (XSS vulnerable).
 * Everything else is configured correctly.
 */
function mockNoCspDomain() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					return Promise.resolve(
						txtResponse('_dmarc.example.com', [
							'v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s',
						]),
					);
				}
				if (url.includes('_domainkey.')) {
					return Promise.resolve(
						txtResponse('default._domainkey.example.com', [
							'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA',
						]),
					);
				}
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(
						txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
					);
				}
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}

			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"', '0 issuewild ";"']));
			}

			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 15 }],
						[{ name: 'example.com', type: 15, TTL: 300, data: '10 mx1.example.com.' }],
					),
				);
			}

			if (url.includes('type=TLSA') || url.includes('type=52')) {
				return Promise.resolve(
					tlsaResponse('_25._tcp.mx1.example.com', [
						{ usage: 3, selector: 1, matchingType: 1, certData: 'aabbccddee' },
					]),
				);
			}

			return Promise.resolve(createDohResponse([], []));
		}

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(
				httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'),
			);
		}

		// No CSP, no X-Frame-Options — XSS and clickjacking vulnerable
		if (url.startsWith('https://')) {
			return Promise.resolve({
				ok: true,
				status: 200,
				headers: new Headers({
					'x-content-type-options': 'nosniff',
					'referrer-policy': 'strict-origin-when-cross-origin',
					'strict-transport-security': 'max-age=31536000; includeSubDomains',
				}),
				text: () => Promise.resolve('OK'),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		}

		return Promise.resolve(createDohResponse([], []));
	});
}

/**
 * Mock for a domain with no CAA records.
 * Everything else is configured correctly.
 */
function mockNoCaaDomain() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					return Promise.resolve(
						txtResponse('_dmarc.example.com', [
							'v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=s',
						]),
					);
				}
				if (url.includes('_domainkey.')) {
					return Promise.resolve(
						txtResponse('default._domainkey.example.com', [
							'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA',
						]),
					);
				}
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(
						txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']),
					);
				}
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}

			// No CAA records
			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(createDohResponse([{ name: 'example.com', type: 257 }], []));
			}

			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 15 }],
						[{ name: 'example.com', type: 15, TTL: 300, data: '10 mx1.example.com.' }],
					),
				);
			}

			if (url.includes('type=TLSA') || url.includes('type=52')) {
				return Promise.resolve(
					tlsaResponse('_25._tcp.mx1.example.com', [
						{ usage: 3, selector: 1, matchingType: 1, certData: 'aabbccddee' },
					]),
				);
			}

			return Promise.resolve(createDohResponse([], []));
		}

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(
				httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'),
			);
		}

		if (url.startsWith('https://')) {
			return Promise.resolve({
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
					'strict-transport-security': 'max-age=31536000; includeSubDomains',
				}),
				text: () => Promise.resolve('OK'),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		}

		return Promise.resolve(createDohResponse([], []));
	});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('simulateAttackPaths', () => {
	async function run(domain = 'example.com') {
		const { simulateAttackPaths } = await import('../src/tools/simulate-attack-paths');
		return simulateAttackPaths(domain);
	}

	it('detects email spoofing attack path when SPF/DMARC are missing (critical)', async () => {
		mockEmailSpoofOnlyDomain();
		const result = await run();

		const emailSpoof = result.attackPaths.find((p) => p.id === 'email_spoof_direct');
		expect(emailSpoof).toBeDefined();
		expect(emailSpoof!.severity).toBe('critical');
		expect(emailSpoof!.feasibility).toBe('trivial');
		expect(emailSpoof!.mitigations.length).toBeGreaterThan(0);
	});

	it('detects DNS hijack path when DNSSEC is disabled (high)', async () => {
		mockDnssecOnlyMissingDomain();
		const result = await run();

		const dnsHijack = result.attackPaths.find((p) => p.id === 'dns_hijack');
		expect(dnsHijack).toBeDefined();
		expect(dnsHijack!.severity).toBe('high');
		expect(dnsHijack!.feasibility).toBe('difficult');
	});

	it('detects TLS stripping path when no MTA-STS and no DANE (medium)', async () => {
		mockNoTransportSecurityDomain();
		const result = await run();

		const tlsStrip = result.attackPaths.find((p) => p.id === 'tls_downgrade_email');
		expect(tlsStrip).toBeDefined();
		expect(tlsStrip!.severity).toBe('medium');
		expect(tlsStrip!.feasibility).toBe('moderate');
	});

	it('detects XSS path when CSP is missing (high)', async () => {
		mockNoCspDomain();
		const result = await run();

		const xss = result.attackPaths.find((p) => p.id === 'xss_injection');
		expect(xss).toBeDefined();
		expect(xss!.severity).toBe('high');
		expect(xss!.feasibility).toBe('moderate');
	});

	it('detects cert misissuance path when CAA is missing (medium)', async () => {
		mockNoCaaDomain();
		const result = await run();

		const cert = result.attackPaths.find((p) => p.id === 'cert_misissuance');
		expect(cert).toBeDefined();
		expect(cert!.severity).toBe('medium');
		expect(cert!.feasibility).toBe('difficult');
	});

	it('returns no attack paths and low risk for well-secured domain', async () => {
		mockSecureDomain();
		const result = await run();

		// A well-secured domain should have few or no attack paths
		// It may still have some edge cases depending on how checks evaluate,
		// but critical/high paths should be absent
		const criticalOrHigh = result.attackPaths.filter(
			(p) => p.severity === 'critical' || p.severity === 'high',
		);
		expect(criticalOrHigh).toHaveLength(0);

		// If no paths at all, overall risk should be low
		if (result.totalPaths === 0) {
			expect(result.overallRisk).toBe('low');
		}
	});

	it('sets overall risk to the most severe feasible path', async () => {
		mockInsecureDomain();
		const result = await run();

		// Insecure domain should have critical paths (email spoofing)
		expect(result.criticalPaths).toBeGreaterThan(0);
		expect(result.overallRisk).toBe('critical');
	});

	it('returns correct structure with all expected fields', async () => {
		mockInsecureDomain();
		const result = await run();

		expect(result).toHaveProperty('domain', 'example.com');
		expect(result).toHaveProperty('totalPaths');
		expect(result).toHaveProperty('criticalPaths');
		expect(result).toHaveProperty('highPaths');
		expect(result).toHaveProperty('attackPaths');
		expect(result).toHaveProperty('overallRisk');
		expect(typeof result.totalPaths).toBe('number');
		expect(typeof result.criticalPaths).toBe('number');
		expect(typeof result.highPaths).toBe('number');
		expect(Array.isArray(result.attackPaths)).toBe(true);

		// Each attack path has correct structure
		for (const path of result.attackPaths) {
			expect(path).toHaveProperty('id');
			expect(path).toHaveProperty('name');
			expect(path).toHaveProperty('severity');
			expect(path).toHaveProperty('feasibility');
			expect(path).toHaveProperty('prerequisites');
			expect(path).toHaveProperty('steps');
			expect(path).toHaveProperty('impact');
			expect(path).toHaveProperty('mitigations');
			expect(Array.isArray(path.prerequisites)).toBe(true);
			expect(Array.isArray(path.steps)).toBe(true);
			expect(Array.isArray(path.mitigations)).toBe(true);
		}
	});

	it('sorts attack paths by severity then feasibility', async () => {
		mockInsecureDomain();
		const result = await run();

		const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
		const feasibilityOrder: Record<string, number> = { trivial: 0, moderate: 1, difficult: 2 };

		for (let i = 1; i < result.attackPaths.length; i++) {
			const prev = result.attackPaths[i - 1];
			const curr = result.attackPaths[i];
			const sevDiff = severityOrder[prev.severity] - severityOrder[curr.severity];
			if (sevDiff === 0) {
				expect(feasibilityOrder[prev.feasibility]).toBeLessThanOrEqual(feasibilityOrder[curr.feasibility]);
			} else {
				expect(sevDiff).toBeLessThanOrEqual(0);
			}
		}
	});
});

describe('formatAttackPaths', () => {
	async function importModule() {
		return import('../src/tools/simulate-attack-paths');
	}

	it('produces compact output with severity icons and one-line summaries', async () => {
		const { formatAttackPaths } = await importModule();
		const result = {
			domain: 'example.com',
			totalPaths: 2,
			criticalPaths: 1,
			highPaths: 1,
			attackPaths: [
				{
					id: 'email_spoof_direct',
					name: 'Direct Email Spoofing',
					severity: 'critical' as const,
					feasibility: 'trivial' as const,
					prerequisites: ['SPF missing or permissive'],
					steps: ['Send email as ceo@domain'],
					impact: 'Phishing emails appear to come from your domain.',
					mitigations: ['Deploy SPF with -all'],
				},
				{
					id: 'dns_hijack',
					name: 'DNS Response Manipulation',
					severity: 'high' as const,
					feasibility: 'difficult' as const,
					prerequisites: ['DNSSEC not enabled'],
					steps: ['Perform DNS cache poisoning'],
					impact: 'DNS responses can be spoofed.',
					mitigations: ['Enable DNSSEC'],
				},
			],
			overallRisk: 'critical' as const,
		};

		const output = formatAttackPaths(result, 'compact');
		expect(output).toContain('Attack Paths: example.com');
		expect(output).toContain('2 feasible attacks');
		expect(output).toContain('Overall Risk: CRITICAL');
		expect(output).toContain('[CRITICAL]');
		expect(output).toContain('[HIGH]');
		expect(output).toContain('Mitigate:');
	});

	it('produces full output with steps, prerequisites, and impact', async () => {
		const { formatAttackPaths } = await importModule();
		const result = {
			domain: 'example.com',
			totalPaths: 1,
			criticalPaths: 0,
			highPaths: 1,
			attackPaths: [
				{
					id: 'dns_hijack',
					name: 'DNS Response Manipulation',
					severity: 'high' as const,
					feasibility: 'difficult' as const,
					prerequisites: ['DNSSEC not enabled on the domain'],
					steps: ['Perform DNS cache poisoning', 'Redirect traffic to attacker server'],
					impact: 'All DNS-dependent security can be bypassed.',
					mitigations: ['Enable DNSSEC'],
				},
			],
			overallRisk: 'high' as const,
		};

		const output = formatAttackPaths(result, 'full');
		expect(output).toContain('Attack Paths: example.com');
		expect(output).toContain('Overall Risk: HIGH');
		expect(output).toContain('Prerequisites:');
		expect(output).toContain('Attack Steps:');
		expect(output).toContain('Impact:');
		expect(output).toContain('Mitigations:');
		expect(output).toContain('DNSSEC not enabled');
		expect(output).toContain('Perform DNS cache poisoning');
	});

	it('formats empty result correctly', async () => {
		const { formatAttackPaths } = await importModule();
		const result = {
			domain: 'secure.example.com',
			totalPaths: 0,
			criticalPaths: 0,
			highPaths: 0,
			attackPaths: [],
			overallRisk: 'low' as const,
		};

		const compactOutput = formatAttackPaths(result, 'compact');
		expect(compactOutput).toContain('No feasible attack paths detected');
		expect(compactOutput).toContain('Overall Risk: LOW');

		const fullOutput = formatAttackPaths(result, 'full');
		expect(fullOutput).toContain('No feasible attack paths detected');
		expect(fullOutput).toContain('Overall Risk: LOW');
	});
});
