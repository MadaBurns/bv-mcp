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

			// DNSSEC: AD=true plus a complete child/parent chain. AD alone is not
			// evidence that the zone is signed (#793).
			if (url.includes('type=DNSKEY') || url.includes('type=48')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 48 }],
						[{ name: 'example.com', type: 48, TTL: 300, data: '257 3 13 AwEAAabc' }],
					),
				);
			}
			if (url.includes('type=DS') || url.includes('type=43')) {
				return Promise.resolve(
					createDohResponse(
						[{ name: 'example.com', type: 43 }],
						[{ name: 'example.com', type: 43, TTL: 300, data: '12345 13 2 abc123' }],
					),
				);
			}

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

/**
 * Mock for a well-protected mail domain that is directly spoof-resistant but has a
 * subdomain gap (issue #564 repro — modelled on spotto.ai):
 *   SPF = v=spf1 include:... -all   (hard fail — NOT permissive)
 *   DMARC = v=DMARC1; p=quarantine; sp=none   (quarantine — NOT none/missing)
 * The direct-spoof path must NOT fire at critical/trivial, but the SUBDOMAIN path
 * (sp=none) legitimately remains. Everything else is configured correctly.
 */
function mockSpoofResistantSubdomainGapDomain() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					// Enforcing org policy (quarantine) but weak subdomain policy (sp=none)
					return Promise.resolve(
						txtResponse('_dmarc.example.com', [
							'v=DMARC1; p=quarantine; sp=none; rua=mailto:dmarc@example.com; adkim=s; aspf=s',
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
				// SPF hard fail (-all)
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

	it('evaluates authoritative infrastructure hijack attack paths from findings', async () => {
		const { evaluateAttackPathsFromFindings } = await import('../src/tools/simulate-attack-paths');
		const paths = evaluateAttackPathsFromFindings([
			{
				category: 'authoritative_dns_infra',
				title: 'Route leak or hijack signal observed',
				severity: 'critical',
				detail: 'Route monitoring reported leak or hijack signals for a.root-servers.net.',
			},
		] as never);

		const routeHijack = paths.find((path) => path.id === 'authoritative_dns_route_hijack');
		expect(routeHijack).toBeDefined();
		expect(routeHijack!.severity).toBe('critical');
		expect(routeHijack!.mitigations).toContain('Validate BGP origin announcements and RPKI ROAs');
	});

	it('detects email spoofing attack path when SPF/DMARC are missing (critical)', async () => {
		mockEmailSpoofOnlyDomain();
		const result = await run();

		const emailSpoof = result.attackPaths.find((p) => p.id === 'email_spoof_direct');
		expect(emailSpoof).toBeDefined();
		expect(emailSpoof!.severity).toBe('critical');
		expect(emailSpoof!.feasibility).toBe('trivial');
		expect(emailSpoof!.mitigations.length).toBeGreaterThan(0);
	});

	it('does NOT emit critical/trivial direct email spoofing when SPF hard-fails and DMARC enforces (issue #564)', async () => {
		// spotto.ai repro: SPF -all + DMARC p=quarantine; sp=none is a well-protected
		// mail domain — assess_spoofability rates it low. The direct-spoof path must not
		// be emitted at critical/trivial just because a subdomain (sp=none / np=none)
		// finding carries the "p=none" substring.
		mockSpoofResistantSubdomainGapDomain();
		const result = await run();

		const criticalDirect = result.attackPaths.find(
			(p) => p.id === 'email_spoof_direct' && (p.severity === 'critical' || p.feasibility === 'trivial'),
		);
		expect(criticalDirect).toBeUndefined();

		// The genuine residual — subdomain spoofing via sp=none — must still fire.
		const subdomainSpoof = result.attackPaths.find((p) => p.id === 'email_spoof_subdomain');
		expect(subdomainSpoof).toBeDefined();
		expect(subdomainSpoof!.severity).toBe('high');
	});

	it('still emits critical/trivial direct email spoofing when SPF and DMARC are both missing (issue #564)', async () => {
		mockEmailSpoofOnlyDomain();
		const result = await run();

		const emailSpoof = result.attackPaths.find((p) => p.id === 'email_spoof_direct');
		expect(emailSpoof).toBeDefined();
		expect(emailSpoof!.severity).toBe('critical');
		expect(emailSpoof!.feasibility).toBe('trivial');
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

/**
 * #782 — two paths were emitted whose stated PREREQUISITES the scan's own check
 * results contradicted, in the same run, on openclaw.org:
 *
 *   cert_misissuance  "No CAA records restrict certificate issuance"
 *                     …on a zone publishing THREE issue tags (check_caa: 90)
 *   clickjacking      "X-Frame-Options header missing"
 *                     …on a host sending XFO: SAMEORIGIN, which
 *                     check_http_security correctly did NOT flag
 *
 * False positives of the worst kind: checkable ones. Attack-path prose is the
 * part of a report that gets quoted, and a reader who verifies one failed
 * prerequisite reasonably distrusts everything else in the document. Both had
 * to be excluded by hand from a client deliverable.
 */
describe('#782 a path never states a prerequisite the findings contradict', () => {
	async function paths(findings: unknown[]) {
		const { evaluateAttackPathsFromFindings } = await import('../src/tools/simulate-attack-paths');
		return evaluateAttackPathsFromFindings(findings as never);
	}

	it('does not claim CAA is absent when only the optional sub-tags are', async () => {
		// The exact shape check_caa emits for a zone WITH CAA: `issue` tags
		// present, optional `issuewild`/`iodef` absent. Both titles contain the
		// substring "no caa", which is what the old predicate matched on.
		const result = await paths([
			{ category: 'caa', title: 'No CAA issuewild tag', severity: 'low', detail: 'No issuewild tag present.' },
			{ category: 'caa', title: 'No CAA iodef tag', severity: 'low', detail: 'No iodef tag present.' },
		]);
		expect(
			result.find((p) => p.id === 'cert_misissuance'),
			'a zone publishing issue tags must not yield a "no CAA" path',
		).toBeUndefined();
	});

	it('still fires when CAA really is absent', async () => {
		// The control must not have been disabled by the fix.
		const result = await paths([
			{ category: 'caa', title: 'No CAA records found', severity: 'medium', detail: 'No CAA RRset published.' },
		]);
		const path = result.find((p) => p.id === 'cert_misissuance');
		expect(path, 'the genuine no-CAA case must still be reported').toBeDefined();
		expect(path!.prerequisites).toContain('No CAA records restrict certificate issuance');
	});

	it('names only the framing control that is actually missing', async () => {
		// XFO present, CSP absent — only the CSP arm of the OR fires.
		const result = await paths([
			{
				category: 'http_security',
				title: 'No Content-Security-Policy header',
				severity: 'medium',
				detail: 'CSP is not set.',
			},
		]);
		const path = result.find((p) => p.id === 'clickjacking');
		expect(path).toBeDefined();
		expect(
			path!.prerequisites,
			'the host sends X-Frame-Options; claiming it is missing is checkably false',
		).not.toContain('X-Frame-Options header missing');
		expect(path!.prerequisites).toContain('No CSP frame-ancestors directive');
	});

	it('names both when both are missing', async () => {
		const result = await paths([
			{ category: 'http_security', title: 'X-Frame-Options header missing', severity: 'medium', detail: 'Not set.' },
			{ category: 'http_security', title: 'No Content-Security-Policy header', severity: 'medium', detail: 'Not set.' },
		]);
		const path = result.find((p) => p.id === 'clickjacking');
		expect(path!.prerequisites).toEqual(['X-Frame-Options header missing', 'No CSP frame-ancestors directive']);
	});

	it('never emits a path with an empty prerequisite list', async () => {
		// A path that fired but can name nothing it depends on is unreviewable.
		const result = await paths([
			{ category: 'http_security', title: 'X-Frame-Options header missing', severity: 'medium', detail: 'Not set.' },
		]);
		for (const p of result) {
			expect(p.prerequisites.length, `${p.id} emitted no prerequisites`).toBeGreaterThan(0);
		}
	});
});

/**
 * #787 — `subdomain_takeover` asserted a hardcoded CRITICAL severity and an
 * "unclaimed resource" prerequisite regardless of what the evidence said.
 *
 * Measured 2026-08-26 on openai.com during a 16-domain AI-provider sweep.
 * `check_subdomain_takeover` emitted exactly two findings:
 *
 *   [high]   Subdomain possible takeover signal Azure CDN
 *   [medium] Dangling CNAME operational drift : blog.openai.com
 *                                              → d2b532lzynlqb7.cloudfront.net
 *
 * The simulator turned that into a CRITICAL path whose prerequisite read
 * "Dangling CNAME pointing to unclaimed resource", which drove the whole
 * domain's `overallRisk` to **critical** — the only critical verdict in the
 * entire sweep.
 *
 * Two separate over-claims:
 *
 *  1. SEVERITY. `hasSubdomainTakeoverRisk` accepts medium|high|critical, but
 *     the path is hardcoded `severity: 'critical'`. A MEDIUM "operational
 *     drift" finding is therefore promoted two full levels, and because
 *     `overallRisk` is just the most severe path, one medium finding renders
 *     the domain critical.
 *
 *  2. PREREQUISITE. "unclaimed resource" asserts the target is REGISTRABLE by
 *     an attacker. Verified against DNS: `d2b532lzynlqb7.cloudfront.net`
 *     returns NOERROR/NODATA (a deleted distribution) on two independent
 *     public resolvers — genuinely dangling. But CloudFront distribution IDs are
 *     assigned by AWS and cannot be chosen, so the resource is NOT claimable.
 *     The scanner knew this: it rated that finding MEDIUM and titled it
 *     "operational drift", not "takeover".
 *
 * Same family as #782 — a path stating more than its own evidence supports.
 */
describe('#787 subdomain_takeover severity and prerequisites follow the evidence', () => {
	async function paths(findings: unknown[]) {
		const { evaluateAttackPathsFromFindings } = await import('../src/tools/simulate-attack-paths');
		return evaluateAttackPathsFromFindings(findings as never);
	}

	const DRIFT_ONLY = [
		{
			category: 'subdomain_takeover',
			title: 'Dangling CNAME operational drift : blog.openai.com → d2b532lzynlqb7.cloudfront.net',
			severity: 'medium',
			detail: 'CNAME target does not resolve.',
		},
	];

	const REAL_OPENAI = [
		{
			category: 'subdomain_takeover',
			title: 'Subdomain possible takeover signal Azure CDN',
			severity: 'high',
			detail: 'Azure CDN endpoint signature observed.',
		},
		...DRIFT_ONLY,
	];

	it('does not promote a medium operational-drift finding to a critical path', async () => {
		const path = (await paths(DRIFT_ONLY)).find((p) => p.id === 'subdomain_takeover');
		expect(path, 'the path should still be reported').toBeDefined();
		expect(path!.severity, 'a medium finding must not render the domain critical').toBe('medium');
	});

	it('does not claim the resource is unclaimed when only drift was observed', async () => {
		const path = (await paths(DRIFT_ONLY)).find((p) => p.id === 'subdomain_takeover');
		expect(
			path!.prerequisites,
			'"unclaimed" asserts attacker-registrability, which a drift finding does not establish',
		).not.toContain('Dangling CNAME pointing to unclaimed resource');
		expect(path!.prerequisites.length).toBeGreaterThan(0);
	});

	it('caps the real openai.com evidence set at high, not critical', async () => {
		const path = (await paths(REAL_OPENAI)).find((p) => p.id === 'subdomain_takeover');
		expect(path!.severity, 'strongest underlying finding was high').toBe('high');
	});

	it('still reports critical when the evidence itself is critical', async () => {
		// Control: the fix must not disarm a genuine critical takeover.
		const path = (
			await paths([
				{
					category: 'subdomain_takeover',
					title: 'Subdomain takeover confirmed',
					severity: 'critical',
					detail: 'Target bucket is unregistered and claimable.',
				},
			])
		).find((p) => p.id === 'subdomain_takeover');
		expect(path!.severity).toBe('critical');
	});
});

/**
 * #788 — `email_spoof_subdomain` is a DEAD path: it fired for 0 of 16 domains,
 * including the two whose org policy is `p=none`.
 *
 * Mirror image of #782. That bug matched prose that meant the opposite; this
 * one FAILS to match for the same reason. `isDmarcSubdomainWeak`'s third clause
 * is `!d.includes('sp=') && d.includes('p=none')`, and check_dmarc's detail for
 * a MISSING subdomain policy reads:
 *
 *   "No subdomain policy (sp=) specified. Subdomains inherit the "none" policy,
 *    which provides no protection against spoofing."
 *
 * `sp=` occurs as a substring precisely BECAUSE the tag is absent, so
 * `!d.includes('sp=')` is false and the clause can never fire. The literal
 * `p=none` is not in the detail either — the policy is named as `"none"`.
 *
 * Measured 2026-08-26 on moonshot.ai (DMARC p=none, spoofability 59): the
 * scanner said subdomains have "no protection against spoofing" and the
 * simulator reported no subdomain-spoofing path at all. A missing HIGH finding
 * on the most spoofable domain in the sweep.
 *
 * The discriminator is the INHERITED POLICY, not the presence of the sp= tag:
 * inheriting "reject" is fine, inheriting "none" is not.
 */
describe('#788 email_spoof_subdomain fires on an inherited none policy', () => {
	async function paths(findings: unknown[]) {
		const { evaluateAttackPathsFromFindings } = await import('../src/tools/simulate-attack-paths');
		return evaluateAttackPathsFromFindings(findings as never);
	}

	it('fires when subdomains inherit a none policy (real moonshot.ai finding)', async () => {
		const result = await paths([
			{
				category: 'dmarc',
				title: 'Subdomains inherit p=none policy',
				severity: 'info',
				detail:
					'No subdomain policy (sp=) specified. Subdomains inherit the "none" policy, which provides no protection against spoofing.',
			},
		]);
		expect(
			result.find((p) => p.id === 'email_spoof_subdomain'),
			'subdomains inheriting p=none are spoofable',
		).toBeDefined();
	});

	it('does NOT fire when subdomains inherit an enforcing policy (real openai.com finding)', async () => {
		// Control: the same "No subdomain policy (sp=)" prose, but inheriting reject.
		const result = await paths([
			{
				category: 'dmarc',
				title: 'No subdomain policy',
				severity: 'low',
				detail:
					'No subdomain policy (sp=) specified. Subdomains inherit the main policy ("reject"), but explicitly setting sp= is recommended.',
			},
		]);
		expect(
			result.find((p) => p.id === 'email_spoof_subdomain'),
			'inheriting reject is not a subdomain weakness',
		).toBeUndefined();
	});

	it('still fires on an explicit sp=none', async () => {
		const result = await paths([
			{ category: 'dmarc', title: 'Subdomain policy is none', severity: 'medium', detail: 'Record sets sp=none.' },
		]);
		expect(result.find((p) => p.id === 'email_spoof_subdomain')).toBeDefined();
	});

	it('still fires when DMARC is absent entirely', async () => {
		const result = await paths([
			{ category: 'dmarc', title: 'No DMARC record', severity: 'high', detail: 'No DMARC record published.' },
		]);
		expect(result.find((p) => p.id === 'email_spoof_subdomain')).toBeDefined();
	});
});
