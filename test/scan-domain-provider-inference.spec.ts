import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createDohResponse } from './helpers/dns-mock';
import { scanCache } from '../src/lib/cache';

beforeEach(() => scanCache.clear());
afterEach(() => vi.restoreAllMocks());

function txtResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 16 }],
		records.map((data) => ({ name: domain, type: 16, TTL: 300, data: `"${data}"` })),
	);
}

function nsResponse(domain: string, nameservers: string[]) {
	return createDohResponse(
		[{ name: domain, type: 2 }],
		nameservers.map((data) => ({ name: domain, type: 2, TTL: 300, data })),
	);
}

function caaResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 257 }],
		records.map((data) => ({ name: domain, type: 257, TTL: 300, data })),
	);
}

function dnssecResponse(domain: string, ad: boolean) {
	return createDohResponse([{ name: domain, type: 1 }], [{ name: domain, type: 1, TTL: 300, data: '1.2.3.4' }], {
		ad,
	});
}

function httpResponse(body: string, status = 200) {
	return {
		ok: status >= 200 && status < 300,
		status,
		text: () => Promise.resolve(body),
		json: () => Promise.resolve({}),
		headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
	} as unknown as Response;
}

function mockAllChecksWithDkimGoogle(spfRecord: string) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) {
					return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
				}
				if (url.includes('google._domainkey.')) {
					return Promise.resolve(txtResponse('google._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2a2rwplBCXGHDzhtSF5cz+DfOpZB3Q9nDy0NxQyL8iB4xQoT0Q5Ka0K9KpV4LK3+KZvP5U9ZvL1yR5pZmqZLa5N4H1s7cQ7YQ0+C1jKSRQG7jP8QF1dPLqVfE1pZe7cQ8Kxc6c4PfD8QK9pC7Z1W0K8M3K7N2R4L9Y5L8B3P4N7U5Q6K0O5M5Y6W8P1R7T9A8K6S4P8b0tVm7dC1wYzV6+C2T3U4V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4z9zzAA']));
				}
				if (url.includes('_domainkey.')) {
					return Promise.resolve(createDohResponse([], []));
				}
				if (url.includes('_mta-sts.')) {
					return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				}
				if (url.includes('_smtp._tls.')) {
					return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				}
				return Promise.resolve(txtResponse('example.com', [spfRecord]));
			}

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(createDohResponse([], []));
			}

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}

			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			}

			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}

			return Promise.resolve(createDohResponse([], []));
		}

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		}

		return Promise.resolve(httpResponse('OK'));
	});
}

describe('scanDomain outbound provider inference', () => {
	it('infers outbound provider from DKIM selector hints when SPF has no include domains', async () => {
		mockAllChecksWithDkimGoogle('v=spf1 -all');
		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain('example.com');

		const spfCheck = result.checks.find((check) => check.category === 'spf');
		expect(spfCheck).toBeDefined();
		const finding = spfCheck?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(finding).toBeDefined();
		expect(finding?.metadata?.signalsUsed).toBeDefined();
		expect(finding?.metadata?.signalsUsed?.dkimSelectors).toContain('google');
	});

	it('raises outbound inference confidence when SPF and DKIM signals are both present', async () => {
		mockAllChecksWithDkimGoogle('v=spf1 include:_spf.google.com -all');
		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain('example.com');

		const spfCheck = result.checks.find((check) => check.category === 'spf');
		const finding = spfCheck?.findings.find((f) => f.title === 'Outbound email provider inferred');
		expect(finding).toBeDefined();
		expect(typeof finding?.metadata?.providerConfidence).toBe('number');
		expect((finding?.metadata?.providerConfidence as number) >= 0.7).toBe(true);
		expect(finding?.metadata?.signalsUsed?.spfDomains).toContain('_spf.google.com');
		expect(finding?.metadata?.signalsUsed?.dkimSelectors).toContain('google');
	});
});
