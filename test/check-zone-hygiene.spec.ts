// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, nsResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Build an empty DoH response (no answers). */
function emptyResponse(name: string, type: number) {
	return createDohResponse([{ name, type }], []);
}

/** Build a DoH response containing a SOA record. */
function soaResponse(domain: string, soaData: string) {
	return createDohResponse([{ name: domain, type: 6 }], [{ name: domain, type: 6, TTL: 300, data: soaData }]);
}

/** Build a DoH response containing A records. */
function aResponse(domain: string, ips: string[]) {
	return createDohResponse(
		[{ name: domain, type: 1 }],
		ips.map((ip) => ({ name: domain, type: 1, TTL: 300, data: ip })),
	);
}

describe('checkZoneHygiene', () => {
	async function run(domain = 'example.com') {
		const { checkZoneHygiene } = await import('../src/tools/check-zone-hygiene');
		return checkZoneHygiene(domain);
	}

	it('should return info findings when zone is consistent and no sensitive subdomains resolve', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// NS query
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}
			// SOA query
			if (url.includes('type=SOA') || url.includes('type=6')) {
				return Promise.resolve(soaResponse('example.com', 'ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 300'));
			}
			// A record queries for sensitive subdomains — all return empty
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('zone_hygiene');
		expect(result.passed).toBe(true);

		// Should have SOA details info finding
		const soaDetails = result.findings.find((f) => f.title === 'SOA record details');
		expect(soaDetails).toBeDefined();
		expect(soaDetails!.metadata?.serial).toBe(2024010101);

		// Should have "no sensitive subdomains" finding
		const noSensitive = result.findings.find((f) => f.title === 'No sensitive subdomains resolve publicly');
		expect(noSensitive).toBeDefined();
	});

	it('should detect sensitive subdomains that resolve publicly', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}
			if (url.includes('type=SOA') || url.includes('type=6')) {
				return Promise.resolve(soaResponse('example.com', 'ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 300'));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				// vpn.example.com resolves
				if (name === 'vpn.example.com') {
					return Promise.resolve(aResponse('vpn.example.com', ['203.0.113.10']));
				}
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('zone_hygiene');
		const vpnFinding = result.findings.find((f) => f.title.includes('vpn.example.com'));
		expect(vpnFinding).toBeDefined();
		expect(vpnFinding!.severity).toBe('medium');
	});

	it('should flag excessive subdomain exposure when 3+ resolve', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.']));
			}
			if (url.includes('type=SOA') || url.includes('type=6')) {
				return Promise.resolve(soaResponse('example.com', 'ns1.example.com. admin.example.com. 100 7200 3600 1209600 300'));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				const resolving = ['vpn.example.com', 'admin.example.com', 'staging.example.com'];
				if (resolving.includes(name)) {
					return Promise.resolve(aResponse(name, ['203.0.113.1']));
				}
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const excessive = result.findings.find((f) => f.title.includes('Excessive internal subdomain exposure'));
		expect(excessive).toBeDefined();
		expect(excessive!.severity).toBe('medium');
	});

	it('should handle DNS query failure gracefully', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('DNS failure'));

		const result = await run();
		expect(result.category).toBe('zone_hygiene');
		expect(result.findings.length).toBeGreaterThan(0);

		// Should have a zone consistency failure note
		const failNote = result.findings.find((f) => f.title === 'Zone consistency check failed');
		expect(failNote).toBeDefined();
		expect(failNote!.severity).toBe('info');
	});

	it('should report SOA serial in findings metadata', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}
			if (url.includes('type=SOA') || url.includes('type=6')) {
				return Promise.resolve(soaResponse('example.com', 'ns1.example.com. hostmaster.example.com. 9999 7200 3600 1209600 300'));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const soaDetails = result.findings.find((f) => f.title === 'SOA record details');
		expect(soaDetails).toBeDefined();
		expect(soaDetails!.metadata?.serial).toBe(9999);
		expect(soaDetails!.metadata?.primaryNs).toBe('ns1.example.com');
	});

	it('should report medium finding when no NS records found', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(emptyResponse('example.com', 2));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const noNs = result.findings.find((f) => f.title === 'No NS records found');
		expect(noNs).toBeDefined();
		expect(noNs!.severity).toBe('medium');
	});

	it('should flag short SOA expire value', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}
			if (url.includes('type=SOA') || url.includes('type=6')) {
				// expire = 86400 (1 day, less than 604800 = 1 week)
				return Promise.resolve(soaResponse('example.com', 'ns1.example.com. admin.example.com. 2024010101 7200 3600 86400 300'));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const shortExpire = result.findings.find((f) => f.title === 'SOA expire value is short');
		expect(shortExpire).toBeDefined();
		expect(shortExpire!.severity).toBe('low');
		expect(shortExpire!.metadata?.expire).toBe(86400);
	});

	it('should handle missing SOA record', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.']));
			}
			if (url.includes('type=SOA') || url.includes('type=6')) {
				return Promise.resolve(emptyResponse('example.com', 6));
			}
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : '';
				return Promise.resolve(emptyResponse(name, 1));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		const noSoa = result.findings.find((f) => f.title === 'No SOA record found');
		expect(noSoa).toBeDefined();
		expect(noSoa!.severity).toBe('medium');
	});
});
