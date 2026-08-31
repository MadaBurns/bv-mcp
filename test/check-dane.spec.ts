// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, dnssecResponse, tlsaResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Build a DoH response containing MX records for a domain. */
function mxResponse(domain: string, records: Array<{ priority: number; exchange: string }>) {
	return createDohResponse(
		[{ name: domain, type: 15 }],
		records.map((r) => ({ name: domain, type: 15, TTL: 300, data: `${r.priority} ${r.exchange}.` })),
	);
}

/** Build an empty DoH response (no answers). */
function emptyResponse(name: string, type: number) {
	return createDohResponse([{ name, type }], []);
}

describe('checkDane', () => {
	async function run(domain = 'example.com') {
		const { checkDane } = await import('../src/tools/check-dane');
		return checkDane(domain);
	}

	it('should return info findings when domain has valid DANE TLSA with DNSSEC', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNSSEC check: A record with AD=true
			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			// MX records
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mx1.example.com' }]));
			}
			// TLSA for MX host
			if (url.includes('_25._tcp.mx1.example.com') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(
					tlsaResponse('_25._tcp.mx1.example.com', [{ usage: 3, selector: 1, matchingType: 1, certData: 'aabbccddee' }]),
				);
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane');
		expect(result.passed).toBe(true);
		// The pin is present but has not been compared with the served certificate.
		const unverified = result.findings.find((f) => f.title.includes('DANE TLSA configured'));
		expect(unverified).toBeDefined();
		expect(unverified?.severity).toBe('low');
		expect(result.score).toBe(95);
	});

	it('should return high finding when DANE exists but no DNSSEC', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNSSEC check: AD=false
			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', false));
			}
			// MX records
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mx1.example.com' }]));
			}
			// TLSA for MX host — DANE-EE without DNSSEC
			if (url.includes('_25._tcp.mx1.example.com') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(
					tlsaResponse('_25._tcp.mx1.example.com', [{ usage: 3, selector: 1, matchingType: 1, certData: 'aabbccddee' }]),
				);
			}
			// No HTTPS TLSA
			if (url.includes('_443._tcp') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(emptyResponse('_443._tcp.example.com', 52));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane');
		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.title).toBe('DANE without DNSSEC');
	});

	it('should return medium finding when no TLSA records found anywhere', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNSSEC check
			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			// MX records
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mx1.example.com' }]));
			}
			// No TLSA for MX or HTTPS
			if (url.includes('type=TLSA') || url.includes('type=52')) {
				const name = url.includes('_25._tcp') ? '_25._tcp.mx1.example.com' : '_443._tcp.example.com';
				return Promise.resolve(emptyResponse(name, 52));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane');
		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toContain('No DANE TLSA for MX');
	});

	it('should return medium finding when HTTPS TLSA exists but no MX TLSA', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNSSEC: true
			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			// MX records
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(mxResponse('example.com', [{ priority: 10, exchange: 'mx1.example.com' }]));
			}
			// No TLSA for MX
			if (url.includes('_25._tcp') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(emptyResponse('_25._tcp.mx1.example.com', 52));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane');
		// HTTPS DANE is handled by check-dane-https; email DANE check reports missing MX TLSA
		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.title).toContain('No DANE TLSA for MX');
	});

	it('should handle DNS query failure gracefully', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('DNS failure'));

		const result = await run();
		expect(result.category).toBe('dane');
		// Should have some finding about the failure
		expect(result.findings.length).toBeGreaterThan(0);
	});

	/**
	 * #639 — an unresolvable MX lookup is an INCONCLUSIVE check, not a graded one.
	 *
	 * This replaces an assertion on the old `low` "MX lookup failed for DANE check"
	 * finding, which left the result at score 95 with `passed: true` and
	 * `checkStatus: 'completed'` — a failed measurement presented as a near-perfect
	 * one, invisible to scoring's transient-failure exclusion and to `scan_domain`'s
	 * transient-zero retry (both key on `checkStatus === 'error'`).
	 */
	it('reports an unresolvable MX lookup as INCONCLUSIVE, not a scored finding', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNSSEC check
			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			// MX fails
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.reject(new Error('MX query failed'));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane');
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.partial).toBe(true);
		expect(result.findings.some((f) => f.metadata?.errorKind === 'dns_error')).toBe(true);
		// The old low finding must be gone — it was the fabrication.
		expect(result.findings.some((f) => f.title === 'MX lookup failed for DANE check')).toBe(false);
	});

	/**
	 * #639 defect 1 — a DoH SERVFAIL arrives as HTTP 200 with an empty answer set, so
	 * nothing throws and the `string[]` projection makes it identical to a genuine
	 * NODATA. It used to be read as "no inbound mail → SMTP DANE not applicable" and
	 * awarded a full 100. A broken delegation is an ABSENCE OF EVIDENCE, not evidence
	 * of absence.
	 */
	it('reports a SERVFAIL MX lookup as INCONCLUSIVE, never as "not applicable" at 100', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=MX') || url.includes('type=15')) {
				// SERVFAIL: HTTP 200, rcode 2, no answers.
				return Promise.resolve(createDohResponse([{ name: 'broken.example', type: 15 }], [], { status: 2 }));
			}
			return Promise.resolve(emptyResponse('broken.example', 1));
		});

		const result = await run('broken.example');
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.findings.some((f) => f.title === 'SMTP DANE not applicable (no inbound mail)')).toBe(false);
	});

	it('still reports a genuine NOERROR/no-MX domain as not applicable at 100', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(emptyResponse('example.com', 15));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.checkStatus ?? 'completed').toBe('completed');
		expect(result.score).toBe(100);
		expect(result.findings.map((f) => f.title)).toContain('SMTP DANE not applicable (no inbound mail)');
	});

	it('should handle domain with no MX records', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNSSEC check
			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			// No MX records
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(emptyResponse('example.com', 15));
			}
			// No HTTPS TLSA
			if (url.includes('_443._tcp') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(emptyResponse('_443._tcp.example.com', 52));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane');
		// No MX means no MX TLSA, should get presence classification
		const findings = result.findings;
		expect(findings.length).toBeGreaterThan(0);
	});

	it('should skip null MX exchanges', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNSSEC check
			if ((url.includes('type=A') || url.includes('type=1')) && !url.includes('_tcp')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			// Null MX
			if (url.includes('type=MX') || url.includes('type=15')) {
				return Promise.resolve(
					createDohResponse([{ name: 'example.com', type: 15 }], [{ name: 'example.com', type: 15, TTL: 300, data: '0 .' }]),
				);
			}
			// No HTTPS TLSA
			if (url.includes('_443._tcp') && (url.includes('type=TLSA') || url.includes('type=52'))) {
				return Promise.resolve(emptyResponse('_443._tcp.example.com', 52));
			}
			return Promise.resolve(emptyResponse('example.com', 1));
		});

		const result = await run();
		expect(result.category).toBe('dane');
		// Should classify as missing DANE since null MX exchange is skipped
		expect(result.findings.length).toBeGreaterThan(0);
	});
});
