// SPDX-License-Identifier: BUSL-1.1

/**
 * Finding 1: every directly-callable check_* wrapper must convert a transient
 * top-level DNS failure (timeout / network error / SERVFAIL) into a structured
 * CheckResult with `missingControl: true` + `errorKind`, instead of throwing —
 * so a direct `tools/call` returns an actionable finding rather than a generic
 * "unexpected error". check-spf.ts is the documented reference pattern.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { setupFetchMock, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

// Every directly-callable check wrapper, called with just a domain.
const WRAPPERS: { name: string; load: () => Promise<(domain: string) => Promise<{ category: string; findings: { metadata?: Record<string, unknown> }[] }>> }[] = [
	{ name: 'checkDmarc', load: async () => (await import('../src/tools/check-dmarc')).checkDmarc },
	{ name: 'checkDkim', load: async () => (await import('../src/tools/check-dkim')).checkDkim },
	{ name: 'checkCaa', load: async () => (await import('../src/tools/check-caa')).checkCaa },
	{ name: 'checkNs', load: async () => (await import('../src/tools/check-ns')).checkNs },
	{ name: 'checkMtaSts', load: async () => (await import('../src/tools/check-mta-sts')).checkMtaSts },
	{ name: 'checkTlsrpt', load: async () => (await import('../src/tools/check-tlsrpt')).checkTlsrpt },
	{ name: 'checkBimi', load: async () => (await import('../src/tools/check-bimi')).checkBimi },
	{ name: 'checkDane', load: async () => (await import('../src/tools/check-dane')).checkDane },
	{ name: 'checkDaneHttps', load: async () => (await import('../src/tools/check-dane-https')).checkDaneHttps },
	{ name: 'checkSvcbHttps', load: async () => (await import('../src/tools/check-svcb-https')).checkSvcbHttps },
	{ name: 'checkSubdomailing', load: async () => (await import('../src/tools/check-subdomailing')).checkSubdomailing },
	{ name: 'checkSubdomainTakeover', load: async () => (await import('../src/tools/check-subdomain-takeover')).checkSubdomainTakeover },
	{ name: 'checkResolverConsistency', load: async () => (await import('../src/tools/check-resolver-consistency')).checkResolverConsistency },
	{ name: 'checkSsl', load: async () => (await import('../src/tools/check-ssl')).checkSsl },
];

describe('check_* wrappers return a structured CheckResult on transient DNS failure', () => {
	it.each(WRAPPERS)('$name resolves a CheckResult instead of throwing', async ({ load }) => {
		mockFetchError(new Error('network timeout'));
		const fn = await load();

		const result = await fn('example.com');

		expect(result).toBeDefined();
		expect(result.category).toBeTruthy();
	});

	it('checkDmarc returns a transient-error result (checkStatus=error, score 0) so the scan retry still fires', async () => {
		mockFetchError(new Error('DNS query failed: network timeout'));
		const { checkDmarc } = await import('../src/tools/check-dmarc');

		const result = await checkDmarc('example.com');

		expect(result.category).toBe('dmarc');
		expect(result.checkStatus).toBe('error'); // shouldRetry() keys off this
		expect(result.score).toBe(0);
		expect(result.partial).toBe(true); // keeps the transient error out of the 5-min cache (self-heals)
		const errFinding = result.findings.find((f) => f.metadata?.errorKind === 'dns_error');
		expect(errFinding).toBeDefined();
	});
});
