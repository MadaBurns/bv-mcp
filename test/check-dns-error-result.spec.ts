// SPDX-License-Identifier: BUSL-1.1

/**
 * Finding 1: every directly-callable check_* wrapper must convert a transient
 * top-level DNS failure (timeout / network error / SERVFAIL) into a structured
 * CheckResult via buildDnsErrorResult — `checkStatus: 'error'` + score 0 +
 * `passed: false` + a high finding carrying `errorKind: 'dns_error'` — instead
 * of throwing. This lets a direct `tools/call` return an actionable finding, and
 * lets scan_domain's transient-zero retry (which keys off `checkStatus ===
 * 'error'`) still fire. buildDnsErrorResult (src/lib/dns-error-result.ts) is the
 * documented reference pattern.
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
	{ name: 'checkSpf', load: async () => (await import('../src/tools/check-spf')).checkSpf },
	{ name: 'checkPtr', load: async () => (await import('../src/tools/check-ptr')).checkPtr },
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
		expect(result.passed).toBe(false); // an errored check did not "pass" (was passed:true with score 0 before)
		expect(result.partial).toBe(true); // keeps the transient error out of the 5-min cache (self-heals)
		const errFinding = result.findings.find((f) => f.metadata?.errorKind === 'dns_error');
		expect(errFinding).toBeDefined();
	});

	it('checkSpf returns a transient-error result (checkStatus=error, score 0, passed false) so the scan retry fires', async () => {
		mockFetchError(new Error('DNS query failed: network timeout'));
		const { checkSpf } = await import('../src/tools/check-spf');

		const result = await checkSpf('example.com');

		expect(result.category).toBe('spf');
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.partial).toBe(true);
		const errFinding = result.findings.find((f) => f.metadata?.errorKind === 'dns_error');
		expect(errFinding).toBeDefined();
	});

	it('checkPtr returns a transient-error result (checkStatus=error, score 0, passed false) so the scan retry fires', async () => {
		mockFetchError(new Error('DNS query failed: network timeout'));
		const { checkPtr } = await import('../src/tools/check-ptr');

		const result = await checkPtr('example.com', undefined, { retries: 0, skipSecondaryConfirmation: true });

		expect(result.category).toBe('ptr');
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.partial).toBe(true);
		const errFinding = result.findings.find((f) => f.metadata?.errorKind === 'dns_error');
		expect(errFinding).toBeDefined();
	});
});
