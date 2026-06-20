// SPDX-License-Identifier: BUSL-1.1

/**
 * Characterization test for the scan_domain per-category dispatch.
 *
 * Pins the EXACT argument shapes reaching the 6 non-uniform checks
 * (mx, ptr, ssl, http_security, dkim, subdomain_takeover) on BOTH the
 * initial-run path (via scanDomain) and the retry path (via the exported
 * runCheckRetry). This is the finer-grained backstop behind scan-domain.spec.ts
 * for the dispatch-table refactor: it must pass against the CURRENT
 * (un-refactored) code first, proving the harness captures args correctly, then
 * stay green across the refactor.
 *
 * Key harness facts (see bv-mcp-testing skill):
 *  - scan-domain re-resolves its STATIC imports after vi.resetModules(), so
 *    vi.doMock replacements are picked up (proven in scan-domain-safe-check.spec.ts).
 *  - The apex NS probe runs through globalThis.fetch BEFORE any check is dispatched;
 *    if it doesn't return NOERROR, the scan short-circuits and zero checks fire.
 *  - Checks only run on cache-miss → forceRefresh:true + IN_MEMORY_CACHE.clear().
 *  - check-dkim exports BOTH checkDkim and applyProviderDkimContext — preserve the
 *    latter when mocking.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse, createDohResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { buildCheckResult } from '../src/lib/scoring';
import type { CheckCategory, CheckResult } from '../src/lib/scoring';
import type { QueryDnsOptions } from '../src/lib/dns-types';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => {
	restore();
	vi.doUnmock('../src/tools/check-mx');
	vi.doUnmock('../src/tools/check-ptr');
	vi.doUnmock('../src/tools/check-ssl');
	vi.doUnmock('../src/tools/check-http-security');
	vi.doUnmock('../src/tools/check-dkim');
	vi.doUnmock('../src/tools/check-subdomain-takeover');
	vi.resetModules();
});

/** Healthy fetch defaults for every check + the apex NS probe (NOERROR). */
function mockAllChecks() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (url.includes('_dmarc.')) return Promise.resolve(txtResponse('_dmarc.example.com', ['v=DMARC1; p=reject']));
				if (url.includes('_domainkey.')) return Promise.resolve(txtResponse('default._domainkey.example.com', ['v=DKIM1; k=rsa; p=MIGf']));
				if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20240101']));
				if (url.includes('_smtp._tls.')) return Promise.resolve(txtResponse('_smtp._tls.example.com', ['v=TLSRPTv1; rua=mailto:tls@example.com']));
				if (url.includes('default._bimi.')) return Promise.resolve(txtResponse('default._bimi.example.com', ['v=BIMI1; l=https://example.com/logo.svg']));
				return Promise.resolve(txtResponse('example.com', ['v=spf1 include:_spf.google.com -all']));
			}
			if (url.includes('type=NS') || url.includes('type=2')) return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			if (url.includes('type=CAA') || url.includes('type=257')) return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse('example.com', true));
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		}
		if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));
		return Promise.resolve(httpResponse('OK'));
	});
}

/** A valid passing CheckResult for the given category, so post-processing/scoring don't choke. */
function okResult(category: CheckCategory): CheckResult {
	return { ...buildCheckResult(category, []), passed: true };
}

/**
 * Install vi.doMock spies for the 6 non-uniform checks and return the spy refs.
 * Each spy resolves a valid CheckResult so the surrounding scan completes.
 * check-dkim preserves applyProviderDkimContext (scan-domain imports both).
 */
function installCheckSpies() {
	const mx = vi.fn().mockResolvedValue(okResult('mx'));
	const ptr = vi.fn().mockResolvedValue(okResult('ptr'));
	const ssl = vi.fn().mockResolvedValue(okResult('ssl'));
	const httpSecurity = vi.fn().mockResolvedValue(okResult('http_security'));
	const dkim = vi.fn().mockResolvedValue(okResult('dkim'));
	const subdomainTakeover = vi.fn().mockResolvedValue(okResult('subdomain_takeover'));

	vi.doMock('../src/tools/check-mx', () => ({ checkMx: mx }));
	vi.doMock('../src/tools/check-ptr', () => ({ checkPtr: ptr }));
	vi.doMock('../src/tools/check-ssl', () => ({ checkSsl: ssl }));
	vi.doMock('../src/tools/check-http-security', () => ({ checkHttpSecurity: httpSecurity }));
	vi.doMock('../src/tools/check-dkim', async (orig) => ({
		...(await (orig() as Promise<Record<string, unknown>>)),
		checkDkim: dkim,
	}));
	vi.doMock('../src/tools/check-subdomain-takeover', () => ({ checkSubdomainTakeover: subdomainTakeover }));

	return { mx, ptr, ssl, httpSecurity, dkim, subdomainTakeover };
}

const PROVIDER_SIG_OPTS = {
	providerSignaturesUrl: 'https://sigs.example/list.json',
	providerSignaturesAllowedHosts: ['sigs.example'],
	providerSignaturesSha256: 'abc123',
};

const tlsBinding = { fetch: vi.fn() } as unknown as { fetch: typeof fetch };

describe('scan_domain per-category dispatch — initial run path', () => {
	it('passes the bespoke arg shapes to the 6 non-uniform checks (eligible tier → tls binding present)', async () => {
		vi.resetModules();
		const spies = installCheckSpies();
		mockAllChecks();

		const { scanDomain } = await import('../src/tools/scan-domain');
		await scanDomain('example.com', undefined, {
			forceRefresh: true,
			authTier: 'owner', // PROBE_ELIGIBLE_TIERS member
			tlsProbeBinding: tlsBinding,
			tlsProbeAuthToken: 'tls-token',
			...PROVIDER_SIG_OPTS,
		});

		// Gate: every spy must have fired ≥1 time, else the harness short-circuited.
		for (const [name, spy] of Object.entries(spies)) {
			expect(spy, `${name} should have been called`).toHaveBeenCalled();
		}

		// mx: (domain, { providerSignatures* }, dnsOptions)
		const mxCall = spies.mx.mock.calls[0];
		expect(mxCall[0]).toBe('example.com');
		expect(mxCall[1]).toEqual(PROVIDER_SIG_OPTS);
		expect(mxCall[2]).toEqual(expect.objectContaining({ skipSecondaryConfirmation: true }));
		expect(mxCall.length).toBe(3);

		// ptr: same options object shape as mx, plus dnsOptions
		const ptrCall = spies.ptr.mock.calls[0];
		expect(ptrCall[0]).toBe('example.com');
		expect(ptrCall[1]).toEqual(PROVIDER_SIG_OPTS);
		expect(ptrCall[2]).toEqual(expect.objectContaining({ skipSecondaryConfirmation: true }));
		expect(ptrCall.length).toBe(3);

		// ssl: (domain, { tlsProbeBinding, tlsProbeAuthToken, signal }) — NO dnsOptions.
		// R7: the scan-path threads the per-check abort signal into the options object.
		const sslCall = spies.ssl.mock.calls[0];
		expect(sslCall[0]).toBe('example.com');
		expect(sslCall[1]).toEqual({
			tlsProbeBinding: tlsBinding,
			tlsProbeAuthToken: 'tls-token',
			signal: expect.any(AbortSignal),
		});
		expect(sslCall.length).toBe(2);

		// http_security: (domain, { signal }) — R7 threads the per-check abort signal.
		const httpCall = spies.httpSecurity.mock.calls[0];
		expect(httpCall[0]).toBe('example.com');
		expect(httpCall[1]).toEqual({ signal: expect.any(AbortSignal) });
		expect(httpCall.length).toBe(2);

		// dkim: (domain, undefined, dnsOptions)
		const dkimCall = spies.dkim.mock.calls[0];
		expect(dkimCall[0]).toBe('example.com');
		expect(dkimCall[1]).toBeUndefined();
		expect(dkimCall[2]).toEqual(expect.objectContaining({ skipSecondaryConfirmation: true }));
		expect(dkimCall.length).toBe(3);

		// subdomain_takeover: (domain, dnsOptions)
		const stCall = spies.subdomainTakeover.mock.calls[0];
		expect(stCall[0]).toBe('example.com');
		expect(stCall[1]).toEqual(expect.objectContaining({ skipSecondaryConfirmation: true }));
		expect(stCall.length).toBe(2);
	});

	it('ssl tls binding is undefined for an INELIGIBLE tier (token still forwarded)', async () => {
		vi.resetModules();
		const spies = installCheckSpies();
		mockAllChecks();

		const { scanDomain } = await import('../src/tools/scan-domain');
		await scanDomain('example.com', undefined, {
			forceRefresh: true,
			authTier: 'free', // NOT in PROBE_ELIGIBLE_TIERS
			tlsProbeBinding: tlsBinding,
			tlsProbeAuthToken: 'tls-token',
		});

		expect(spies.ssl).toHaveBeenCalled();
		const sslCall = spies.ssl.mock.calls[0];
		// R7: scan-path threads the per-check abort signal into the ssl options.
		expect(sslCall[1]).toEqual({
			tlsProbeBinding: undefined,
			tlsProbeAuthToken: 'tls-token',
			signal: expect.any(AbortSignal),
		});
		expect(sslCall.length).toBe(2);
	});
});

describe('scan_domain per-category dispatch — retry path (runCheckRetry)', () => {
	const retryDnsBase: QueryDnsOptions = { skipSecondaryConfirmation: true, queryCache: new Map() };

	async function loadRetry() {
		vi.resetModules();
		const spies = installCheckSpies();
		const { runCheckRetry } = await import('../src/tools/scan-domain');
		return { runCheckRetry, spies };
	}

	it('mx retry: (domain, { providerSignatures* }, retryDns with skipSecondaryConfirmation)', async () => {
		const { runCheckRetry, spies } = await loadRetry();
		await runCheckRetry('mx', 'example.com', retryDnsBase, 5000, { ...PROVIDER_SIG_OPTS, authTier: 'owner' });
		const call = spies.mx.mock.calls[0];
		expect(call[0]).toBe('example.com');
		expect(call[1]).toEqual(PROVIDER_SIG_OPTS);
		expect(call[2]).toEqual(expect.objectContaining({ skipSecondaryConfirmation: true }));
		expect(call.length).toBe(3);
	});

	it('ptr retry: (domain, { providerSignatures* }, retryDns)', async () => {
		const { runCheckRetry, spies } = await loadRetry();
		await runCheckRetry('ptr', 'example.com', retryDnsBase, 5000, { ...PROVIDER_SIG_OPTS });
		const call = spies.ptr.mock.calls[0];
		expect(call[0]).toBe('example.com');
		expect(call[1]).toEqual(PROVIDER_SIG_OPTS);
		expect(call[2]).toEqual(expect.objectContaining({ skipSecondaryConfirmation: true }));
		expect(call.length).toBe(3);
	});

	it('ssl retry: ignores retryDns, recomputes tier gate (eligible → binding present, no 3rd arg)', async () => {
		const { runCheckRetry, spies } = await loadRetry();
		await runCheckRetry('ssl', 'example.com', retryDnsBase, 5000, {
			authTier: 'owner',
			tlsProbeBinding: tlsBinding,
			tlsProbeAuthToken: 'tls-token',
		});
		const call = spies.ssl.mock.calls[0];
		expect(call[0]).toBe('example.com');
		expect(call[1]).toEqual({ tlsProbeBinding: tlsBinding, tlsProbeAuthToken: 'tls-token' });
		expect(call.length).toBe(2);
	});

	it('ssl retry: ineligible tier → binding undefined', async () => {
		const { runCheckRetry, spies } = await loadRetry();
		await runCheckRetry('ssl', 'example.com', retryDnsBase, 5000, {
			authTier: 'free',
			tlsProbeBinding: tlsBinding,
			tlsProbeAuthToken: 'tls-token',
		});
		const call = spies.ssl.mock.calls[0];
		expect(call[1]).toEqual({ tlsProbeBinding: undefined, tlsProbeAuthToken: 'tls-token' });
		expect(call.length).toBe(2);
	});

	it('http_security retry: (domain, { signal: undefined }) — retry path passes no per-check signal', async () => {
		const { runCheckRetry, spies } = await loadRetry();
		await runCheckRetry('http_security', 'example.com', retryDnsBase, 5000, undefined);
		const call = spies.httpSecurity.mock.calls[0];
		expect(call[0]).toBe('example.com');
		// R7: the retry path supplies no per-check signal (no abort plumbing on a retry),
		// so the options object carries `signal: undefined` — a behavioural no-op.
		expect(call[1]).toEqual({ signal: undefined });
		expect(call.length).toBe(2);
	});

	it('dkim retry: (domain, undefined, retryDns)', async () => {
		const { runCheckRetry, spies } = await loadRetry();
		await runCheckRetry('dkim', 'example.com', retryDnsBase, 5000, undefined);
		const call = spies.dkim.mock.calls[0];
		expect(call[0]).toBe('example.com');
		expect(call[1]).toBeUndefined();
		expect(call[2]).toEqual(expect.objectContaining({ skipSecondaryConfirmation: true }));
		expect(call.length).toBe(3);
	});

	it('subdomain_takeover retry: (domain, retryDns)', async () => {
		const { runCheckRetry, spies } = await loadRetry();
		await runCheckRetry('subdomain_takeover', 'example.com', retryDnsBase, 5000, undefined);
		const call = spies.subdomainTakeover.mock.calls[0];
		expect(call[0]).toBe('example.com');
		expect(call[1]).toEqual(expect.objectContaining({ skipSecondaryConfirmation: true }));
		expect(call.length).toBe(2);
	});

	it('retry of an out-of-table category returns the synthetic error default', async () => {
		const { runCheckRetry } = await loadRetry();
		const result = await runCheckRetry('authoritative_dns_infra' as CheckCategory, 'example.com', retryDnsBase, 5000, undefined);
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.checkStatus).toBe('error');
	});
});
