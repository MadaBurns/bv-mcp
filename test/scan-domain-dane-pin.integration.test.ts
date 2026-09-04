// SPDX-License-Identifier: BUSL-1.1

/**
 * Scan-path scoring-coherence guard for DANE-HTTPS pin verification (#841).
 *
 * `scan_domain` does NOT route through the tool registry — it invokes `checkDaneHttps`
 * from its `CHECK_DISPATCH` table. These tests prove the BV_TLS_PROBE binding is
 * threaded all the way into the scan's `dane_https` category, tier-gated exactly as
 * the `ssl` enrichment is, so a real scan's DANE score reflects the served certificate:
 *
 *   verified pin (100)  >  absent / unverified (95)  >  mismatch (75)
 *
 * Mirrors test/scan-domain-tls-probe.integration.test.ts's domain-agnostic harness.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, tlsaResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { LEAF_SPKI_SHA256, STALE_SHA256, servedCertificate } from '../packages/dns-checks/src/__tests__/checks/served-certificate.fixture';

const { restore } = setupFetchMock();
const TLS_PROBE_AUTH_TOKEN = 'tls-probe-dane-scan-integration-key-32b';

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

function dohName(url: string): string {
	return new URL(url).searchParams.get('name') ?? 'example.com';
}

/**
 * Domain-agnostic clean scan; `tlsaFor` decides what `_443._tcp.<domain>` answers.
 * The TLS probe is a SEPARATE binding object, never global fetch.
 */
function mockCleanScan(tlsaFor: (domain: string) => string | null) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			const name = dohName(url);
			const base = name.replace(/^_[^.]+\./, '').replace(/^[^.]+\._[^.]+\./, '');
			if (url.includes('type=TLSA') || url.includes('type=52')) {
				const m = /^_443\._tcp\.(.+)$/.exec(name);
				const pin = m ? tlsaFor(m[1]) : null;
				return Promise.resolve(
					pin
						? tlsaResponse(name, [{ usage: 3, selector: 1, matchingType: 1, certData: pin }])
						: createDohResponse([{ name, type: 52 }], []),
				);
			}
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (name.includes('_dmarc.')) return Promise.resolve(txtResponse(name, ['v=DMARC1; p=reject']));
				if (name.includes('_domainkey.')) return Promise.resolve(txtResponse(name, ['v=DKIM1; k=rsa; p=MIGf']));
				if (name.includes('_mta-sts.')) return Promise.resolve(txtResponse(name, ['v=STSv1; id=20240101']));
				if (name.includes('_smtp._tls.')) return Promise.resolve(txtResponse(name, ['v=TLSRPTv1; rua=mailto:tls@' + base]));
				if (name.includes('_bimi.')) return Promise.resolve(txtResponse(name, ['v=BIMI1; l=https://' + base + '/logo.svg']));
				return Promise.resolve(txtResponse(name, ['v=spf1 include:_spf.google.com -all']));
			}
			if (url.includes('type=NS') || url.includes('type=2'))
				return Promise.resolve(nsResponse(name, ['ns1.' + base + '.', 'ns2.' + base + '.']));
			if (url.includes('type=CAA') || url.includes('type=257')) return Promise.resolve(caaResponse(name, ['0 issue "letsencrypt.org"']));
			if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse(name, true));
			return Promise.resolve(createDohResponse([], []));
		}

		if (url.startsWith('https://')) {
			return Promise.resolve({
				url,
				ok: true,
				status: 200,
				headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
			} as unknown as Response);
		}
		if (url.startsWith('http://')) {
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: url.replace('http://', 'https://') }),
			} as unknown as Response);
		}
		return Promise.resolve(createDohResponse([], []));
	});
}

/** A bv-tls-probe binding that answers with the served certificate for whatever host was asked. */
function probeBinding(bodyFor: (host: string) => unknown, status = 200) {
	return {
		fetch: vi.fn(async (input: RequestInfo | URL) => {
			const host = new URL(String(input)).searchParams.get('host') ?? '';
			return new Response(JSON.stringify(bodyFor(host)), { status, headers: { 'Content-Type': 'application/json' } });
		}),
	};
}

const certProbe = () =>
	probeBinding((host) => ({ reachable: true, minVersion: 'TLS1.2', maxVersion: 'TLS1.3', certificate: servedCertificate(host) }));

async function daneFor(domain: string, runtimeOptions?: Record<string, unknown>) {
	const { scanDomain } = await import('../src/tools/scan-domain');
	IN_MEMORY_CACHE.clear();
	const result = await scanDomain(domain, undefined, { forceRefresh: true, ...runtimeOptions });
	const check = result.checks.find((c) => c.category === 'dane_https');
	return { categoryScore: result.score.categoryScores.dane_https, check, result };
}

const withProbe = (binding: ReturnType<typeof probeBinding>, authTier = 'enterprise') => ({
	tlsProbeBinding: binding,
	tlsProbeAuthToken: TLS_PROBE_AUTH_TOKEN,
	authTier,
});

describe('scan_domain DANE-HTTPS pin-verification coherence (#841)', () => {
	it('verified 100 > absent 95 > mismatch 75 — the end state, measured through the scan path', async () => {
		mockCleanScan(() => null);
		const absent = await daneFor('daneabsent.com', withProbe(certProbe()));

		mockCleanScan(() => LEAF_SPKI_SHA256);
		const verified = await daneFor('daneverified.com', withProbe(certProbe()));

		mockCleanScan(() => STALE_SHA256);
		const stale = await daneFor('danestale.com', withProbe(certProbe()));

		expect(absent.categoryScore).toBe(95);
		expect(verified.categoryScore).toBe(100);
		expect(stale.categoryScore).toBe(75);
		expect(verified.categoryScore).toBeGreaterThan(absent.categoryScore);
		expect(absent.categoryScore).toBeGreaterThan(stale.categoryScore);

		expect(verified.check!.findings.some((f) => f.metadata?.certificateMatchVerified === true)).toBe(true);
		expect(stale.check!.findings.some((f) => f.severity === 'high' && f.metadata?.certificateMatchVerified === false)).toBe(true);
		// A mismatch is a MEASURED defect, not a missing control — the web-only critical-gap
		// ceiling (64) must not arm on it.
		expect(stale.result.score.overall).not.toBeNull();
		expect(stale.result.score.overall!).toBeGreaterThan(64);
	});

	it('the probe is asked for the EXACT scanned host (the TLSA owner), port 443', async () => {
		mockCleanScan(() => LEAF_SPKI_SHA256);
		const binding = certProbe();
		await daneFor('danehost.com', withProbe(binding));
		const hosts = binding.fetch.mock.calls.map(([input]) => new URL(String(input)).searchParams.get('host'));
		// Both `ssl` and `dane_https` consult the probe; every call pins the scanned host itself.
		expect(hosts.length).toBeGreaterThanOrEqual(2);
		expect(new Set(hosts)).toEqual(new Set(['danehost.com']));
	});

	it('binding absent → 95 present-not-verified (self-host posture), no probe involved', async () => {
		mockCleanScan(() => STALE_SHA256);
		const { categoryScore, check } = await daneFor('danenoprobe.com');
		expect(categoryScore).toBe(95);
		expect(check!.partial).toBeUndefined();
		expect(check!.findings.find((f) => f.title.startsWith('DANE TLSA configured'))?.severity).toBe('low');
	});

	it('free tier → the paid-tier gate withholds the binding: no probe call, 95 unchanged', async () => {
		mockCleanScan(() => STALE_SHA256);
		const binding = certProbe();
		const { categoryScore } = await daneFor('danefree.com', withProbe(binding, 'free'));
		expect(binding.fetch).not.toHaveBeenCalled();
		expect(categoryScore).toBe(95);
	});

	it('cold-cache pending probe → 95 unverified (never above the no-probe posture), check partial, category still completed', async () => {
		mockCleanScan(() => STALE_SHA256);
		const pending = probeBinding(() => ({ error: 'probe pending — cache warming' }));
		const { categoryScore, check } = await daneFor('danepending.com', withProbe(pending));
		expect(categoryScore).toBe(95);
		expect(check!.partial).toBe(true);
		expect(check!.checkStatus).toBeUndefined();
		const low = check!.findings.find((f) => f.title.startsWith('DANE TLSA configured'))!;
		expect(low.severity).toBe('low');
		expect(low.metadata?.notAssessedReason).toBe('certificate_probe_pending');
	});

	it('permanent probe failure (off-host redirect) → 95, NOT partial (no retry-forever)', async () => {
		mockCleanScan(() => STALE_SHA256);
		const redirecting = probeBinding(() => ({ reachable: true, minVersion: 'TLS1.2', certificateError: 'off-host redirect' }));
		const { categoryScore, check } = await daneFor('daneredirect.com', withProbe(redirecting));
		expect(categoryScore).toBe(95);
		expect(check!.partial).toBeUndefined();
		expect(check!.findings.find((f) => f.title.startsWith('DANE TLSA configured'))?.metadata?.notAssessedReason).toBe('off_host_redirect');
	});

	it('no TLSA anywhere → the probe is only ever consulted by `ssl` (DANE stays lazy)', async () => {
		mockCleanScan(() => null);
		const binding = certProbe();
		await daneFor('danelazy.com', withProbe(binding));
		expect(binding.fetch).toHaveBeenCalledOnce();
	});
});
