// SPDX-License-Identifier: BUSL-1.1

/**
 * Scan-path scoring-coherence guard for DANE-HTTPS pin verification (#841), now
 * KILL-SWITCHED (3.75.1, `DANE_PIN_VERIFICATION_ENABLED = false`).
 *
 * `scan_domain` does NOT route through the tool registry — it invokes `checkDaneHttps`
 * from its `CHECK_DISPATCH` table. These tests prove that, measured through a real scan
 * with the BV_TLS_PROBE binding threaded in exactly as the `ssl` enrichment is, the
 * `dane_https` category NEVER moves on the probe's capture any more: every pin sits at
 * the unverified 95 with the permanent `probe_vantage_intercepted` sub-state, the probe
 * is consulted only by `ssl`, and neither the 3.75.0 false mismatch (75) nor a verified
 * 100 can be produced from the intercepted Browser Rendering vantage.
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

/** A bv-tls-probe binding that answers with a served certificate for whatever host was asked. */
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

function expectIntercepted(check: Awaited<ReturnType<typeof daneFor>>['check']) {
	expect(check!.partial).toBeUndefined();
	expect(check!.checkStatus).toBeUndefined();
	const low = check!.findings.find((f) => f.title.startsWith('DANE TLSA configured'))!;
	expect(low.severity).toBe('low');
	expect(low.metadata?.certificateMatchVerified).toBe(false);
	expect(low.metadata?.certificateProbe).toBe('failed');
	expect(low.metadata?.notAssessedReason).toBe('probe_vantage_intercepted');
	expect(check!.findings.some((f) => f.severity === 'high')).toBe(false);
}

describe('scan_domain DANE-HTTPS pin verification is kill-switched on the scan path (3.75.1)', () => {
	it('would-match, would-mismatch and absent all sit at 95 — the capture never moves the category', async () => {
		mockCleanScan(() => null);
		const absent = await daneFor('daneabsent.com', withProbe(certProbe()));

		mockCleanScan(() => LEAF_SPKI_SHA256);
		const wouldMatch = await daneFor('daneverified.com', withProbe(certProbe()));

		mockCleanScan(() => STALE_SHA256);
		const wouldMismatch = await daneFor('danestale.com', withProbe(certProbe()));

		expect(absent.categoryScore).toBe(95);
		expect(wouldMatch.categoryScore).toBe(95);
		expect(wouldMismatch.categoryScore).toBe(95);
		expect(wouldMatch.check!.findings.some((f) => f.metadata?.certificateMatchVerified === true)).toBe(false);
		expectIntercepted(wouldMatch.check);
		expectIntercepted(wouldMismatch.check);
		// No DANE credit toward Stage 4 can be earned from this vantage, and nothing below
		// the 1.18.0 posture can be produced either: the scan is above the critical-gap cap.
		expect(wouldMismatch.result.score.overall).not.toBeNull();
		expect(wouldMismatch.result.score.overall!).toBeGreaterThan(64);
	});

	it('the probe is consulted ONLY by `ssl`: with a TLSA record present, DANE spends no probe call', async () => {
		mockCleanScan(() => LEAF_SPKI_SHA256);
		const binding = certProbe();
		await daneFor('danehost.com', withProbe(binding));
		expect(binding.fetch).toHaveBeenCalledOnce();
		const hosts = binding.fetch.mock.calls.map(([input]) => new URL(String(input)).searchParams.get('host'));
		expect(hosts).toEqual(['danehost.com']);
	});

	it('binding absent → 95 present-not-verified (self-host posture), no probe metadata at all', async () => {
		mockCleanScan(() => STALE_SHA256);
		const { categoryScore, check } = await daneFor('danenoprobe.com');
		expect(categoryScore).toBe(95);
		expect(check!.partial).toBeUndefined();
		const low = check!.findings.find((f) => f.title.startsWith('DANE TLSA configured'))!;
		expect(low.severity).toBe('low');
		expect(low.metadata?.certificateProbe).toBeUndefined();
		expect(low.metadata?.notAssessedReason).toBeUndefined();
	});

	it('free tier → the paid-tier gate withholds the binding: no probe call, 95, self-host posture', async () => {
		mockCleanScan(() => STALE_SHA256);
		const binding = certProbe();
		const { categoryScore, check } = await daneFor('danefree.com', withProbe(binding, 'free'));
		expect(binding.fetch).not.toHaveBeenCalled();
		expect(categoryScore).toBe(95);
		expect(check!.findings.find((f) => f.title.startsWith('DANE TLSA configured'))?.metadata?.notAssessedReason).toBeUndefined();
	});

	it('a probe that would answer "pending" or "off-host redirect" is never asked — the result is the same permanent sub-state', async () => {
		mockCleanScan(() => STALE_SHA256);
		const pending = probeBinding(() => ({ error: 'probe pending — cache warming' }));
		const a = await daneFor('danepending.com', withProbe(pending));
		expect(a.categoryScore).toBe(95);
		expectIntercepted(a.check);

		mockCleanScan(() => STALE_SHA256);
		const redirecting = probeBinding(() => ({ reachable: true, minVersion: 'TLS1.2', certificateError: 'off-host redirect' }));
		const b = await daneFor('daneredirect.com', withProbe(redirecting));
		expect(b.categoryScore).toBe(95);
		expectIntercepted(b.check);
	});

	it('no TLSA anywhere → the probe is only ever consulted by `ssl` (DANE stays lazy)', async () => {
		mockCleanScan(() => null);
		const binding = certProbe();
		await daneFor('danelazy.com', withProbe(binding));
		expect(binding.fetch).toHaveBeenCalledOnce();
	});
});
