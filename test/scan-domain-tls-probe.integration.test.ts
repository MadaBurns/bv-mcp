// SPDX-License-Identifier: BUSL-1.1

/**
 * Scan-path scoring-coherence guard for the operator-only BV_TLS_PROBE enrichment.
 *
 * `scan_domain` does NOT route through the tool registry — it invokes `checkSsl`
 * directly inside `scanDomain` (see scan-domain.ts). These tests prove the probe
 * binding is threaded all the way into the scan's `ssl` category so a real scan's
 * SSL score reflects legacy-TLS detection:
 *
 *   - probe TLS1.1  → ssl category score strictly BELOW probe-absent (High penalty)
 *   - probe TLS1.2  → ssl category score EXACTLY EQUAL to probe-absent
 *                     (the must-not-penalize-1.2 guard)
 *   - binding absent → unchanged baseline
 *
 * Mirrors test/scan-domain.spec.ts's mockAllChecks harness, made domain-agnostic
 * (echoes the queried `name`) so three distinct domains avoid cross-call cache bleed.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => restore());

/** Extract the `name` query param from a DoH URL so responses echo the queried domain (domain-agnostic). */
function dohName(url: string): string {
	return new URL(url).searchParams.get('name') ?? 'example.com';
}

/**
 * Domain-agnostic fetch mock: every check gets a clean, passing response, and the
 * SSL check specifically sees HTTPS 200 + HSTS and HTTP→HTTPS 301 (info-only SSL).
 * The TLS probe is a SEPARATE binding object (below), never global fetch.
 */
function mockCleanScan() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

		if (url.includes('cloudflare-dns.com')) {
			const name = dohName(url);
			const base = name.replace(/^_[^.]+\./, '').replace(/^[^.]+\._[^.]+\./, '');
			if (url.includes('type=TXT') || url.includes('type=16')) {
				if (name.includes('_dmarc.')) return Promise.resolve(txtResponse(name, ['v=DMARC1; p=reject']));
				if (name.includes('_domainkey.')) return Promise.resolve(txtResponse(name, ['v=DKIM1; k=rsa; p=MIGf']));
				if (name.includes('_mta-sts.')) return Promise.resolve(txtResponse(name, ['v=STSv1; id=20240101']));
				if (name.includes('_smtp._tls.')) return Promise.resolve(txtResponse(name, ['v=TLSRPTv1; rua=mailto:tls@' + base]));
				if (name.includes('_bimi.')) return Promise.resolve(txtResponse(name, ['v=BIMI1; l=https://' + base + '/logo.svg']));
				return Promise.resolve(txtResponse(name, ['v=spf1 include:_spf.google.com -all']));
			}
			if (url.includes('type=NS') || url.includes('type=2')) return Promise.resolve(nsResponse(name, ['ns1.' + base + '.', 'ns2.' + base + '.']));
			if (url.includes('type=CAA') || url.includes('type=257')) return Promise.resolve(caaResponse(name, ['0 issue "letsencrypt.org"']));
			if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse(name, true));
			return Promise.resolve(createDohResponse([], []));
		}

		// SSL check: HTTPS reachable + HSTS, HTTP → HTTPS redirect.
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

/** A bv-tls-probe service-binding mock returning the given JSON body. */
function probeBinding(body: unknown, status = 200) {
	return { fetch: vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })) };
}

async function sslScoreFor(domain: string, runtimeOptions?: Record<string, unknown>) {
	const { scanDomain } = await import('../src/tools/scan-domain');
	IN_MEMORY_CACHE.clear();
	const result = await scanDomain(domain, undefined, { forceRefresh: true, ...runtimeOptions });
	const sslCheck = result.checks.find((c) => c.category === 'ssl');
	return { categoryScore: result.score.categoryScores.ssl, sslCheck };
}

describe('scan_domain TLS-probe scoring coherence', () => {
	it('probe absent → SSL category is the clean baseline (no TLS-version finding)', async () => {
		mockCleanScan();
		const { categoryScore, sslCheck } = await sslScoreFor('tlsabsent.com');
		expect(sslCheck).toBeDefined();
		expect(sslCheck!.findings.some((f) => f.metadata?.tlsProbeEnriched === true)).toBe(false);
		expect(categoryScore).toBeGreaterThan(0);
	});

	it('probe TLS1.1 → SSL category score strictly BELOW probe-absent, with a High enriched finding', async () => {
		mockCleanScan();
		const baseline = await sslScoreFor('tlsbase1.com');
		mockCleanScan();
		const weak = await sslScoreFor('tlsweak.com', {
			tlsProbeBinding: probeBinding({ reachable: true, minVersion: 'TLS1.1', maxVersion: 'TLS1.2' }),
		});
		expect(weak.categoryScore).toBeLessThan(baseline.categoryScore);
		const enriched = weak.sslCheck!.findings.find((f) => f.metadata?.tlsProbeEnriched === true);
		expect(enriched).toBeDefined();
		expect(enriched!.severity).toBe('high');
	});

	it('probe TLS1.2 → SSL category score EXACTLY EQUAL to probe-absent (must-not-penalize-1.2)', async () => {
		mockCleanScan();
		const baseline = await sslScoreFor('tlsbase2.com');
		mockCleanScan();
		const modern = await sslScoreFor('tlsmodern.com', {
			tlsProbeBinding: probeBinding({ reachable: true, minVersion: 'TLS1.2', maxVersion: 'TLS1.3' }),
		});
		expect(modern.categoryScore).toBe(baseline.categoryScore);
		expect(modern.sslCheck!.findings.some((f) => f.metadata?.tlsProbeEnriched === true)).toBe(false);
	});

	it('probe unreachable → SSL category unchanged (inconclusive, no penalty)', async () => {
		mockCleanScan();
		const baseline = await sslScoreFor('tlsbase3.com');
		mockCleanScan();
		const down = await sslScoreFor('tlsdown.com', {
			tlsProbeBinding: probeBinding({ reachable: false, error: 'connect timeout' }),
		});
		expect(down.categoryScore).toBe(baseline.categoryScore);
		expect(down.sslCheck!.findings.some((f) => f.metadata?.tlsProbeEnriched === true)).toBe(false);
	});
});
