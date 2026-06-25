// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #455 — the MTA-STS policy fetch must not emit a confident `high`
 * "policy file not accessible" finding when the fetch was intercepted by a
 * Cloudflare/Akamai WAF challenge/block (commonly HTTP 403). Real sending MTAs
 * are not subject to the interactive challenge, so a healthy policy (the
 * blackveilsecurity.com repro) was being falsely flagged. The interception is
 * downgraded to an inconclusive `info` and the score recomputed.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

function txtResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 16 }],
		records.map((data) => ({ name: domain, type: 16, TTL: 300, data: `"${data}"` })),
	);
}

/** A real Response for the policy fetch — exercises the genuine .ok/.status/.headers/.clone() path. */
function policyHttp(status: number, headers: Record<string, string> = {}, body = ''): Response {
	return new Response(body || null, { status, headers });
}

/** Mock the DoH DNS lookups + the policy-file fetch, keyed by URL like the sibling spec. */
function mockFetch(opts: { mtaStsDns?: Response; tlsrptDns?: Response; policyFetch?: Response }) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('_mta-sts.') && opts.mtaStsDns) return Promise.resolve(opts.mtaStsDns);
			if (url.includes('_smtp._tls.') && opts.tlsrptDns) return Promise.resolve(opts.tlsrptDns);
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(opts.policyFetch ?? policyHttp(404));
		}
		return Promise.resolve(policyHttp(404));
	});
}

describe('checkMtaSts — WAF-challenged policy fetch (issue #455)', () => {
	async function run(domain = 'example.com') {
		const { checkMtaSts } = await import('../src/tools/check-mta-sts');
		return checkMtaSts(domain);
	}

	const validTxt = (d: string) => txtResponse(`_mta-sts.${d}`, ['v=STSv1; id=20260114010000']);
	const validTlsRpt = (d: string) => txtResponse(`_smtp._tls.${d}`, ['v=TLSRPTv1; rua=mailto:tlsrpt@example.com']);

	it('downgrades a Cloudflare challenge (403 + cf-mitigated) to an inconclusive info — no high finding', async () => {
		mockFetch({
			mtaStsDns: validTxt('example.com'),
			tlsrptDns: validTlsRpt('example.com'),
			policyFetch: policyHttp(403, { 'cf-ray': '91def5678-AKL', 'cf-mitigated': 'challenge', server: 'cloudflare' }),
		});

		const result = await run();

		// The false-positive high must be gone…
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
		expect(result.findings.some((f) => f.title === 'MTA-STS policy file not accessible')).toBe(false);
		// …replaced by an inconclusive challenge finding…
		const waf = result.findings.find((f) => f.metadata?.wafKind === 'challenge');
		expect(waf).toBeDefined();
		expect(waf!.severity).toBe('info');
		expect(waf!.metadata?.inconclusive).toBe(true);
		expect(waf!.metadata?.httpStatus).toBe(403);
		// …with the TXT-record control still credited and the score recovered off the floor.
		expect(result.controlPresent).toBe(true);
		expect(result.score).toBeGreaterThan(75);
	});

	it('downgrades a Cloudflare block page (403 + block body) to an inconclusive info', async () => {
		mockFetch({
			mtaStsDns: validTxt('example.com'),
			tlsrptDns: validTlsRpt('example.com'),
			policyFetch: policyHttp(403, { 'cf-ray': '91def5678-AKL', server: 'cloudflare' }, 'Sorry, you have been blocked'),
		});

		const result = await run();

		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
		const waf = result.findings.find((f) => f.metadata?.wafEvent === 'cloudflare');
		expect(waf).toBeDefined();
		expect(waf!.metadata?.wafKind).toBe('block');
		expect(waf!.metadata?.inconclusive).toBe(true);
	});

	it('downgrades a WAF-intercepted redirect (301 + cf-mitigated) — replaces the policy-redirects high', async () => {
		mockFetch({
			mtaStsDns: validTxt('example.com'),
			tlsrptDns: validTlsRpt('example.com'),
			policyFetch: policyHttp(301, { 'cf-ray': '91def5678-AKL', 'cf-mitigated': 'challenge', server: 'cloudflare', location: 'https://challenge.cloudflare.com/' }),
		});

		const result = await run();

		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
		expect(result.findings.some((f) => f.title === 'MTA-STS policy redirects')).toBe(false);
		expect(result.findings.some((f) => f.metadata?.inconclusive === true)).toBe(true);
	});

	it('bounds the body sniff on a hostile oversized 403 — still detects, does not buffer the whole body', async () => {
		// block marker up front, then ~1 MB of attacker-controlled padding. The bounded
		// reader must detect the block from the early bytes without buffering it all.
		const hostileBody = 'Sorry, you have been blocked' + 'A'.repeat(1_000_000);
		mockFetch({
			mtaStsDns: validTxt('example.com'),
			tlsrptDns: validTlsRpt('example.com'),
			policyFetch: policyHttp(403, { 'cf-ray': '91def5678-AKL', server: 'cloudflare' }, hostileBody),
		});

		const result = await run();

		// Detection still works off the early bytes; the false-positive high is gone.
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
		const waf = result.findings.find((f) => f.metadata?.wafEvent === 'cloudflare');
		expect(waf).toBeDefined();
		expect(waf!.metadata?.wafKind).toBe('block');
	});

	it('does NOT downgrade a genuine (non-WAF) 403 — the high finding is preserved', async () => {
		mockFetch({
			mtaStsDns: validTxt('example.com'),
			tlsrptDns: validTlsRpt('example.com'),
			// Plain origin 403, no Cloudflare/Akamai signals → looksLikeWaf is false → no downgrade.
			policyFetch: policyHttp(403, { server: 'nginx' }),
		});

		const result = await run();

		expect(result.findings.some((f) => f.title === 'MTA-STS policy file not accessible' && f.severity === 'high')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.inconclusive === true)).toBe(false);
	});
});
