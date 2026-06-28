// SPDX-License-Identifier: BUSL-1.1

/**
 * Audit — MTA-STS policy-fetch finding-title coupling (issue #455).
 *
 * src/tools/check-mta-sts.ts identifies the @blackveil/dns-checks package's
 * false-positive policy-fetch findings by EXACT title via
 * `POLICY_FETCH_FALSE_POSITIVE_TITLES = new Set([...])`, then downgrades them
 * when a WAF intercepts the policy fetch. That Set is a brittle cross-package
 * string coupling: if the package ever rewords either title, the Set silently
 * stops matching and the WAF false-positive reappears in production with no
 * other test catching the drift.
 *
 * This audit pins the coupling. It drives the real production wrapper
 * (`checkMtaSts`) against the two GENUINE (non-WAF) failure conditions — a plain
 * 404 (policy file not accessible) and a plain 301 (policy redirects), both with
 * NO Cloudflare/Akamai WAF signal so the wrapper's downgrade does NOT fire — and
 * asserts the emitted finding titles are EXACTLY the strings the Set relies on.
 * If the package rewords a title, this audit goes red, forcing a maintainer to
 * update the Set too.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from '../helpers/dns-mock';
import type { Finding } from '../../src/lib/scoring';

// SSOT-coupling tripwire: these MUST match POLICY_FETCH_FALSE_POSITIVE_TITLES in
// src/tools/check-mta-sts.ts. If the @blackveil/dns-checks package rewords a
// title, update BOTH.
const TITLE_NOT_ACCESSIBLE = 'MTA-STS policy file not accessible';
const TITLE_REDIRECTS = 'MTA-STS policy redirects';

const { restore } = setupFetchMock();
afterEach(() => restore());

function txtResponse(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 16 }],
		records.map((data) => ({ name: domain, type: 16, TTL: 300, data: `"${data}"` })),
	);
}

/** A real Response for the policy fetch — exercises the genuine .ok/.status/.headers path. */
function policyHttp(status: number, headers: Record<string, string> = {}, body = ''): Response {
	return new Response(body || null, { status, headers });
}

/** Mock the DoH DNS lookups + the policy-file fetch, keyed by URL. */
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

describe('audit — MTA-STS policy-fetch title coupling (issue #455 Set tripwire)', () => {
	async function run(domain = 'example.com') {
		// Dynamic import inside the test fn — bind the wrapper AFTER the fetch mock is installed.
		const { checkMtaSts } = await import('../../src/tools/check-mta-sts');
		return checkMtaSts(domain);
	}

	// A valid _mta-sts TXT record so the check proceeds to the policy fetch.
	const validTxt = (d: string) => txtResponse(`_mta-sts.${d}`, ['v=STSv1; id=20260114010000']);
	const validTlsRpt = (d: string) => txtResponse(`_smtp._tls.${d}`, ['v=TLSRPTv1; rua=mailto:tlsrpt@example.com']);

	it(`emits the EXACT title "${TITLE_NOT_ACCESSIBLE}" on a genuine (non-WAF) 404`, async () => {
		mockFetch({
			mtaStsDns: validTxt('example.com'),
			tlsrptDns: validTlsRpt('example.com'),
			// Plain origin 404, no Cloudflare/Akamai signals → looksLikeWaf is false → no downgrade.
			policyFetch: policyHttp(404, { server: 'nginx' }, 'Not Found'),
		});

		const result = await run();

		// No WAF downgrade occurred — the genuine package finding passes through untouched.
		expect(result.findings.some((f: Finding) => f.metadata?.inconclusive === true)).toBe(false);
		// The package emits the EXACT title the Set keys on.
		expect(result.findings.some((f: Finding) => f.title === TITLE_NOT_ACCESSIBLE)).toBe(true);
	});

	it(`emits the EXACT title "${TITLE_REDIRECTS}" on a genuine (non-WAF) 301 redirect`, async () => {
		mockFetch({
			mtaStsDns: validTxt('example.com'),
			tlsrptDns: validTlsRpt('example.com'),
			// Plain origin 301 redirect, no Cloudflare/Akamai signals → no downgrade.
			policyFetch: policyHttp(301, { server: 'nginx', location: 'https://example.com/mta-sts.txt' }),
		});

		const result = await run();

		expect(result.findings.some((f: Finding) => f.metadata?.inconclusive === true)).toBe(false);
		expect(result.findings.some((f: Finding) => f.title === TITLE_REDIRECTS)).toBe(true);
	});
});
