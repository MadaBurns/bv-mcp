// SPDX-License-Identifier: BUSL-1.1

/**
 * Task 9 (bot-policy-scanner-ua plan) — the MTA-STS policy fetch must honor
 * robots.txt on the `mta-sts.<domain>` host, reusing the EXISTING WAF-exclusion
 * path (`excludeForPolicyThrow` / `isObservableFetchThrow`) rather than adding a
 * new one: a robots.txt disallow is philosophically the same shape of problem as
 * a WAF interception ("the policy fetch was blocked externally, for a reason
 * unrelated to the domain's actual security posture") and now throws
 * `RobotsDisallowedError` from the gated fetch, which `observingFetch` observes,
 * re-throws (so the package still runs its own catch path), and which
 * `isObservableFetchThrow` now recognizes — so `excludeForPolicyThrow` fires
 * automatically, same as an AbortError/TimeoutError stall.
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

function plainResponse(status: number, headers: Record<string, string> = {}, body = ''): Response {
	return new Response(body || null, { status, headers });
}

/**
 * Mock the DoH DNS lookups + the `mta-sts.<domain>` robots.txt fetch + the policy
 * fetch. `withRobotsGate` fetches `https://mta-sts.<domain>/robots.txt` (memoized
 * per-hostname for the gated-fetch's lifetime) before allowing the policy fetch
 * through — so a disallowing robots.txt must prevent the policy fetch from ever
 * being reached.
 */
function mockFetch(opts: { mtaStsDns?: Response; tlsrptDns?: Response; robots?: Response; policyFetch?: Response }) {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		if (url.includes('cloudflare-dns.com')) {
			if (url.includes('_mta-sts.') && opts.mtaStsDns) return Promise.resolve(opts.mtaStsDns);
			if (url.includes('_smtp._tls.') && opts.tlsrptDns) return Promise.resolve(opts.tlsrptDns);
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.endsWith('/robots.txt')) {
			return Promise.resolve(opts.robots ?? plainResponse(404));
		}
		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(opts.policyFetch ?? plainResponse(404));
		}
		return Promise.resolve(plainResponse(404));
	});
}

describe('checkMtaSts — robots.txt disallow on the policy fetch', () => {
	async function run(domain = 'example.com') {
		const { checkMtaSts } = await import('../src/tools/check-mta-sts');
		return checkMtaSts(domain);
	}

	const validTxt = (d: string) => txtResponse(`_mta-sts.${d}`, ['v=STSv1; id=20260114010000']);
	const validTlsRpt = (d: string) => txtResponse(`_smtp._tls.${d}`, ['v=TLSRPTv1; rua=mailto:tlsrpt@example.com']);

	it('excludes the category (checkStatus: error) when robots.txt disallows the policy fetch, and never reaches the policy URL', async () => {
		const policyFetch = vi.fn();
		mockFetch({
			mtaStsDns: validTxt('example.com'),
			tlsrptDns: validTlsRpt('example.com'),
			robots: plainResponse(200, {}, 'User-agent: *\nDisallow: /\n'),
		});
		// Wrap the mock to additionally assert the policy path is never fetched.
		const inner = globalThis.fetch;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('mta-sts.') && url.includes('.well-known')) policyFetch();
			return (inner as typeof fetch)(input as never);
		});

		const result = await run();

		expect(policyFetch).not.toHaveBeenCalled();
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.findings.some((f) => f.metadata?.inconclusive === true)).toBe(true);
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
	});

	it('does NOT exclude the category when robots.txt allows the policy fetch (control: unaffected happy path)', async () => {
		// A DISTINCT domain from the disallow case above: `withRobotsGate`'s robots.txt
		// verdict is memoized per-hostname for the module-scope `gatedFetch`'s isolate
		// lifetime (by design — see the plan's Global Constraints), so reusing
		// example.com here would read the previous test's cached disallow instead of
		// exercising this case.
		mockFetch({
			mtaStsDns: validTxt('allowed-example.com'),
			tlsrptDns: validTlsRpt('allowed-example.com'),
			robots: plainResponse(200, {}, 'User-agent: *\nAllow: /\n'),
			policyFetch: plainResponse(200, { 'content-type': 'text/plain' }, 'version: STSv1\nmode: enforce\nmx: mail.allowed-example.com\nmax_age: 604800\n'),
		});

		const result = await run('allowed-example.com');

		expect(result.checkStatus).not.toBe('error');
		expect(result.findings.some((f) => f.metadata?.inconclusive === true)).toBe(false);
	});
});
