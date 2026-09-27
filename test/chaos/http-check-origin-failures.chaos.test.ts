// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos G (SQ-194) — HTTP-backed checks under origin failures: 5xx, a redirect
 * loop, and an oversized response body.
 *
 * Mock boundaries only: `globalThis.fetch` (via `setupFetchMock`/`vi.stubGlobal`
 * semantics) and DNS via `test/helpers/dns-mock.ts`. No internal module is
 * mocked — `check_http_security` and `check_mta_sts` run for real.
 *
 * Contract under test (bv-mcp-check-conventions): a probe that never reached
 * the origin must ABSTAIN (`checkStatus` 'timeout'/'error', or `inconclusive` +
 * `errorKind`) and must NEVER also carry a `missingControl` finding — "measured
 * absent" and "probe cut" must not land on the same finding.
 *
 * ## Duplicate coverage skipped (see ticket comments for the full trace)
 *
 * - H2 (MTA-STS policy fetch hangs past budget) is already covered end-to-end
 *   by `test/mta-sts-fetch-budget.spec.ts`, including the exact
 *   checkStatus/missingControl/categoryScores assertions this ticket asks for.
 *   That file also documents the FALSIFIED nuance in H2's own wording: the
 *   Worker wrapper deliberately normalizes a stalled policy fetch to
 *   `checkStatus: 'error'`, never `'timeout'` (`'timeout'` is the
 *   `safeCheck`-killed, never-retried shape). No new test added here.
 * - H5 (bv-tls-probe binding throws/5xx) is already covered at the binding
 *   level by `test/tls-probe-binding.spec.ts` (`callTlsProbe` returns `null`
 *   fail-soft on both a throw and a non-ok response). More importantly,
 *   `check_ssl`'s only call site is currently DEAD CODE:
 *   `TLS_VERSION_ENRICHMENT_ENABLED = false` (the #927 kill-switch) means
 *   `callTlsProbe` is never invoked from `check_ssl` today, exactly as
 *   `test/binding-degradation-wiring.spec.ts` already documents and tests. No
 *   new test added here.
 *
 * ## H3 was FALSIFIED, then fixed (SQ-204)
 *
 * H3 (persistent redirect loop) was originally FALSIFIED against this ticket's "the check
 * abstains" wording: `checkHTTPSecurity`'s `followRedirects` hop-cap-exhaustion branch scored
 * the last redirect response's headers as if it were the final page. SQ-204 fixed the
 * exhausted-cap branch to abstain (`checkStatus: 'error'`, `errorKind: 'redirect_chain_unresolved'`,
 * no `missingControl`) instead — see `packages/dns-checks/src/checks/check-http-security.ts`'s
 * `hopCapExceeded` / `redirectLoopFinding`. The test below now asserts the fixed (abstaining)
 * behaviour, not the original falsified claim.
 *
 * ## One hypothesis below is still FALSIFIED by the code (see in-test comments and ticket
 * comments for the full trace); per dispatch instructions H4's test asserts the MEASURED
 * behaviour instead of the ticket's claim, and no src/ change was made for it.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, txtResponse, caaResponse, dnssecResponse, createDohResponse, httpResponse } from '../helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../../src/lib/cache';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => {
	restore();
	vi.resetModules();
});

function urlOf(input: string | URL | Request): string {
	return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
}

// ---------------------------------------------------------------------------
// H1 — origin answers 503 to every request
// ---------------------------------------------------------------------------

describe('H1: origin 5xx — check_http_security abstains without claiming absence, category excluded not zeroed', () => {
	it('check_http_security: a 503 origin sets checkStatus=error and attaches no missingControl finding', async () => {
		// Mirrors the existing "500 error" case in test/check-http-security.spec.ts
		// (uniform non-ok mock for every fetch, including robots.txt — proven
		// fail-open there), but that spec never asserts checkStatus or the
		// missingControl absence, which is the actual abstention contract.
		globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 503, headers: new Headers() });

		const { checkHttpSecurity } = await import('../../src/tools/check-http-security');
		const result = await checkHttpSecurity('chaos-503.example.com');

		expect(result.category).toBe('http_security');
		// The origin WAS reached and answered — the finding is a real, non-fabricated
		// "Server error", not a "probe cut" story. checkStatus is what excludes the
		// category from scoring (see the scan-level assertion below), not the finding.
		const serverError = result.findings.find((f) => f.title === 'Server error');
		expect(serverError).toBeDefined();
		expect(serverError!.severity).toBe('medium');
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
	});

	/** Healthy DNS answers for every non-HTTP category, so a scan doesn't fail wholesale. */
	function healthyDoh(url: string, domain: string): Promise<Response> | undefined {
		if (!url.includes('cloudflare-dns.com')) return undefined;
		if (url.includes('type=TXT') || url.includes('type=16')) {
			if (url.includes('_dmarc.')) return Promise.resolve(txtResponse(`_dmarc.${domain}`, ['v=DMARC1; p=reject']));
			if (url.includes('_domainkey.')) return Promise.resolve(txtResponse(`default._domainkey.${domain}`, ['v=DKIM1; k=rsa; p=MIGf']));
			return Promise.resolve(txtResponse(domain, ['v=spf1 include:_spf.google.com -all']));
		}
		if (url.includes('type=CAA') || url.includes('type=257')) return Promise.resolve(caaResponse(domain, ['0 issue "letsencrypt.org"']));
		if (url.includes('type=A') || url.includes('type=1')) return Promise.resolve(dnssecResponse(domain, true));
		return Promise.resolve(createDohResponse([], []));
	}

	it('scan_domain: a 503 origin excludes http_security from categoryScores (absent, not zeroed) while a DNS-only category still scores', async () => {
		const domain = 'chaos-503-scan.example.com';
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = urlOf(input);
			const doh = healthyDoh(url, domain);
			if (doh) return doh;
			// "the origin answers 503 to every request" — literally every non-DNS fetch,
			// robots.txt included (proven fail-open at the check level above).
			return Promise.resolve(httpResponse('', 503));
		});

		const { scanDomain } = await import('../../src/tools/scan-domain');
		const result = await scanDomain(domain, undefined, { forceRefresh: true });

		const httpSecurity = result.checks.find((c) => c.category === 'http_security');
		expect(httpSecurity, 'http_security must still be present in checks[] for display').toBeDefined();
		expect(httpSecurity!.checkStatus).toBe('error');
		expect(httpSecurity!.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);

		// Excluded, not zeroed: an unmeasured category must not sit in the score at 0.
		expect(result.score.categoryScores).not.toHaveProperty('http_security');

		// Negative control / sanity: a DNS-only category (no HTTP fetch involved at
		// all) must still be measured and scored, proving the exclusion is targeted
		// at the category that actually failed to reach the origin, not a side effect
		// of the whole scan degrading.
		expect(result.score.categoryScores).toHaveProperty('dnssec');
		expect(result.score.categoryScores.dnssec).toBeGreaterThan(0);
	});
});

// ---------------------------------------------------------------------------
// H3 — persistent redirect loop
// ---------------------------------------------------------------------------

describe('H3: persistent redirect loop — check_http_security is bounded AND abstains (SQ-204 fix)', () => {
	it('a redirect that never terminates is bounded at the hop cap and abstains instead of scoring the last hop', async () => {
		// safeFetch itself has no hop-following logic at all (src/lib/safe-fetch.ts is
		// a thin SSRF-validating passthrough to native `fetch`). The actual hop cap now
		// lives in ONE place (SQ-204): the package's `followRedirects` `MAX_REDIRECT_HOPS`
		// in packages/dns-checks/src/checks/check-http-security.ts, exported as
		// `HTTP_SECURITY_MAX_REDIRECT_HOPS` and imported by the wrapper's own dual-fetch
		// prober (src/tools/check-http-security.ts) instead of a second, independent cap.
		// Simulate an origin that ALWAYS redirects — every hop, forever, from either
		// layer's perspective — and prove the check still returns.
		let hops = 0;
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = urlOf(input);
			if (url.endsWith('/robots.txt')) return Promise.resolve(httpResponse('User-agent: *\nDisallow:\n'));
			hops += 1;
			return Promise.resolve(httpResponse('', 301, new Headers({ location: `https://chaos-redirect-loop.example.com/hop-${hops}` })));
		});

		const { checkHttpSecurity } = await import('../../src/tools/check-http-security');
		// No fake/real-clock waiting needed: every mocked fetch resolves immediately,
		// so a still-looping implementation would resolve just as fast as a bounded
		// one — what this test actually discriminates on is hop count / shape, not
		// wall-clock. An UNBOUNDED implementation would keep incrementing `hops`
		// forever inside this one `await`, which the assertions below rule out.
		const result = await checkHttpSecurity('chaos-redirect-loop.example.com');

		expect(result.category).toBe('http_security');
		expect(hops, 'the mock must have been engaged for more than a single hop').toBeGreaterThan(1);
		// Bounded: the mock could redirect forever, but the check only ever asked for a
		// small, capped number of hops (the wrapper's dual-fetch pre-probe, hop cap now
		// shared with the package) — nowhere near "30 hops, forever".
		expect(hops).toBeLessThan(30);

		// FIXED (SQ-204): once the reconciled hop cap is exhausted while STILL redirecting,
		// packages/dns-checks/src/checks/check-http-security.ts's `hopCapExceeded` branch now
		// abstains via `redirectLoopFinding()` instead of analyzing the last redirect
		// response's headers as if it were the final page — `checkStatus: 'error'`, so
		// scoring excludes the category rather than scoring a probe that never reached a
		// final page. No `missingControl` — a cut chain must not also claim the headers are
		// absent (issue #638 law).
		expect(result.checkStatus).toBe('error');
		expect(result.findings.some((f) => f.metadata?.errorKind === 'redirect_chain_unresolved')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		expect(result.findings.some((f) => /^No /.test(f.title))).toBe(false);
		expect(result.findings.some((f) => f.title.includes('check timed out'))).toBe(false);
		expect(result.findings.some((f) => f.metadata?.inconclusive === true)).toBe(true);
	});
});

// ---------------------------------------------------------------------------
// H4 — oversized response body
// ---------------------------------------------------------------------------

/**
 * A ReadableStream that can produce far more than any real cap (here: enough
 * 1 KB chunks to reach ~5 MB) but counts every `pull()` — used to prove a
 * bounded reader actually stopped consuming near its cap rather than reading
 * the whole thing.
 */
function makeCountingOversizedStream(pullCount: { n: number }): ReadableStream<Uint8Array> {
	const chunk = new Uint8Array(1024).fill(97); // 1 KB of 'a'
	const MAX_CHUNKS = 5_000; // ~5 MB available — far past any check's byte cap
	let sent = 0;
	return new ReadableStream<Uint8Array>({
		pull(controller) {
			pullCount.n += 1;
			if (sent >= MAX_CHUNKS) {
				controller.close();
				return;
			}
			sent += 1;
			controller.enqueue(chunk);
		},
	});
}

describe('H4: oversized body — check_mta_sts is bounded, but FALSIFIED: it does not abstain', () => {
	it('an oversized MTA-STS policy body is bounded-read then scored as a real HIGH finding (not an abstention)', async () => {
		// There is no generic "safeFetch size cap" (src/lib/safe-fetch.ts has none).
		// The byte cap that actually applies to a CONTENT read is
		// packages/dns-checks/src/response-body.ts's `readResponseTextCapped`,
		// MAX_BODY_BYTES=65536 (RFC 8461's 64 KB ceiling for MTA-STS), used in
		// packages/dns-checks/src/checks/check-mta-sts.ts. Unlike the WAF-sniff
		// reader (`readBoundedText`, fail-open/truncate-silently, used only for
		// heuristic WAF fingerprinting), this one is null-on-overflow and the
		// caller turns that into a real, scored finding — not an abstention.
		const domain = 'chaos-oversized.example.com';
		const pullCount = { n: 0 };
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = urlOf(input);
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse(`_mta-sts.${domain}`, ['v=STSv1; id=20240101']));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.endsWith('/robots.txt')) return Promise.resolve(httpResponse('User-agent: *\nDisallow:\n'));
			if (url.includes(`mta-sts.${domain}`) && url.includes('.well-known')) {
				// No content-length header — forces the real streaming byte-cap path
				// rather than the Content-Length early-rejection shortcut, so the
				// pull-count assertion below actually proves the STREAMING cap-stop.
				return Promise.resolve(new Response(makeCountingOversizedStream(pullCount), { status: 200 }));
			}
			return Promise.resolve(httpResponse('OK'));
		});

		const { checkMtaSts } = await import('../../src/tools/check-mta-sts');
		const result = await checkMtaSts(domain);

		expect(result.category).toBe('mta_sts');
		const oversized = result.findings.find((f) => f.title === 'MTA-STS policy file oversized');
		expect(oversized, 'the oversized-body branch must have fired').toBeDefined();
		expect(oversized!.severity).toBe('high');

		// The reader stopped near the 64 KB cap (~65 chunks of 1 KB), nowhere near
		// the 5,000 chunks (~5 MB) the source could have produced.
		expect(pullCount.n, 'the bounded reader must have stopped consuming near the byte cap').toBeGreaterThan(0);
		expect(pullCount.n).toBeLessThan(200);

		// FALSIFIED vs. the ticket's H4 wording ("the check abstains ... bounded-read
		// error kind"): it does not. The oversized body is a real, scored HIGH
		// finding — checkStatus stays undefined (measured), and it is neither an
		// `inconclusive` nor a `missingControl` finding.
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.some((f) => f.metadata?.inconclusive === true)).toBe(false);
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
	});
});
