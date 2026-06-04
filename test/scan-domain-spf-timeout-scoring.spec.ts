// SPDX-License-Identifier: BUSL-1.1

/**
 * PROOF TEST (audit Finding 1): a transient SPF DNS failure scores DIFFERENTLY
 * depending on HOW the failure surfaces, which it should not.
 *
 *  - check-spf's wrapper CATCHES the DNS error internally and returns a finding
 *    with { missingControl: true } and NO checkStatus  → scoring ZEROES spf and
 *    counts it (missingControls[spf]=true, can trip the critical-gap ceiling).
 *  - The dmarc-style path RETHROWS, so scan-domain's safeCheck catches it and
 *    stamps checkStatus='error'             → scoring EXCLUDES spf as a transient
 *    failure (renormalised denominator, shown n/a), per the documented
 *    "scoring excludes inconclusive" design.
 *
 * Both represent the identical real-world condition ("SPF could not be
 * measured"), so the overall score MUST be the same. This test asserts the
 * current divergence; once Finding 1 is fixed (transient catch → checkStatus,
 * not missingControl) the two runs converge and the `toBeLessThan` flips to
 * `toBe`.
 */
import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { setupFetchMock, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse, createDohResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { buildCheckResult, createFinding } from '../src/lib/scoring';

const { restore } = setupFetchMock();

beforeEach(() => IN_MEMORY_CACHE.clear());
afterEach(() => {
	restore();
	vi.doUnmock('../src/tools/check-spf');
	vi.resetModules();
});

/** Healthy defaults for every check except the one under test. */
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
		if (url.includes('mta-sts.') && url.includes('.well-known')) return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		if (url.startsWith('https://')) return Promise.resolve(httpResponse('OK'));
		return Promise.resolve(httpResponse('OK'));
	});
}

/** Run a scan where check-spf is mocked to fail in the given way. */
async function scanWithSpfFailure(mode: 'missingControl' | 'throws') {
	vi.resetModules();
	vi.doMock('../src/tools/check-spf', () => ({
		checkSpf: vi.fn().mockImplementation(async () => {
			if (mode === 'throws') throw new Error('SPF check timed out');
			// Mimic check-spf's real internal-catch output.
			return buildCheckResult('spf', [
				createFinding('spf', 'SPF check timed out', 'high', 'DNS lookup timed out before the SPF record could be resolved', {
					errorKind: 'timeout',
					confidence: 'heuristic',
					missingControl: true,
				}),
			]);
		}),
	}));
	mockAllChecks();
	IN_MEMORY_CACHE.clear();
	const { scanDomain } = await import('../src/tools/scan-domain');
	return scanDomain('example.com');
}

describe('Finding 1 — a transient check failure scores the same however it surfaces', () => {
	// SCORING-EQUIVALENCE GUARD (one axis only — see caveat below).
	//
	// A transient DNS failure surfaced as a heuristic `missingControl` finding must not
	// score worse than the same failure surfaced as a `checkStatus`/throw transient.
	// Verified empirically: both land on the identical overall score because the
	// `confidence: 'heuristic'` finding never enters the engine's `missingControls` set
	// (no critical-gap ceiling), so its zeroed category contribution nets out to the
	// same headline number as transient exclusion.
	//
	// CAVEAT: score-equivalent is NOT behaviour-equivalent. The two shapes differ in
	// scan_domain's transient-zero RETRY: shouldRetry() keys off `checkStatus === 'error'`,
	// so only the throw/checkStatus shape is retried — a `missingControl` shape is not.
	// This is why buildDnsErrorResult (the Finding-1 fix) uses `checkStatus`, NOT
	// `missingControl`. The two corpora are not interchangeable; do not collapse them.
	it('overall score is identical whether spf fails via internal-catch or via throw', async () => {
		const viaMissingControl = await scanWithSpfFailure('missingControl');
		const viaThrow = await scanWithSpfFailure('throws');

		const spfMC = viaMissingControl.checks.find((c) => c.category === 'spf');
		const spfThrow = viaThrow.checks.find((c) => c.category === 'spf');

		// The two paths produce the asymmetric per-check shape we traced...
		expect(spfMC?.checkStatus).toBeUndefined(); // internal-catch: no transient marker
		expect(spfThrow?.checkStatus).toBe('error'); // safeCheck: transient marker → excluded
		expect(viaMissingControl.score.categoryScores.spf).toBe(0); // present-and-zeroed
		expect(viaThrow.score.categoryScores.spf).toBeUndefined(); // excluded/n-a

		// ...yet the headline score is the SAME. No regression from the wrapper catch.
		expect(viaMissingControl.score.overall).toBe(viaThrow.score.overall);
	});
});
