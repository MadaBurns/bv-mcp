// SPDX-License-Identifier: BUSL-1.1

/**
 * SCORING-ENGINE EQUIVALENCE GUARD (originally audit Finding 1): a transient
 * SPF DNS failure must score the SAME however it surfaces in a CheckResult.
 *
 *  - A wrapper that CATCHES the DNS error and returns a heuristic
 *    { missingControl: true } finding with NO checkStatus  → scoring ZEROES the
 *    category and counts it (present-and-zeroed).
 *  - A wrapper that lets the error PROPAGATE, so scan-domain's safeCheck stamps
 *    checkStatus='error'  → scoring EXCLUDES the category as a transient failure
 *    (renormalised denominator, shown n/a), per the "scoring excludes
 *    inconclusive" design.
 *
 * Finding 1 SHIPPED: check-spf (and check-ptr) now use buildDnsErrorResult, so
 * the REAL check-spf emits the checkStatus='error' shape and is retried. This
 * test deliberately MOCKS check-spf to emit BOTH shapes to prove the scoring
 * engine treats them as score-equivalent — a standing invariant independent of
 * which shape any wrapper happens to emit. See the in-body CAVEAT: score-equal
 * is NOT retry-equal (only checkStatus is retried), which is exactly why the
 * Finding-1 fix chose checkStatus over missingControl.
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
	// A transient DNS failure surfaced as a heuristic `missingControl` finding must never
	// arm the critical-gap ceiling, and its two surfacing shapes must keep their traced
	// per-check asymmetry (zeroed-and-counted vs excluded-and-renormalised).
	//
	// HISTORY: until scoring model 1.20.0 this test asserted the two shapes produce an
	// IDENTICAL overall score. That equality was an ARTIFACT, not an invariant: the
	// fixture domain mocks no MX, so it detects as `web_only`, and `web_only` weighted
	// spf at 0 — a zero-weight category contributes nothing whether counted or excluded.
	// In every profile with a non-zero spf weight the two shapes have ALWAYS diverged
	// (zeroed drags the weighted mean; excluded renormalises it away), so the equality
	// claim never described mail profiles at all. Model 1.20.0 gave `web_only` spf
	// weight 2 (non-sender lockdown), ending the accidental equality here too. The
	// production check is unaffected: real check-spf uses buildDnsErrorResult (the
	// `checkStatus` shape) precisely so transients are excluded AND retried.
	//
	// CAVEAT (unchanged): score posture is NOT behaviour posture. shouldRetry() keys
	// off `checkStatus === 'error'`, so only the throw/checkStatus shape is retried —
	// a `missingControl` shape is not. Do not collapse the two shapes.
	it('keeps the traced shape asymmetry, bounds the divergence to the spf weight share, and arms no ceiling', async () => {
		const viaMissingControl = await scanWithSpfFailure('missingControl');
		const viaThrow = await scanWithSpfFailure('throws');

		const spfMC = viaMissingControl.checks.find((c) => c.category === 'spf');
		const spfThrow = viaThrow.checks.find((c) => c.category === 'spf');

		// The two paths produce the asymmetric per-check shape we traced...
		expect(spfMC?.checkStatus).toBeUndefined(); // internal-catch: no transient marker
		expect(spfThrow?.checkStatus).toBe('error'); // safeCheck: transient marker → excluded
		expect(viaMissingControl.score.categoryScores.spf).toBe(0); // present-and-zeroed
		expect(viaThrow.score.categoryScores.spf).toBeUndefined(); // excluded/n-a

		// Narrow `overall: number | null` FIRST — an un-narrowed comparison is vacuous
		// against the UNGRADED case (`null >= null` and `null - null <= 6` are both true).
		const mcOverall = viaMissingControl.score.overall;
		const throwOverall = viaThrow.score.overall;
		if (mcOverall === null || throwOverall === null) {
			throw new Error('fixture scans must be graded — got a null overall');
		}

		// The heuristic finding must not arm the critical-gap ceiling on either path.
		expect(mcOverall).toBeGreaterThan(64);
		expect(throwOverall).toBeGreaterThan(64);

		// The zeroed shape may only trail the excluded shape by spf's small weight
		// share in this profile (web_only spf=2 → a few points), never by a cliff.
		expect(throwOverall).toBeGreaterThanOrEqual(mcOverall);
		expect(throwOverall - mcOverall).toBeLessThanOrEqual(6);
	});
});
