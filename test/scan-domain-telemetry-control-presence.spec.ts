// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-71 (a): the ProfileAccumulator telemetry `scanDomain` POSTs to `/ingest` used to
 * carry the raw `CheckResult.passed` per category. `passed` records "did not
 * penalize", not "control exists" — an absent DNSSEC/CAA/MTA-STS record scores 60/85/85
 * under `penaltyOverride` and therefore `passed: true`, so those three commonest real-
 * world gaps contributed EXACTLY ZERO to the accumulator's `topFailingCategories`
 * cohort statistics (profile-accumulator.ts's `failureValue = passed ? 0 : 1`).
 *
 * The fix routes the telemetry's `passed` field through `isSatisfiedControl` (the
 * shared structured signal in `lib/control-presence.ts`) instead of the raw scoring
 * field, so an unrebutted absence correctly counts as a failure for this reporting
 * surface — without touching the published score itself (still always
 * `canonicalScore`, asserted below).
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, txtResponse, nsResponse, caaResponse, dnssecResponse, httpResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	IN_MEMORY_CACHE.clear();
});

/** A ProfileAccumulator stub: records /ingest bodies, misses on /weights. */
function accumulatorStub(ingestBodies: string[]) {
	return {
		idFromName: (name: string) => name,
		get: () => ({
			fetch: async (request: Request) => {
				if (request.url.includes('/ingest')) {
					ingestBodies.push(await request.text());
					return new Response('{}', { status: 200 });
				}
				return new Response('{}', { status: 500 });
			},
		}),
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
	} as any;
}

/**
 * Realistic multi-dispatch fetch mock (same shape used across scan-domain.spec.ts /
 * scan-domain-safe-check.spec.ts) EXCEPT it deliberately serves no DNSKEY/DS material,
 * so `dnssec` completes as a genuinely, unrebutted-absent (but unpenalized: score 60)
 * category while every other category is fully present — an evidence-sufficient scan,
 * unlike an all-empty-DNS fixture (which drives `score.overall` to `null` and skips
 * the telemetry POST entirely).
 */
function mockAllChecksDnssecAbsent() {
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
			if (url.includes('type=NS') || url.includes('type=2')) {
				return Promise.resolve(nsResponse('example.com', ['ns1.example.com.', 'ns2.example.com.']));
			}
			if (url.includes('type=CAA') || url.includes('type=257')) {
				return Promise.resolve(caaResponse('example.com', ['0 issue "letsencrypt.org"']));
			}
			// DNSSEC: A record present, but this fixture never answers DNSKEY (type=48) /
			// DS (type=43) with material — those fall through to the empty default below,
			// so the domain measures as genuinely unsigned.
			if (url.includes('type=A') || url.includes('type=1')) {
				return Promise.resolve(dnssecResponse('example.com', true));
			}
			return Promise.resolve(createDohResponse([], []));
		}

		if (url.includes('mta-sts.') && url.includes('.well-known')) {
			return Promise.resolve(httpResponse('version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400'));
		}
		if (url.startsWith('https://')) {
			return Promise.resolve(httpResponse('OK'));
		}
		return Promise.resolve(httpResponse('OK'));
	});
}

describe('scanDomain telemetry reports control presence, not raw `passed` (SQ-71)', () => {
	it('reports an unpenalized absent DNSSEC as a failure in the accumulator telemetry', async () => {
		mockAllChecksDnssecAbsent();

		const ingestBodies: string[] = [];
		const pending: Promise<unknown>[] = [];
		const { scanDomain } = await import('../src/tools/scan-domain');
		const result = await scanDomain('example.com', undefined, {
			forceRefresh: true,
			profileAccumulator: accumulatorStub(ingestBodies),
			waitUntil: (p: Promise<unknown>) => pending.push(p),
		});
		await Promise.allSettled(pending);

		const dnssecCheck = result.checks.find((c) => c.category === 'dnssec');
		expect(dnssecCheck).toBeDefined();
		// Control fact: an unsigned zone scores 60 via `penaltyOverride` and is NOT
		// penalized -- the raw scoring field stays `true` on genuine absence. If this
		// ever flips, the fixture no longer exercises the defect and the assertion
		// below is vacuous.
		expect(dnssecCheck!.passed).toBe(true);
		expect(dnssecCheck!.score).toBe(60);
		expect(result.score.overall).not.toBeNull();

		expect(ingestBodies.length).toBeGreaterThan(0);
		const telemetry = JSON.parse(ingestBodies[0]);
		const dnssecTelemetry = telemetry.categoryFindings.find((cf: { category: string }) => cf.category === 'dnssec');
		expect(dnssecTelemetry).toBeDefined();
		// The fix: telemetry `passed` is the structured control-presence verdict, so an
		// unrebutted absence reports `false` here even though the raw check `passed`
		// above is `true` -- otherwise this category is invisible to
		// `topFailingCategories` cohort statistics.
		expect(dnssecTelemetry.passed).toBe(false);

		// The published score must be untouched by this telemetry-only fix -- still the
		// canonical (non-adaptive) score.
		expect(telemetry.overallScore).toBe(result.score.overall);
	});
});
