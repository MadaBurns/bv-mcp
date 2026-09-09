// SPDX-License-Identifier: BUSL-1.1

/**
 * Class-A regression guard: "transient failure scored as a deficiency".
 *
 * Six checks used to catch a THROWN DNS query / fetch (a momentary resolver
 * timeout / SERVFAIL / network flake) and return a SCORED finding via
 * buildCheckResult(...) WITHOUT setting `checkStatus`. The scoring engine only
 * EXCLUDES a category when `checkStatus` is 'timeout'/'error' — so a healthy
 * domain hit by a blip was penalized. The correct posture is to mark the
 * category INCONCLUSIVE (info finding + checkStatus) so the engine renormalizes
 * over the remaining categories instead of zeroing/penalizing this one.
 *
 * subdomailing is deliberately covered too, to DOCUMENT that it does NOT exhibit
 * the FP: extractSpfIncludeChain swallows a thrown queryDNS internally, so the
 * check degrades to a non-penalizing info ("No SPF record") path, never the
 * scored catch.
 */

import { describe, it, expect } from 'vitest';
import { checkNS } from '../../checks/check-ns';
import { checkMX } from '../../checks/check-mx';
import { checkCAA } from '../../checks/check-caa';
import { checkDNSSEC } from '../../checks/check-dnssec';
import { checkSubdomailing } from '../../checks/check-subdomailing';
import { checkSSL } from '../../checks/check-ssl';
import type { DNSQueryFunction, FetchFunction, RawDNSQueryFunction, Finding } from '../../types';

/** A DNS resolver that always throws — models a transient SERVFAIL/timeout/network flake. */
const throwingDNS: DNSQueryFunction = async () => {
	throw new Error('transient resolver failure');
};

/** A raw DoH resolver that always throws (used by checkDNSSEC's AD-flag probe). */
const throwingRawDNS: RawDNSQueryFunction = async () => {
	throw new Error('transient resolver failure');
};

/** True when a finding would actually penalize the score (medium and above). */
function hasScoredDeficiency(findings: Finding[]): boolean {
	return findings.some((f) => f.severity === 'medium' || f.severity === 'high' || f.severity === 'critical');
}

describe('transient DNS failure → category is INCONCLUSIVE, not a scored deficiency', () => {
	it('checkNS: a thrown NS query is excluded (checkStatus error), not a critical finding', async () => {
		const result = await checkNS('example.com', throwingDNS);
		expect(result.checkStatus).toBe('error');
		expect(hasScoredDeficiency(result.findings)).toBe(false);
	});

	it('checkMX: a thrown MX query is excluded (checkStatus error), not a medium finding', async () => {
		const result = await checkMX('example.com', throwingDNS);
		expect(result.checkStatus).toBe('error');
		expect(hasScoredDeficiency(result.findings)).toBe(false);
	});

	it('checkCAA: a thrown CAA query is excluded (checkStatus error), not a medium finding', async () => {
		const result = await checkCAA('example.com', throwingDNS);
		expect(result.checkStatus).toBe('error');
		expect(hasScoredDeficiency(result.findings)).toBe(false);
	});

	// checkDNSSEC only abstains when the raw AD-flag probe throws — a thrown queryDNS alone
	// is fail-soft (DNSKEY/DS treated as absent), so it is driven through rawQueryDNS here.
	it.each([
		{ name: 'checkNS', run: () => checkNS('example.com', throwingDNS) },
		{ name: 'checkMX', run: () => checkMX('example.com', throwingDNS) },
		{ name: 'checkCAA', run: () => checkCAA('example.com', throwingDNS) },
		{ name: 'checkDNSSEC', run: () => checkDNSSEC('example.com', throwingDNS, { rawQueryDNS: throwingRawDNS }) },
	])('$name: DNS abstentions are retryable and cannot be cached or read as a pass', async ({ run }) => {
		const result = await run();
		expect(result).toMatchObject({ checkStatus: 'error', score: 0, passed: false, partial: true });
		expect(result.controlPresent).not.toBe(true);
	});

	const unknownZone = {
		scannedLabel: 'sub.example.com',
		registrableDomain: 'example.com',
		zoneApex: 'example.com',
		isApex: false,
		delegationStatus: 'unknown' as const,
		apexNsRecords: [],
	};

	it('unknown CAA zone delegation has the same non-answer contract', async () => {
		const result = await checkCAA('sub.example.com', throwingDNS, { zone: unknownZone });
		expect(result).toMatchObject({ checkStatus: 'error', score: 0, passed: false, partial: true });
	});

	it('unknown DNSSEC zone delegation has the same non-answer contract (#900)', async () => {
		// Before #900 this spread checkStatus over an info-only buildCheckResult: score 100, no
		// `partial`, never retried by scan_domain's transient-zero pass, and cached for 5 minutes.
		const result = await checkDNSSEC('sub.example.com', throwingDNS, { rawQueryDNS: throwingRawDNS, zone: unknownZone });
		expect(result).toMatchObject({ checkStatus: 'error', score: 0, passed: false, partial: true });
		expect(result.controlPresent).not.toBe(true);
	});

	it('checkDNSSEC: a thrown AD-flag query is excluded (checkStatus error), not a medium/high finding', async () => {
		const result = await checkDNSSEC('example.com', throwingDNS, { rawQueryDNS: throwingRawDNS });
		expect(result.checkStatus).toBe('error');
		expect(hasScoredDeficiency(result.findings)).toBe(false);
	});

	it('checkSubdomailing: does NOT exhibit the FP — a thrown queryDNS is swallowed internally and degrades to a non-penalizing info path', async () => {
		const result = await checkSubdomailing('example.com', throwingDNS);
		// The throw is caught inside extractSpfIncludeChain (resolve), so the scored
		// "SubdoMailing check failed" catch is unreachable; the check reports info-only.
		expect(result.checkStatus).toBeUndefined();
		expect(hasScoredDeficiency(result.findings)).toBe(false);
	});
});

describe('checkSSL: transient / unassessable HTTPS → INCONCLUSIVE, not a scored deficiency', () => {
	it('(i) a fetch timeout is excluded with checkStatus timeout', async () => {
		const fetchFn: FetchFunction = async () => {
			throw new Error('fetch timeout');
		};
		const result = await checkSSL('example.com', fetchFn);
		expect(result.checkStatus).toBe('timeout');
		// #900 class: a thrown fetch is transient — retryable (score 0) and never cached (partial).
		expect(result).toMatchObject({ score: 0, passed: false, partial: true });
	});

	it('(ii) a connection refusal is excluded with checkStatus error', async () => {
		const fetchFn: FetchFunction = async () => {
			throw new Error('ECONNREFUSED');
		};
		const result = await checkSSL('example.com', fetchFn);
		expect(result.checkStatus).toBe('error');
		expect(result).toMatchObject({ score: 0, passed: false, partial: true });
	});

	it('(iii) an origin-unreachable 530 is not assessable — checkStatus error and no scored HSTS finding', async () => {
		const fetchFn: FetchFunction = async () => new Response(null, { status: 530 });
		const result = await checkSSL('example.com', fetchFn);
		expect(result.checkStatus).toBe('error');
		// The old code emitted a medium "No HSTS header" against an unreachable origin.
		expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
		expect(hasScoredDeficiency(result.findings)).toBe(false);
		// The not-assessed scalars apply, but an origin that ANSWERED 0/5xx is origin-persistent
		// (same split as check-http-security's 5xx branch), so it caches: no `partial`.
		expect(result).toMatchObject({ score: 0, passed: false });
		expect(result.partial).toBeUndefined();
	});

	it('(iv) a no-content 204 is transient — not assessed, and kept out of the cache', async () => {
		const fetchFn: FetchFunction = async () => new Response(null, { status: 204 });
		const result = await checkSSL('example.com', fetchFn);
		expect(result).toMatchObject({ checkStatus: 'error', score: 0, passed: false, partial: true });
	});
});
