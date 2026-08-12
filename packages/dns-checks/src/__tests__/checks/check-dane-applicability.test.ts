// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #639 — `check_dane` collapsed the three states this codebase treats separately.
 *
 * - NOT APPLICABLE — the MX lookup SUCCEEDED and found no usable MX. Info, score 100.
 * - INCONCLUSIVE   — the MX lookup could not be made (threw, or SERVFAIL/REFUSED).
 *                    checkDANE THROWS; the caller renders `checkStatus: 'error'`.
 * - MISSING        — mail-accepting domain publishing no TLSA. Medium, score 85.
 *
 * Two conflations are pinned here:
 *
 * 1. A DoH SERVFAIL/REFUSED arrives as HTTP 200 with an EMPTY answer set, so nothing
 *    throws and the `DNSQueryFunction` (`string[]`) projection makes it identical to a
 *    genuine NODATA. The check read that as "no inbound mail → not applicable" and
 *    awarded a perfect 100 — fabricating a measurement it never made.
 * 2. A THROWN MX query was swallowed into a `low` finding scoring 95 (and `passed`), so
 *    a DANE measurement failure could never be excluded from scoring as transient.
 *
 * The scoring block at the end is the blast-radius proof the fix was accepted on: a
 * cleanly-resolving domain's score must be BYTE-IDENTICAL, and only the failure paths
 * may move.
 */

import { describe, it, expect } from 'vitest';
import { checkDANE } from '../../checks/check-dane';
import { computeScanScore } from '../../scoring';
import type { CheckResult, DNSQueryFunction, RawDNSQueryFunction } from '../../types';

/** DoH rcodes. */
const NOERROR = 0;
const SERVFAIL = 2;
const NXDOMAIN = 3;
const REFUSED = 5;

/**
 * A resolver whose MX answer is empty. `TLSA` likewise. Mirrors what
 * `queryDnsRecords` hands the check for NODATA *and* for SERVFAIL — the whole point
 * being that the two are indistinguishable at this seam.
 */
const emptyDNS: DNSQueryFunction = async () => [];

/** Records the raw probes the check issues, so the extra-subrequest cost can be pinned. */
function recordingRaw(response: Record<string, unknown>): { raw: RawDNSQueryFunction; calls: Array<{ name: string; type: string }> } {
	const calls: Array<{ name: string; type: string }> = [];
	const raw: RawDNSQueryFunction = async (name, recordType) => {
		calls.push({ name, type: recordType });
		return response;
	};
	return { raw, calls };
}

describe('checkDANE — NOT APPLICABLE (measured: the domain accepts no mail)', () => {
	it('reports not-applicable at score 100 when the MX lookup succeeds with no records', async () => {
		const { raw } = recordingRaw({ Status: NOERROR });
		const result = await checkDANE('example.com', emptyDNS, { rawQueryDNS: raw });
		expect(result.score).toBe(100);
		expect(result.findings.map((f) => f.title)).toEqual(['SMTP DANE not applicable (no inbound mail)']);
		expect(result.findings[0].severity).toBe('info');
	});

	it('treats an RFC 7505 null MX the same way', async () => {
		const nullMx: DNSQueryFunction = async (_name, type) => (type === 'MX' ? ['0 .'] : []);
		const { raw } = recordingRaw({ Status: NOERROR });
		const result = await checkDANE('example.com', nullMx, { rawQueryDNS: raw });
		expect(result.score).toBe(100);
		expect(result.findings[0].title).toBe('SMTP DANE not applicable (no inbound mail)');
	});

	it('treats NXDOMAIN as a measurement — a name that does not exist accepts no mail', async () => {
		const { raw } = recordingRaw({ Status: NXDOMAIN });
		const result = await checkDANE('nope.example.com', emptyDNS, { rawQueryDNS: raw });
		expect(result.score).toBe(100);
		expect(result.findings[0].title).toBe('SMTP DANE not applicable (no inbound mail)');
	});

	it('degrades to the prior behaviour when the caller supplies no raw rcode channel', async () => {
		// Nothing to corroborate against — abstaining here would punish every library
		// consumer that only passes a DNSQueryFunction. The Worker always passes one.
		const result = await checkDANE('example.com', emptyDNS);
		expect(result.score).toBe(100);
		expect(result.findings[0].title).toBe('SMTP DANE not applicable (no inbound mail)');
	});
});

describe('checkDANE — INCONCLUSIVE (the measurement could not be made)', () => {
	it('THROWS rather than claiming not-applicable when the resolver returns SERVFAIL', async () => {
		const { raw } = recordingRaw({ Status: SERVFAIL });
		await expect(checkDANE('broken.example', emptyDNS, { rawQueryDNS: raw })).rejects.toThrow(/SERVFAIL/);
	});

	it('THROWS on REFUSED', async () => {
		const { raw } = recordingRaw({ Status: REFUSED });
		await expect(checkDANE('refused.example', emptyDNS, { rawQueryDNS: raw })).rejects.toThrow(/REFUSED/);
	});

	it('THROWS when the corroborating probe itself fails', async () => {
		const throwingRaw: RawDNSQueryFunction = async () => {
			throw new Error('transient resolver failure');
		};
		await expect(checkDANE('example.com', emptyDNS, { rawQueryDNS: throwingRaw })).rejects.toThrow(/could not be determined/);
	});

	it('THROWS when the MX query itself throws, instead of scoring 95 (defect 2)', async () => {
		const throwingDNS: DNSQueryFunction = async () => {
			throw new Error('DNS query failed: transient resolver failure');
		};
		const { raw } = recordingRaw({ Status: NOERROR });
		await expect(checkDANE('example.com', throwingDNS, { rawQueryDNS: raw })).rejects.toThrow(/DNS query failed/);
	});

	it('surfaces a message the error-sanitiser allowlist preserves (prefix "DNS query")', async () => {
		const { raw } = recordingRaw({ Status: SERVFAIL });
		await expect(checkDANE('broken.example', emptyDNS, { rawQueryDNS: raw })).rejects.toThrow(/^DNS query /);
	});
});

describe('checkDANE — MISSING (measured, control absent) and the clean path', () => {
	/** Mail-accepting domain publishing no TLSA. */
	const mailDNS: DNSQueryFunction = async (_name, type) => (type === 'MX' ? ['10 mail.example.com.'] : []);

	it('still grades a mail-accepting domain with no TLSA as a medium gap at 85', async () => {
		const { raw } = recordingRaw({ AD: false, Status: NOERROR });
		const result = await checkDANE('example.com', mailDNS, { rawQueryDNS: raw });
		expect(result.score).toBe(85);
		expect(result.findings.map((f) => f.title)).toEqual(['No DANE TLSA for MX servers']);
	});

	it('issues NO corroborating MX probe when real MX hosts exist (no extra subrequest on the happy path)', async () => {
		const { raw, calls } = recordingRaw({ AD: false, Status: NOERROR });
		await checkDANE('example.com', mailDNS, { rawQueryDNS: raw });
		// Only the per-host RFC 7672 AD-flag probe, never a second MX lookup.
		expect(calls).toEqual([{ name: 'mail.example.com', type: 'A' }]);
	});

	it('issues exactly ONE corroborating MX probe on the no-MX branch', async () => {
		const { raw, calls } = recordingRaw({ Status: NOERROR });
		await checkDANE('example.com', emptyDNS, { rawQueryDNS: raw });
		expect(calls).toEqual([{ name: 'example.com', type: 'MX' }]);
	});
});

describe('#639 blast radius — scoring moves ONLY on the failure paths', () => {
	const mk = (category: string, score: number, extra: Record<string, unknown> = {}) =>
		({ category, score, passed: score >= 50, findings: [], checkStatus: 'completed', ...extra }) as unknown as CheckResult;

	/** A representative non-mail roster, matching what scan_domain submits. */
	function roster(dane: CheckResult | null): CheckResult[] {
		const base = [
			mk('spf', 100),
			mk('dmarc', 100),
			mk('dkim', 100),
			mk('dnssec', 60),
			mk('ssl', 90),
			mk('mta_sts', 85),
			mk('ns', 100),
			mk('caa', 80),
			mk('bimi', 0, { missingControl: true }),
			mk('tlsrpt', 85),
			mk('subdomain_takeover', 100),
			mk('http_security', 70),
			mk('mx', 0, { missingControl: true, controlPresent: false }),
			mk('dane_https', 90),
			mk('svcb_https', 90),
			mk('subdomailing', 100),
			mk('dnskey_strength', 0),
			mk('ptr', 100),
		];
		return dane ? [...base, dane] : base;
	}

	const ctx = { profile: 'non_mail' as const, signals: [], weights: {}, detectedProvider: null };

	it('leaves a cleanly-resolving non-mail domain BYTE-IDENTICAL (the not-applicable path still scores 100)', () => {
		// This is the assertion the fix was accepted on: nothing about a domain whose DNS
		// answered may move. DANE still earns its hardening point here — removing that is
		// the separate, operator-gated weighting decision.
		const before = computeScanScore(roster(mk('dane', 100)), ctx);
		expect(before.overall).toBe(96);
		expect(before.categoryScores.dane).toBe(100);
	});

	it('excludes an INCONCLUSIVE dane from the hardening denominator rather than scoring it', () => {
		// The buildDnsErrorResult shape the wrapper now returns for a SERVFAIL / thrown
		// lookup. The engine files `checkStatus: 'error'` as a transient failure, which
		// drops the category from BOTH numerator and denominator (renormalised), and the
		// category is reported n/a rather than zeroed.
		const errored = mk('dane', 0, { passed: false, checkStatus: 'error', partial: true });
		const after = computeScanScore(roster(errored), ctx);
		const before = computeScanScore(roster(mk('dane', 100)), ctx);
		expect(after.overall).toBeLessThan(before.overall);
		expect(before.overall - (after.overall ?? 0)).toBeLessThanOrEqual(1);
		expect(after.categoryScores.dane).toBeUndefined();
	});

	it('scores the same whether an inconclusive dane is submitted or absent (no phantom 100)', () => {
		const errored = mk('dane', 0, { passed: false, checkStatus: 'error', partial: true });
		expect(computeScanScore(roster(errored), ctx).overall).toBe(computeScanScore(roster(null), ctx).overall);
	});
});
