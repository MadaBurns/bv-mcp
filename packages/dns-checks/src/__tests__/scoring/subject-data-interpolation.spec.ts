// SPDX-License-Identifier: BUSL-1.1

/**
 * The scanned subject's own DATA — its domain name, its nameserver/MX hostnames, the
 * policy URLs derived from it, the raw record tokens it publishes — is interpolated into
 * finding prose at ~28 `high`/`critical` emission sites. `scoreIndicatesMissingControl`
 * matches `MISSING_CONTROL_REGEX` against that prose, so subject data could ARM (or
 * disarm) a category zeroing that the check author never asserted.
 *
 * Measured live in production 2026-08-20 (`force_refresh`, no cache): `github.com` and
 * `missingkids.org` produced BYTE-IDENTICAL `dnssec` findings (same title "DNSSEC not
 * enabled", same `high` severity, same `penaltyOverride: 40`, same
 * `confidence: deterministic`, same `controlPresent: false`/`recordPresent: false`) and
 * scored 60/passed vs 0/failed. `dnssec` is a critical category in every profile, so the
 * zeroing also tripped the 64 critical-gap ceiling: `scan_domain missingkids.org`
 * returned 64/D against a 79/B counterfactual.
 *
 * These tests pin BOTH directions:
 *   - subject data must be invisible to the missing-control gate, AND
 *   - prose that genuinely asserts a missing control must still zero.
 */

import { describe, expect, it, vi } from 'vitest';
import { checkDNSSEC } from '../../checks/check-dnssec';
import { checkSPF } from '../../checks/check-spf';
import { getNsVisibilityFinding } from '../../checks/ns-analysis';
import { classifyDmarc } from '../../scoring/classifiers/dmarc';
import { buildCheckResult, computeProfileAwareScanScore, createFinding, scoreIndicatesMissingControl } from '../../scoring';
import type { CheckCategory, CheckResult, DNSQueryFunction, RawDNSQueryFunction } from '../../types';

/** Unsigned zone: no DNSKEY, no DS, AD flag clear. Identical for every domain below. */
function unsignedZone(): { queryDNS: DNSQueryFunction; rawQueryDNS: RawDNSQueryFunction } {
	return {
		queryDNS: vi.fn(async () => []) as unknown as DNSQueryFunction,
		rawQueryDNS: vi.fn(async () => ({ AD: false })) as unknown as RawDNSQueryFunction,
	};
}

async function dnssecFor(domain: string) {
	const { queryDNS, rawQueryDNS } = unsignedZone();
	return checkDNSSEC(domain, queryDNS, { rawQueryDNS });
}

describe('subject data interpolated into finding prose', () => {
	describe('must not arm scoreIndicatesMissingControl (the live defect)', () => {
		it('scores an unsigned zone the same regardless of the domain name — "missing" in the name', async () => {
			const control = await dnssecFor('github.com');
			const subject = await dnssecFor('missingkids.org');

			// The findings are byte-identical apart from the interpolated name.
			expect(subject.findings.map((f) => f.title)).toEqual(control.findings.map((f) => f.title));
			expect(subject.findings[0]?.severity).toBe(control.findings[0]?.severity);
			expect(subject.findings[0]?.metadata?.penaltyOverride).toBe(control.findings[0]?.metadata?.penaltyOverride);

			// Equal to each other AND equal to the designed value — "both zero" must not pass.
			expect(control.score).toBe(60);
			expect(subject.score).toBe(60);
			expect(subject.score).toBe(control.score);
			expect(control.passed).toBe(true);
			expect(subject.passed).toBe(true);
			expect(scoreIndicatesMissingControl(control.findings)).toBe(false);
			expect(scoreIndicatesMissingControl(subject.findings)).toBe(false);
		});

		it('scores an unsigned zone the same when the name contains "required"', async () => {
			const control = await dnssecFor('github.com');
			const subject = await dnssecFor('requiredfields.co.nz');
			expect(control.score).toBe(60);
			expect(subject.score).toBe(60);
			expect(scoreIndicatesMissingControl(subject.findings)).toBe(false);
			expect(subject.passed).toBe(true);
		});

		it('scores an unsigned zone the same when the name contains "notfound" / a "no-…-record" shape', async () => {
			// DISCRIMINATING CONTROLS. `not\s+found` and `no\s+…\srecord` both require
			// whitespace, which a DNS label cannot contain, so these two names are near
			// misses that scored 60 even BEFORE the fix. They prove the regex — not the
			// harness — is what moves the score in the two tests above.
			for (const name of ['thenotfound.com', 'no-mx-record.com']) {
				const subject = await dnssecFor(name);
				expect(subject.score, name).toBe(60);
				expect(scoreIndicatesMissingControl(subject.findings), name).toBe(false);
			}
		});

		it('does not let the name zero a category through subdomain labels either', async () => {
			const subject = await dnssecFor('mail.missing.required.example.com');
			expect(subject.score).toBe(60);
			expect(scoreIndicatesMissingControl(subject.findings)).toBe(false);
		});
	});

	describe('must still zero when the PROSE genuinely asserts a missing control', () => {
		it('check-spf.ts:123 "No SPF record found" still zeroes spf', async () => {
			const queryDNS = vi.fn(async () => []) as unknown as DNSQueryFunction;
			const result = await checkSPF('example.com', queryDNS);
			const finding = result.findings.find((f) => f.title === 'No SPF record found');
			expect(finding).toBeDefined();
			expect(finding?.severity).toBe('critical');
			expect(finding?.metadata?.missingControl).toBeUndefined(); // zeroes by PROSE, no explicit flag
			expect(scoreIndicatesMissingControl(result.findings)).toBe(true);
			expect(result.score).toBe(0);
			expect(result.passed).toBe(false);
		});

		it('ns-analysis.ts:48 "No NS records found" still zeroes ns', () => {
			const finding = getNsVisibilityFinding('example.com', false);
			expect(finding.title).toBe('No NS records found');
			expect(scoreIndicatesMissingControl([finding])).toBe(true);
			const result = buildCheckResult('ns', [finding]);
			expect(result.score).toBe(0);
			expect(result.passed).toBe(false);
		});

		it('check-dnssec.ts:156 "DNSSEC chain of trust incomplete" still zeroes dnssec', async () => {
			const queryDNS = vi.fn(async (_d: string, type: string) =>
				type === 'DNSKEY' ? ['257 3 13 base64key...'] : [],
			) as unknown as DNSQueryFunction;
			const rawQueryDNS = vi.fn(async () => ({ AD: false })) as unknown as RawDNSQueryFunction;
			const result = await checkDNSSEC('example.com', queryDNS, { rawQueryDNS });
			const finding = result.findings.find((f) => f.title === 'DNSSEC chain of trust incomplete');
			expect(finding).toBeDefined();
			// The prose route must remain live here even though the site ALSO carries the
			// explicit flag — it is the prose, not the flag, that reaches engine.ts's
			// critical-gap ceiling (engine.ts:213-219 does not read metadata.missingControl).
			expect(scoreIndicatesMissingControl([finding!])).toBe(true);
			expect(result.score).toBe(0);
			expect(result.passed).toBe(false);
		});

		it('classifiers/dmarc.ts:67 "No DMARC record found" still zeroes dmarc', () => {
			const findings = classifyDmarc({ recordCount: 0, policy: null, domain: 'example.com' });
			expect(findings[0]?.title).toBe('No DMARC record found');
			expect(findings[0]?.metadata?.missingControl).toBeUndefined(); // zeroes by PROSE
			expect(scoreIndicatesMissingControl(findings)).toBe(true);
			const result = buildCheckResult('dmarc', findings);
			expect(result.score).toBe(0);
			expect(result.passed).toBe(false);
		});

		it('the four designed zeroers still zero when the SUBJECT NAME is missingkids.org', async () => {
			// The fix must not immunise a domain because of its name: a genuinely-absent
			// control on `missingkids.org` must be zeroed for the real reason.
			const queryDNS = vi.fn(async () => []) as unknown as DNSQueryFunction;
			const spf = await checkSPF('missingkids.org', queryDNS);
			expect(spf.score).toBe(0);
			expect(spf.passed).toBe(false);

			const ns = buildCheckResult('ns', [getNsVisibilityFinding('missingkids.org', false)]);
			expect(ns.score).toBe(0);

			const dmarc = buildCheckResult('dmarc', classifyDmarc({ recordCount: 0, policy: null, domain: 'missingkids.org' }));
			expect(dmarc.score).toBe(0);

			const chain = await checkDNSSEC(
				'missingkids.org',
				vi.fn(async (_d: string, type: string) => (type === 'DNSKEY' ? ['257 3 13 base64key...'] : [])) as unknown as DNSQueryFunction,
				{ rawQueryDNS: vi.fn(async () => ({ AD: false })) as unknown as RawDNSQueryFunction },
			);
			expect(chain.score).toBe(0);
		});

		it('a hand-written prose zeroer is still detected (positive control on the gate itself)', () => {
			const armed = createFinding('caa', 'No CAA records', 'high', 'No CAA record is published, so any CA may issue for this name.');
			expect(scoreIndicatesMissingControl([armed])).toBe(true);
			const demoted = { ...armed, severity: 'medium' as const };
			expect(scoreIndicatesMissingControl([demoted])).toBe(false);
		});
	});

	describe('echoed RECORD CONTENT must not arm the gate either', () => {
		it('multiple DMARC records still zero dmarc on a trigger-named domain (explicit flag, not prose)', () => {
			// dmarc.ts:82 carries `{ missingControl: true }`, so the CATEGORY zero is
			// name-independent and survives. What changes is engine-level: the prose gate used
			// to fire for trigger-named domains only, so the 64 critical-gap ceiling applied to
			// `missingkids.org` and not to `example.com` for the identical misconfiguration.
			// Now both behave alike — which is the point.
			for (const domain of ['example.com', 'missingkids.org']) {
				const findings = classifyDmarc({ recordCount: 2, policy: 'reject', domain });
				expect(findings[0]?.metadata?.missingControl, domain).toBe(true);
				const result = buildCheckResult('dmarc', findings);
				expect(result.score, domain).toBe(0);
				expect(result.passed, domain).toBe(false);
				expect(scoreIndicatesMissingControl(findings), domain).toBe(false);
			}
		});

		it('a domain publishing p=missing scores dmarc the same as p=bogus', () => {
			const bogus = buildCheckResult('dmarc', classifyDmarc({ recordCount: 1, policy: 'bogus', domain: 'example.com' }));
			const missing = buildCheckResult('dmarc', classifyDmarc({ recordCount: 1, policy: 'missing', domain: 'example.com' }));
			const required = buildCheckResult('dmarc', classifyDmarc({ recordCount: 1, policy: 'required', domain: 'example.com' }));

			expect(bogus.score).toBe(50);
			expect(missing.score).toBe(50);
			expect(required.score).toBe(50);
			expect(scoreIndicatesMissingControl(missing.findings)).toBe(false);
			expect(scoreIndicatesMissingControl(required.findings)).toBe(false);
		});
	});

	describe('whole-domain blast radius', () => {
		/**
		 * Reconstruct the live 2026-08-20 `scan_domain missingkids.org` roster
		 * (`scoringModelVersion 1.10.0`, `scoringConfigHash e7e35de9`), varying ONLY the
		 * scanned name. Category levels are the measured ones; severities are chosen so the
		 * finding-count mix approximates the live `{critical: 0, high: 1, medium: 4, low: 8}`.
		 * `penaltyOverride` pins each category to its measured level independently of severity.
		 */
		function roster(dnssec: CheckResult): CheckResult[] {
			const flat: Array<[CheckCategory, number, 'medium' | 'low' | null]> = [
				['spf', 100, null],
				['dkim', 100, null],
				['ns', 100, null],
				['subdomain_takeover', 100, null],
				['subdomailing', 100, null],
				['dnskey_strength', 100, null],
				['ptr', 100, null],
				['dmarc', 70, 'medium'],
				['mta_sts', 85, 'medium'],
				['caa', 85, 'medium'],
				['dane', 85, 'medium'],
				['bimi', 95, 'low'],
				['tlsrpt', 95, 'low'],
				['mx', 95, 'low'],
				['dane_https', 95, 'low'],
				['svcb_https', 95, 'low'],
			];
			const others = flat.map(([category, score, severity]) =>
				buildCheckResult(
					category,
					severity === null
						? []
						: [
								createFinding(category, 'Roster baseline', severity, 'Reconstructed category level for the counterfactual.', {
									penaltyOverride: 100 - score,
								}),
							],
				),
			);
			return [dnssec, ...others];
		}

		it('a name-driven dnssec zero must not move the overall score or grade', async () => {
			const control = computeProfileAwareScanScore(roster(await dnssecFor('github.com')), { profile: 'enterprise_mail' });
			const subject = computeProfileAwareScanScore(roster(await dnssecFor('missingkids.org')), { profile: 'enterprise_mail' });

			// Measured on this reconstruction (profile `enterprise_mail`):
			//   BEFORE fix  missingkids.org → dnssec 0,  overall 64, grade C  (the critical-gap
			//               ceiling firing — the 64 reproduces live production exactly)
			//   AFTER  fix  missingkids.org → dnssec 60, overall 88, grade A
			//   CONTROL     github.com      → dnssec 60, overall 88, grade A
			// The exact post-fix overall depends on the roster reconstruction (the 2026-08-20
			// audit's independent reconstruction gave 79/B); what is load-bearing and asserted
			// here is that the name no longer moves it AND the 64 ceiling no longer binds.
			expect(subject.score.overall).toBe(control.score.overall);
			expect(subject.score.grade).toBe(control.score.grade);
			expect(subject.score.overall).toBeGreaterThan(64);
		});
	});
});
