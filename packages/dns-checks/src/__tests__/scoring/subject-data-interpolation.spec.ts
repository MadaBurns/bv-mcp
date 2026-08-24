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
import { buildCheckResult, computeProfileAwareScanScore, createFinding, redactSubjectData, scoreIndicatesMissingControl } from '../../scoring';
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

		it('classifiers/dmarc.ts "No DMARC record found" still zeroes dmarc', () => {
			const findings = classifyDmarc({ recordCount: 0, policy: null, domain: 'example.com' });
			expect(findings[0]?.title).toBe('No DMARC record found');
			// Since scoring model 1.13.0 the site ALSO declares the flag (like its
			// multiple-record and missing-p= siblings). The load-bearing assertion is the
			// next line: the PROSE route must stay live independently of the flag, because
			// it is the prose, not the flag, that reaches engine.ts's critical-gap ceiling.
			expect(findings[0]?.metadata?.missingControl).toBe(true);
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

	/**
	 * The redaction projection runs on ATTACKER-CONTROLLED, UNBOUNDED prose.
	 *
	 * `sanitizeDnsData` (`check-utils.ts`) explicitly "Does NOT truncate" — the 8,000-char
	 * `MAX_META_STRING` clamp applies to metadata only — and sites such as
	 * `check-svcb-https.ts:170` interpolate a raw DNS record value straight into `detail`.
	 * So a scanned domain chooses the length AND the byte content of the string these
	 * regexes walk.
	 *
	 * `TRAILING_PUNCT` (`/[^\p{L}\p{N}_]+$/u`) is unanchored on the left, so on a long
	 * non-word run that is NOT at the end it backtracks from every start position: O(N²).
	 * Measured before this guard existed, on one `redactSubjectData` call:
	 *   8KB → 37ms · 16KB → 143ms · 32KB → 560ms · 64KB → 2,215ms
	 * against 0.008ms for `MISSING_CONTROL_REGEX` alone on the same input — a ~260,000×
	 * regression, on Cloudflare Worker CPU time, reachable by any domain that can publish a
	 * DNS record. The token is far too long to be a DNS name, so the work is pure waste:
	 * the `MAX_NAME_LENGTH` guard rejects it one line later.
	 *
	 * The budgets below are deliberately ~20× above the fixed cost rather than tight, so
	 * these assert "not quadratic" rather than a specific machine's speed.
	 */
	/**
	 * A declared term shorter than a trigger word can only ever DISARM.
	 *
	 * `subjectTerms` redaction is a global, case-insensitive substring replace over the
	 * finding's own prose. No `MISSING_CONTROL_REGEX` trigger is shorter than 6 characters
	 * (`missing`, `required`, `not found`, `no …record`), so a 2-3 character term cannot be
	 * the thing being hidden — but it CAN chew a trigger word apart from the inside. A
	 * domain publishing `p=no` declares the term `no`, which would strip the `no` from a
	 * `not found` in the same finding's prose and silently switch off a genuine zeroing.
	 *
	 * Arming is not the mirror risk: redaction substitutes `-` rather than emptiness, so it
	 * cannot splice two prose halves into a new match. The exposure is one-directional,
	 * which is why the floor is raised rather than the mechanism redesigned.
	 *
	 * 4 matches the `core.length < 4` floor the host/email redactor already applies.
	 */
	describe('declared subject terms are too short to dismantle a trigger word', () => {
		it('ignores a term short enough to chew a trigger word apart', () => {
			const prose = 'Record not found for the zone.';
			// "no" would turn "not found" into "-t found" and disarm the gate.
			expect(redactSubjectData(prose, ['no'])).toBe(prose);
			expect(redactSubjectData(prose, ['not'])).toBe(prose);
		});

		it('still redacts a term long enough to be real subject data', () => {
			const projected = redactSubjectData('DMARC policy value "missingpolicy" is invalid.', ['missingpolicy']);
			expect(projected).not.toContain('missingpolicy');
		});

		it('keeps a genuine missing-control zeroing armed when a short term is declared', () => {
			const finding = createFinding('dmarc', 'No DMARC record found', 'high', 'No DMARC record found for the domain.', {
				confidence: 'deterministic',
				subjectTerms: ['no'],
			});
			expect(scoreIndicatesMissingControl([finding])).toBe(true);
		});
	});

	describe('pathological attacker-controlled prose is bounded', () => {
		/**
		 * A long non-word run that neither STARTS nor ENDS the token — the worst case.
		 *
		 * The leading `AAAA` is load-bearing, not decoration. `LEADING_PUNCT` is anchored at
		 * `^` and strips a run that starts the token, so `/'.repeat(n) + 'A'` never reaches
		 * `TRAILING_PUNCT` at all and measures as fast — a fixture shaped that way passes
		 * against the UNFIXED code and proves nothing. This mirrors the real reachable
		 * carrier: an SVCB/HTTPS presentation value such as `ech="AAAA////…////A"`.
		 */
		const pathological = (kb: number) => `AAAA${'/'.repeat(kb * 1024)}A`;

		it('leaves an over-long token untouched without paying quadratic backtracking', () => {
			const token = pathological(64);
			const detail = `HTTPS record at example.com uses alias mode (priority 0): ${token}. Ensure the target also has valid HTTPS records.`;

			const started = performance.now();
			const projected = redactSubjectData(detail);
			const elapsed = performance.now() - started;

			// Unchanged: 64KB is not a DNS name, so redaction must decline it...
			expect(projected).toContain(token);
			// ...and must decline it CHEAPLY. Pre-fix this measured ~2,215ms.
			expect(elapsed).toBeLessThan(100);
		});

		it('scales linearly, not quadratically, with attacker-chosen length', () => {
			// Timed over REPEATS, not a single call. Once linear, one pass is far below timer
			// resolution, and a ratio of two sub-millisecond samples is dominated by clock
			// granularity rather than by the algorithm: CI measured 16KB at the old 0.01ms
			// floor against a 1ms 64KB sample and reported a 100× "regression" on code that
			// is provably linear. Summing repeats lifts both samples above the noise so the
			// ratio means what it claims.
			const REPEATS = 20;
			const time = (kb: number) => {
				const input = pathological(kb);
				const started = performance.now();
				for (let i = 0; i < REPEATS; i += 1) redactSubjectData(input);
				return performance.now() - started;
			};

			time(8); // warm up, so the first timed batch does not absorb JIT cost
			// Floor at 1ms — a full millisecond IS the resolution guarantee, unlike 0.01ms.
			// Flooring can only shrink the measured ratio, so it cannot mask a regression:
			// quadratic growth puts the 16KB batch in the seconds, nowhere near the floor.
			const small = Math.max(time(16), 1);
			const large = time(64);

			// A 4× input costs ~4× when linear and ~16× when quadratic. 8 sits between the
			// two with margin on both sides; pre-fix this measured ~15.5×.
			expect(large / small).toBeLessThan(8);
		});

		it('does not redact at all for a finding the severity gate already rejects', () => {
			// `info` can never zero a category, so the gate must short-circuit BEFORE the
			// projection runs. Pre-fix the redaction was computed eagerly and `info` findings
			// paid the full cost.
			const finding = createFinding('svcb_https', 'HTTPS record in alias mode', 'info', `alias mode: ${pathological(64)}.`, {
				confidence: 'deterministic',
			});

			const started = performance.now();
			const result = scoreIndicatesMissingControl([finding]);
			const elapsed = performance.now() - started;

			expect(result).toBe(false);
			expect(elapsed).toBeLessThan(100);
		});
	});
});
