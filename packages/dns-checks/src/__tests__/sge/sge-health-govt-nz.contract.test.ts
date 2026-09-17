// SPDX-License-Identifier: BUSL-1.1

/**
 * REGRESSION CASE — health.govt.nz.
 *
 * The fixture is not hand-written. It is the verbatim JSON serialisation of the
 * six `CheckResult`s this package's own check functions produced when run
 * against LIVE DNS/HTTPS on 2026-09-13, at `@blackveil/dns-checks` 1.42.0
 * (base 7dce66041). Reproduce it with a DoH-backed `DNSQueryFunction` and
 * `checkDMARC` / `checkSPF` / `checkDKIM` / `checkMTASTS` / `checkTLSRPT` /
 * `checkMX`; the underlying records at that moment were:
 *
 *   _dmarc.health.govt.nz  TXT  "v=DMARC1; p=reject; sp=none; pct=100; rua=…"
 *   health.govt.nz         TXT  "v=spf1 mx ip4:… include:… -all"
 *   selector1._domainkey   CNAME → selector1-health-govt-nz._domainkey.mohgovtnz.onmicrosoft.com (valid v=DKIM1 RSA key)
 *   _mta-sts               TXT  "v=STSv1; id=…"   policy file: mode: enforce
 *   _smtp._tls             TXT  "v=TLSRPTv1; rua=mailto:…"
 *   health.govt.nz         MX   0 health-govt-nz.mail.protection.outlook.com
 *
 * Live DNS moves. If this fixture stops matching reality that is a fixture
 * refresh, not a code failure — but the ASSERTIONS below are about the
 * evaluator's logic given these signals, and they hold regardless.
 *
 * REFRESHED 2026-09-14 (1.44.0, bv-mcp #991). The `dmarc` entry gained the
 * `metadata` block that `checkDMARC` now emits — `dmarcPolicy` / `sp` / `np` /
 * `pct` presence / inheritance. The underlying record was RE-MEASURED before
 * writing it, from BOTH 1.1.1.1 and 8.8.8.8, and came back byte-identical to
 * the 2026-09-13 string above. Nothing else in the fixture changed; no score,
 * finding, severity, `passed`, `controlPresent` or `recordPresent` moved.
 *
 * The metadata block is NOT hand-derived from the record by a human reading the
 * tags. The `coherence` suite at the bottom of this file runs the REAL
 * `checkDMARC` over that same record string and asserts the evaluator reaches
 * the same conclusion — so if this hand-copied block ever drifts from what the
 * check actually emits, that suite is measuring the check rather than the copy.
 */

import { describe, it, expect, vi } from 'vitest';
import { evaluateSgeCompliance } from '../../sge';
import type { SgeEvaluateOptions } from '../../sge';
import { checkDMARC } from '../../checks/check-dmarc';
import type { CheckResult, DNSQueryFunction } from '../../types';
import measured from './fixtures/health-govt-nz-2026-09-13.json';

const RESULTS = measured as unknown as CheckResult[];

function pick(category: string): CheckResult {
	const found = RESULTS.find((r) => r.category === category);
	if (!found) throw new Error(`fixture is missing the ${category} result`);
	return found;
}

describe('health.govt.nz — the fixture is a genuine trap for the old oracles', () => {
	// If these stop holding, the rest of this file stops being a regression test:
	// it would be asserting the right answer against a fixture that no longer
	// discriminates. That is the "fixture pin ≠ contract" failure, so pin the trap
	// itself, not just the verdict.
	it('carries a p=reject DMARC that a severity- or score-band oracle would have FAILED', () => {
		const dmarc = pick('dmarc');
		expect(dmarc.controlPresent).toBe(true);
		expect(dmarc.recordPresent).toBe(true);
		// The trap: a HIGH-severity finding (sp=none) and a score of 50 — well below any
		// "pass" band — on a domain whose p= is genuinely reject.
		expect(dmarc.findings.some((f) => f.severity === 'high')).toBe(true);
		expect(dmarc.score).toBe(50);
	});

	it('carries a dkim result whose `passed` is true — the flag the old oracle read', () => {
		expect(pick('dkim').passed).toBe(true);
	});
});

describe('health.govt.nz — the evaluator gets both formerly-wrong controls right', () => {
	const evaluation = evaluateSgeCompliance('health.govt.nz', RESULTS);
	const control = (id: string) => {
		const found = evaluation.controls.find((c) => c.control === id);
		if (!found) throw new Error(`control ${id} missing`);
		return found;
	};

	// FORMERLY A FALSE NEGATIVE. p=reject with sp=none scores 50 and raises a HIGH
	// finding, so every score-band, severity-count and `passed`-adjacent oracle reads
	// this domain as failing DMARC. It is not: the SGE control is the organisational
	// domain's own p=, and it is reject. This assertion fails for any implementation
	// that reaches for the score or the findings instead of controlPresent +
	// findingsIndicatePartialEnforcement.
	it('DMARC p=reject is SATISFIED despite a score of 50 and a HIGH finding', () => {
		expect(control('dmarc_reject').status).toBe('satisfied');
		expect(control('dmarc_reject').evidence).toContainEqual({
			signal: 'findingsIndicatePartialEnforcement()',
			value: false,
		});
	});

	// DKIM. On the live 2026-09-13 measurement this domain DOES publish an active key
	// (selector1 → a valid v=DKIM1 RSA key), so `satisfied` is the correct answer and
	// the evaluator gives it. The false-positive risk is the OTHER shape — see below.
	it('DKIM is SATISFIED, and only because an active key was affirmatively observed', () => {
		expect(control('dkim').status).toBe('satisfied');
		expect(control('dkim').evidence).toContainEqual({
			signal: 'CheckResult.controlPresent (dkim: active key)',
			value: true,
		});
	});

	// The false-positive guard. Take the SAME fixture and flip only the DKIM
	// structural signal to "no selector answered", leaving `passed: true` and a
	// pass-band score in place — precisely the shape that made the old oracle report
	// DKIM as compliant on domains with no key at all. The evaluator must refuse to
	// call that satisfied, and must equally refuse to call it a failure.
	it('would NOT report DKIM satisfied if the key evidence disappeared but `passed` stayed true', () => {
		const withoutKey = RESULTS.map((r) => (r.category === 'dkim' ? { ...r, controlPresent: false, passed: true, score: 100 } : r));
		const rerun = evaluateSgeCompliance('health.govt.nz', withoutKey);
		const dkim = rerun.controls.find((c) => c.control === 'dkim');
		expect(dkim?.status).toBe('not_measured');
		expect(dkim?.notMeasuredReason).toBe('selector_enumeration_inconclusive');
		expect(dkim?.status).not.toBe('satisfied');
		expect(dkim?.status).not.toBe('not_satisfied');
	});
});

/**
 * The two observations this package cannot make itself, supplied so the fixture
 * can reach a decided verdict. Both are caller claims, not measurements taken
 * here — which is exactly why each has to be handed in.
 */
const BOTH_OBSERVED: SgeEvaluateOptions = {
	smtpTls: 'enforced',
	subdomainCoverage: {
		enumeration: 'complete',
		source: 'test fixture',
		observations: [{ name: 'www.health.govt.nz', dmarcRecordPresent: true, spfAll: '-all', dkimNullRecordPresent: true }],
	},
};

describe('health.govt.nz — the whole evaluation', () => {
	it('is indeterminate on DNS evidence alone, with SMTP TLS and sub-domain coverage unmeasured', () => {
		const evaluation = evaluateSgeCompliance('health.govt.nz', RESULTS);
		expect(evaluation.mailTransport).toBe('present');
		expect(evaluation.counts).toEqual({ satisfied: 5, notSatisfied: 0, notMeasured: 2 });
		expect(evaluation.verdict).toBe('indeterminate');
		const unmeasured = evaluation.controls.filter((c) => c.status === 'not_measured');
		expect(unmeasured.map((c) => c.control)).toEqual(['smtp_tls', 'subdomain_coverage']);
		expect(unmeasured.map((c) => c.notMeasuredReason)).toEqual(['no_transport_probe', 'no_subdomain_enumeration']);
	});

	// bv-mcp #996. This record is `p=reject; sp=none`, but even `sp=reject` would not
	// move the sub-domain control: SGE refuses sp= as the mechanism outright. A
	// transport probe alone therefore no longer clears the domain, and the ceiling
	// stays INDETERMINATE until someone enumerates the sub-domains.
	it('does NOT reach compliant on a transport probe alone — sub-domain coverage is still unmeasured', () => {
		const evaluation = evaluateSgeCompliance('health.govt.nz', RESULTS, { smtpTls: 'enforced' });
		expect(evaluation.verdict).toBe('indeterminate');
		expect(evaluation.controls.find((c) => c.control === 'subdomain_coverage')?.status).toBe('not_measured');
	});

	it('reaches compliant once both caller-supplied observations are present', () => {
		const evaluation = evaluateSgeCompliance('health.govt.nz', RESULTS, BOTH_OBSERVED);
		expect(evaluation.verdict).toBe('compliant');
		expect(evaluation.counts.satisfied).toBe(7);
	});

	// THE POINT OF THE WHOLE #991 CHANGE, on the real domain. A COMPLIANT verdict
	// here is correct against the written SGE controls AND the subdomain tree is
	// measurably open at the APEX RECORD level. Before that change the second half
	// was invisible on this surface: all ticks, verdict COMPLIANT, and no trace of
	// the exposure that the same scan's own DMARC findings flagged at severity
	// `high`. The #996 control is a different statement — it reads an enumeration,
	// never this record — so the advisory still has to carry the apex fact.
	it('is COMPLIANT and STILL reports the subdomain exposure — the two facts coexist', () => {
		const evaluation = evaluateSgeCompliance('health.govt.nz', RESULTS, BOTH_OBSERVED);
		expect(evaluation.verdict).toBe('compliant');

		const gap = evaluation.advisories.find((a) => a.id === 'subdomain_policy_gap');
		expect(gap).toBeDefined();
		expect(gap?.severity).toBe('exposure');
		// np= is absent on this record, so the RFC 9989 §4.7 np->sp->p chain falls
		// through to sp=none: BOTH existing and non-existent subdomains are unenforced.
		expect(gap?.evidence).toContainEqual({ signal: 'npMitigatesNonExistentSubdomains', value: false });
		expect(gap?.evidence).toContainEqual({ signal: 'dmarcNonExistentSubdomainPolicy()', value: 'not-specified' });

		// …and the control the ruling protects did not move.
		expect(evaluation.controls.find((c) => c.control === 'dmarc_reject')?.status).toBe('satisfied');
		expect(evaluation.counts).toEqual({ satisfied: 7, notSatisfied: 0, notMeasured: 0 });
	});

	it('reports the pct= tag this record publishes as an ADVISORY, not an exposure', () => {
		const evaluation = evaluateSgeCompliance('health.govt.nz', RESULTS);
		const pct = evaluation.advisories.find((a) => a.id === 'pct_tag_present');
		expect(pct?.severity).toBe('advisory');
	});
});

/**
 * THE SCORER/EVALUATOR COHERENCE LOCK (bv-mcp #991).
 *
 * Two live surfaces rule on this exact record. The SCORER
 * (`scoring/classifiers/dmarc.ts`) raises "Subdomain policy weaker than parent
 * policy" at severity `high`. The SGE EVALUATOR reports `dmarc_reject`
 * satisfied. Before this change those read as opposite verdicts on the same
 * input, and the SGE output carried no trace of the subdomain exposure at all —
 * so a reader of the SGE surface alone would have concluded the domain was
 * clean on subdomains while our own scorer said it was not.
 *
 * The ruling keeps BOTH: the control stays satisfied (RFC 9989 §4.7 — `sp`
 * does not apply to the Organizational Domain, so it cannot weaken the apex
 * policy the control is about) and the scorer's finding stays (it is a security
 * finding, not an SGE control verdict). Coherence is restored by making the SGE
 * surface REPORT the exposure as its own advisory.
 *
 * This lock asserts the two surfaces agree in DIRECTION. The two sides have
 * INDEPENDENT PROVENANCE by construction: the scorer side is finding PROSE
 * produced by the classifier, the evaluator side is a structured advisory
 * derived from `CheckResult.metadata`, which the classifier never reads and
 * never writes. Neither can be satisfied by the other's implementation. (Prose
 * matching is forbidden in PRODUCTION code on this path; a test asserting that
 * production prose and production structure agree is exactly where it belongs.)
 */
describe('coherence: the scorer and the SGE evaluator agree in direction on sp=none', () => {
	const SUBDOMAIN_FINDING = 'Subdomain policy weaker than parent policy';

	function dmarcFromRecord(domain: string, record: string | null): Promise<CheckResult> {
		const zone: Record<string, string[]> = record === null ? {} : { [`_dmarc.${domain}`]: [record] };
		const dns: DNSQueryFunction = vi.fn(async (name: string) => zone[name] ?? []);
		return checkDMARC(domain, dns);
	}

	// The record measured live on 2026-09-14 from BOTH 1.1.1.1 and 8.8.8.8, byte for
	// byte. Positive control for that measurement: the apex `_dmarc` query returned
	// non-empty on both resolvers while `_dmarc.www.health.govt.nz` returned empty on
	// both, and `www.health.govt.nz` resolved A 104.20.42.43 / 172.66.155.110 — so the
	// www subdomain exists, is unprotected, and the empty answer is a real NODATA
	// rather than a dead probe.
	const LIVE_RECORD = 'v=DMARC1; p=reject; sp=none; pct=100; rua=mailto:496msrauhe@rua.powerdmarc.com;';

	it('both surfaces fire on the live health.govt.nz record', async () => {
		const dmarc = await dmarcFromRecord('health.govt.nz', LIVE_RECORD);
		const scorerFlags = dmarc.findings.some((f) => f.title === SUBDOMAIN_FINDING);
		const evaluation = evaluateSgeCompliance('health.govt.nz', [{ category: 'mx', passed: true, score: 100, findings: [], controlPresent: true }, dmarc]);
		const sgeFlags = evaluation.advisories.some((a) => a.id === 'subdomain_policy_gap');

		expect(scorerFlags).toBe(true);
		expect(sgeFlags).toBe(true);
		// And the control the ruling protects is untouched.
		expect(evaluation.controls.find((c) => c.control === 'dmarc_reject')?.status).toBe('satisfied');
	});

	// A lock that only ever asserts `true === true` proves nothing. These cases make
	// both sides go quiet together, and the last one is the positive control for the
	// scorer leg specifically.
	const cases: Array<{ label: string; record: string; expected: boolean }> = [
		{ label: 'p=reject; sp=none', record: 'v=DMARC1; p=reject; sp=none', expected: true },
		{ label: 'p=reject; sp=quarantine', record: 'v=DMARC1; p=reject; sp=quarantine', expected: true },
		{ label: 'p=quarantine; sp=none', record: 'v=DMARC1; p=quarantine; sp=none', expected: true },
		{ label: 'p=reject; sp=none; np=reject', record: 'v=DMARC1; p=reject; sp=none; np=reject', expected: true },
		{ label: 'p=reject; sp=reject', record: 'v=DMARC1; p=reject; sp=reject', expected: false },
		{ label: 'p=reject with no sp=', record: 'v=DMARC1; p=reject', expected: false },
	];

	for (const { label, record, expected } of cases) {
		it(`${label}: scorer finding and SGE advisory both ${expected ? 'fire' : 'stay silent'}`, async () => {
			const dmarc = await dmarcFromRecord('example.test', record);
			const evaluation = evaluateSgeCompliance('example.test', [{ category: 'mx', passed: true, score: 100, findings: [], controlPresent: true }, dmarc]);

			// `Subdomain policy weaker than DOMAIN policy` is the quarantine-apex wording;
			// both spellings are the same classifier branch family, so match the stem.
			const scorerFlags = dmarc.findings.some((f) => f.title.startsWith('Subdomain policy weaker than'));
			const sgeFlags = evaluation.advisories.some((a) => a.id === 'subdomain_policy_gap');

			expect(scorerFlags).toBe(expected);
			expect(sgeFlags).toBe(expected);
			expect(sgeFlags).toBe(scorerFlags);
		});
	}
});
