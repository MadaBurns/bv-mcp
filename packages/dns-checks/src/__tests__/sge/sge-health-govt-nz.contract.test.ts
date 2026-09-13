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
 */

import { describe, it, expect } from 'vitest';
import { evaluateSgeCompliance } from '../../sge';
import type { CheckResult } from '../../types';
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

describe('health.govt.nz — the whole evaluation', () => {
	it('is indeterminate on DNS evidence alone, with SMTP TLS the single unmeasured control', () => {
		const evaluation = evaluateSgeCompliance('health.govt.nz', RESULTS);
		expect(evaluation.mailTransport).toBe('present');
		expect(evaluation.counts).toEqual({ satisfied: 5, notSatisfied: 0, notMeasured: 1 });
		expect(evaluation.verdict).toBe('indeterminate');
		const unmeasured = evaluation.controls.filter((c) => c.status === 'not_measured');
		expect(unmeasured.map((c) => c.control)).toEqual(['smtp_tls']);
		expect(unmeasured[0].notMeasuredReason).toBe('no_transport_probe');
	});

	it('reaches compliant once a transport probe supplies the sixth control', () => {
		const evaluation = evaluateSgeCompliance('health.govt.nz', RESULTS, { smtpTls: 'enforced' });
		expect(evaluation.verdict).toBe('compliant');
		expect(evaluation.counts.satisfied).toBe(6);
	});
});
