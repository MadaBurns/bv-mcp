// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { evaluateSgeCompliance, SGE_CONTROL_IDS } from '../../sge';
import type { SgeControlId, SgeEvaluation, SgeSubdomainCoverage, SgeSubdomainObservation } from '../../sge';
import type { CheckCategory, CheckResult, Finding } from '../../types';

/**
 * Build a CheckResult directly rather than through `buildCheckResult`, so a test
 * can assert what the evaluator does with a `passed`/`score` pair that CONTRADICTS
 * the structural signals. That combination is the whole point: the evaluator must
 * be provably independent of both.
 */
function result(category: CheckCategory, over: Partial<CheckResult> = {}): CheckResult {
	return { category, passed: true, score: 100, findings: [] as Finding[], ...over };
}

function finding(category: CheckCategory, title: string, metadata?: Record<string, unknown>): Finding {
	return { category, title, severity: 'medium', detail: 'irrelevant', ...(metadata ? { metadata } : {}) } as Finding;
}

function control(evaluation: SgeEvaluation, id: SgeControlId) {
	const found = evaluation.controls.find((c) => c.control === id);
	if (!found) throw new Error(`control ${id} missing from evaluation`);
	return found;
}

/** A mail-bearing domain, so the transport controls are not excused. */
const MX_PRESENT = result('mx', { controlPresent: true });

/** A sub-domain with all three SGE anti-spoofing records MEASURED and present. */
function covered(name: string, over: Partial<SgeSubdomainObservation> = {}): SgeSubdomainObservation {
	return { name, dmarcRecordPresent: true, spfAll: '-all', dkimNullRecordPresent: true, ...over };
}

/** A complete enumeration in which every sub-domain is covered. */
const FULL_COVERAGE: SgeSubdomainCoverage = {
	enumeration: 'complete',
	source: 'test',
	observations: [covered('www.example.test'), covered('mail.example.test')],
};

describe('evaluateSgeCompliance — shape and three-state contract', () => {
	it('always reports all seven controls, in SGE_CONTROL_IDS order, even with no input at all', () => {
		const evaluation = evaluateSgeCompliance('example.test', []);
		expect(evaluation.controls.map((c) => c.control)).toEqual([...SGE_CONTROL_IDS]);
		expect(evaluation.controls).toHaveLength(7);
	});

	it('surfaces a missing check as not_measured — never as a fail, never as a pass, never omitted', () => {
		const evaluation = evaluateSgeCompliance('example.test', []);
		for (const c of evaluation.controls) {
			expect(c.status).toBe('not_measured');
			expect(c.notMeasuredReason).toBeDefined();
		}
		expect(evaluation.counts).toEqual({ satisfied: 0, notSatisfied: 0, notMeasured: 7 });
		expect(evaluation.verdict).toBe('indeterminate');
	});

	it('attaches a reason to every not_measured control and to no other control', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('dmarc', { controlPresent: true, recordPresent: true }),
			result('spf', { metadata: { spfAll: '~all' } }),
		]);
		for (const c of evaluation.controls) {
			if (c.status === 'not_measured') expect(c.notMeasuredReason).toBeDefined();
			else expect(c.notMeasuredReason).toBeUndefined();
		}
	});

	it('treats an out-of-union checkStatus (e.g. a cache read from a skewed deploy) as not measured', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('dmarc', { controlPresent: true, recordPresent: true, checkStatus: 'pending_migration' as never }),
		]);
		expect(control(evaluation, 'dmarc_reject').status).toBe('not_measured');
		expect(control(evaluation, 'dmarc_reject').notMeasuredReason).toBe('check_not_completed');
	});
});

describe('DMARC — p=reject', () => {
	it('p=reject (enforcing, not partial) is satisfied', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('dmarc', { controlPresent: true, recordPresent: true })]);
		expect(control(evaluation, 'dmarc_reject').status).toBe('satisfied');
	});

	it('p=quarantine (structural partialEnforcement) is not satisfied', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('dmarc', {
				controlPresent: true,
				recordPresent: true,
				findings: [finding('dmarc', 'DMARC policy set to quarantine', { partialEnforcement: true })],
			}),
		]);
		expect(control(evaluation, 'dmarc_reject').status).toBe('not_satisfied');
	});

	it('p=none (published but not enforcing) is a measured negative, not an absence', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('dmarc', { controlPresent: false, recordPresent: true })]);
		expect(control(evaluation, 'dmarc_reject').status).toBe('not_satisfied');
	});

	it('no DMARC record is not satisfied', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('dmarc', { controlPresent: false, recordPresent: false }),
		]);
		expect(control(evaluation, 'dmarc_reject').status).toBe('not_satisfied');
	});

	it('a completed check that reports neither flag is not_measured, not a fail', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('dmarc')]);
		expect(control(evaluation, 'dmarc_reject').status).toBe('not_measured');
		expect(control(evaluation, 'dmarc_reject').notMeasuredReason).toBe('signal_absent');
	});

	// The two oracles this module exists to refuse. Both fixtures are deliberately
	// self-contradictory: the structural signal says one thing and passed/score say
	// the opposite. The verdict must follow the structural signal in both directions.
	it('ignores `passed: true` + score 100 when the structural signal says not enforcing', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('dmarc', { passed: true, score: 100, controlPresent: false, recordPresent: true }),
		]);
		expect(control(evaluation, 'dmarc_reject').status).toBe('not_satisfied');
	});

	it('ignores `passed: false` + score 0 when the structural signal says enforcing at reject', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('dmarc', { passed: false, score: 0, controlPresent: true, recordPresent: true }),
		]);
		expect(control(evaluation, 'dmarc_reject').status).toBe('satisfied');
	});
});

describe('SPF — -all', () => {
	it('-all is satisfied', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('spf', { metadata: { spfAll: '-all' } })]);
		expect(control(evaluation, 'spf_hardfail').status).toBe('satisfied');
	});

	it.each(['~all', '+all', '?all', 'no-all-mechanism'])('%s is not satisfied', (qualifier) => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('spf', { metadata: { spfAll: qualifier } })]);
		expect(control(evaluation, 'spf_hardfail').status).toBe('not_satisfied');
	});

	it('no SPF record (canonical missing-control predicate) is a measured negative', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('spf', { passed: false, score: 0, findings: [finding('spf', 'No SPF record found', { missingControl: true })] }),
		]);
		expect(control(evaluation, 'spf_hardfail').status).toBe('not_satisfied');
	});

	it('a completed spf check with neither a qualifier nor a missing-control finding is not_measured', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('spf')]);
		expect(control(evaluation, 'spf_hardfail').status).toBe('not_measured');
		expect(control(evaluation, 'spf_hardfail').notMeasuredReason).toBe('signal_absent');
	});

	it('a junk metadata value cannot pass through as a trusted verdict', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('spf', { metadata: { spfAll: 'ALL-GOOD' } })]);
		expect(control(evaluation, 'spf_hardfail').status).toBe('not_measured');
	});

	// Regression for bv-mcp #988: the check_spf FINDING path still matches `all` as an
	// unanchored substring, so an include: hostname containing "-all" can make a soft-fail
	// record read as a hard fail IN THE FINDINGS. The evaluator reads the reader, so a
	// prose-driven implementation of this control would fail this test and this one alone.
	it('reads the structured qualifier, not the findings, when a hostname decoys as -all', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('spf', {
				metadata: { spfAll: '~all' },
				findings: [finding('spf', 'SPF record: v=spf1 include:send-all.example.net ~all')],
			}),
		]);
		expect(control(evaluation, 'spf_hardfail').status).toBe('not_satisfied');
	});
});

describe('DKIM', () => {
	it('an observed active key is satisfied', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('dkim', { controlPresent: true })]);
		expect(control(evaluation, 'dkim').status).toBe('satisfied');
	});

	// A selector-list miss is NOT measured absence: DKIM has no discovery mechanism, so a
	// domain signing with an uncommon selector is indistinguishable from one that does not
	// sign. Reporting `not_satisfied` here would be a false adverse claim; reporting
	// `satisfied` is the bv-mcp #705 residual-gap false positive. It must be neither.
	it('a selector-enumeration miss is not_measured — neither satisfied nor not_satisfied', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('dkim', { passed: true, score: 50, controlPresent: false }),
		]);
		const dkim = control(evaluation, 'dkim');
		expect(dkim.status).toBe('not_measured');
		expect(dkim.notMeasuredReason).toBe('selector_enumeration_inconclusive');
	});

	it('never reads `passed: true` on a dkim result as evidence the control exists', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('dkim', { passed: true, score: 100 })]);
		expect(control(evaluation, 'dkim').status).not.toBe('satisfied');
	});
});

describe('SMTP TLS', () => {
	it('is not_measured by default — this package opens no SMTP connection', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT]);
		expect(control(evaluation, 'smtp_tls').status).toBe('not_measured');
		expect(control(evaluation, 'smtp_tls').notMeasuredReason).toBe('no_transport_probe');
	});

	it('is never inferred from an enforcing MTA-STS policy', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('mta_sts', { recordPresent: true, metadata: { mtaStsMode: 'enforce' } }),
		]);
		expect(control(evaluation, 'mta_sts_enforce').status).toBe('satisfied');
		expect(control(evaluation, 'smtp_tls').status).toBe('not_measured');
	});

	it('accepts an externally supplied transport observation in both directions', () => {
		expect(control(evaluateSgeCompliance('example.test', [MX_PRESENT], { smtpTls: 'enforced' }), 'smtp_tls').status).toBe('satisfied');
		expect(control(evaluateSgeCompliance('example.test', [MX_PRESENT], { smtpTls: 'not_enforced' }), 'smtp_tls').status).toBe(
			'not_satisfied',
		);
	});
});

describe('MTA-STS — mode: enforce', () => {
	it('mode enforce is satisfied', () => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('mta_sts', { recordPresent: true, metadata: { mtaStsMode: 'enforce' } }),
		]);
		expect(control(evaluation, 'mta_sts_enforce').status).toBe('satisfied');
	});

	it.each(['testing', 'none'])('mode %s is not satisfied', (mode) => {
		const evaluation = evaluateSgeCompliance('example.test', [
			MX_PRESENT,
			result('mta_sts', { recordPresent: true, metadata: { mtaStsMode: mode } }),
		]);
		expect(control(evaluation, 'mta_sts_enforce').status).toBe('not_satisfied');
	});

	it('no _mta-sts record is a measured negative', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('mta_sts', { recordPresent: false })]);
		expect(control(evaluation, 'mta_sts_enforce').status).toBe('not_satisfied');
	});

	it('a published record whose policy file could not be read is not_measured, NOT mode none', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('mta_sts', { recordPresent: true })]);
		expect(control(evaluation, 'mta_sts_enforce').status).toBe('not_measured');
		expect(control(evaluation, 'mta_sts_enforce').notMeasuredReason).toBe('policy_unreadable');
	});
});

describe('TLS-RPT', () => {
	it('a published record is satisfied', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('tlsrpt', { recordPresent: true })]);
		expect(control(evaluation, 'tls_rpt').status).toBe('satisfied');
	});

	// The bv-web-prod `sge-readiness.ts` `evalTlsRpt` defect read an ABSENT TLS-RPT record
	// as "reporting enabled". This is the test that would catch that inversion here.
	it('an absent record is not_satisfied — never read as reporting enabled', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('tlsrpt', { recordPresent: false })]);
		expect(control(evaluation, 'tls_rpt').status).toBe('not_satisfied');
	});

	it('an undetermined record is not_measured', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('tlsrpt')]);
		expect(control(evaluation, 'tls_rpt').status).toBe('not_measured');
		expect(control(evaluation, 'tls_rpt').notMeasuredReason).toBe('signal_absent');
	});
});

describe('a domain with no MX', () => {
	const NO_MX = result('mx', { controlPresent: false });

	it('reports mailTransport absent from the mx controlPresent signal', () => {
		expect(evaluateSgeCompliance('parked.test', [NO_MX]).mailTransport).toBe('absent');
	});

	// The documented decision. A no-MX domain receives no mail, so the three inbound
	// transport controls have nothing to describe. They are excused into not_measured,
	// NOT failed — NIST SP 800-177r1 §4.4.2 treats a correctly-configured non-mail domain
	// as a recommended posture, and failing it would be an affirmative adverse claim.
	it('excuses the three inbound-transport controls as no_mail_exchanger rather than failing them', () => {
		const evaluation = evaluateSgeCompliance('parked.test', [
			NO_MX,
			// Absent MTA-STS and TLS-RPT records, which on a mail domain would be
			// measured negatives. They must not be on this one.
			result('mta_sts', { recordPresent: false }),
			result('tlsrpt', { recordPresent: false }),
		]);
		for (const id of ['smtp_tls', 'mta_sts_enforce', 'tls_rpt'] as const) {
			expect(control(evaluation, id).status).toBe('not_measured');
			expect(control(evaluation, id).notMeasuredReason).toBe('no_mail_exchanger');
		}
	});

	it('still evaluates the three anti-spoofing controls — MX is inbound, spoofing is not', () => {
		const evaluation = evaluateSgeCompliance('parked.test', [
			NO_MX,
			result('dmarc', { controlPresent: true, recordPresent: true }),
			result('spf', { metadata: { spfAll: '-all' } }),
			result('dkim', { controlPresent: true }),
		]);
		expect(control(evaluation, 'dmarc_reject').status).toBe('satisfied');
		expect(control(evaluation, 'spf_hardfail').status).toBe('satisfied');
		expect(control(evaluation, 'dkim').status).toBe('satisfied');
	});

	it('can never reach `compliant`, because the excused controls stay unmeasured', () => {
		const evaluation = evaluateSgeCompliance(
			'parked.test',
			[
				NO_MX,
				result('dmarc', { controlPresent: true, recordPresent: true }),
				result('spf', { metadata: { spfAll: '-all' } }),
				result('dkim', { controlPresent: true }),
			],
			{ smtpTls: 'enforced', subdomainCoverage: FULL_COVERAGE },
		);
		expect(evaluation.verdict).toBe('indeterminate');
	});

	// Sub-domain coverage is ANTI-SPOOFING, not inbound transport. A parked domain
	// with an unprotected sub-domain tree is precisely what SGE is written about, so
	// this control is never excused by the absence of an MX — unlike the three
	// transport controls directly above.
	it('still evaluates sub-domain coverage — it is anti-spoofing, not inbound transport', () => {
		const evaluation = evaluateSgeCompliance('parked.test', [NO_MX], {
			subdomainCoverage: {
				enumeration: 'complete',
				source: 'test',
				observations: [{ name: 'old.parked.test', dmarcRecordPresent: false, spfAll: '-all', dkimNullRecordPresent: true }],
			},
		});
		expect(control(evaluation, 'subdomain_coverage').status).toBe('not_satisfied');
	});

	it('an mx check that did not resolve the question leaves transport unknown and evaluates normally', () => {
		const evaluation = evaluateSgeCompliance('example.test', [result('mx'), result('tlsrpt', { recordPresent: false })]);
		expect(evaluation.mailTransport).toBe('unknown');
		expect(control(evaluation, 'tls_rpt').status).toBe('not_satisfied');
	});
});

describe('verdict', () => {
	const ALL_GOOD = [
		MX_PRESENT,
		result('dmarc', { controlPresent: true, recordPresent: true }),
		result('spf', { metadata: { spfAll: '-all' } }),
		result('dkim', { controlPresent: true }),
		result('mta_sts', { recordPresent: true, metadata: { mtaStsMode: 'enforce' } }),
		result('tlsrpt', { recordPresent: true }),
	];

	it('is compliant only when all seven controls are satisfied', () => {
		const evaluation = evaluateSgeCompliance('example.test', ALL_GOOD, { smtpTls: 'enforced', subdomainCoverage: FULL_COVERAGE });
		expect(evaluation.verdict).toBe('compliant');
		expect(evaluation.counts).toEqual({ satisfied: 7, notSatisfied: 0, notMeasured: 0 });
	});

	it('is indeterminate — never compliant — when a control is unmeasured', () => {
		const evaluation = evaluateSgeCompliance('example.test', ALL_GOOD, { subdomainCoverage: FULL_COVERAGE });
		expect(evaluation.verdict).toBe('indeterminate');
		expect(evaluation.counts.notMeasured).toBe(1);
	});

	// bv-mcp #996: the two caller-supplied controls are independent ceilings. Supplying
	// only one leaves the other unmeasured, and one unmeasured control is enough to
	// keep the verdict off `compliant`.
	it('is indeterminate when everything is measured EXCEPT sub-domain coverage', () => {
		const evaluation = evaluateSgeCompliance('example.test', ALL_GOOD, { smtpTls: 'enforced' });
		expect(evaluation.verdict).toBe('indeterminate');
		expect(evaluation.counts).toEqual({ satisfied: 6, notSatisfied: 0, notMeasured: 1 });
		expect(control(evaluation, 'subdomain_coverage').notMeasuredReason).toBe('no_subdomain_enumeration');
	});

	it('is non_compliant when any control is a measured failure, whatever else is unmeasured', () => {
		const evaluation = evaluateSgeCompliance('example.test', [MX_PRESENT, result('spf', { metadata: { spfAll: '~all' } })]);
		expect(evaluation.verdict).toBe('non_compliant');
		expect(evaluation.counts.notSatisfied).toBe(1);
		expect(evaluation.counts.notMeasured).toBe(6);
	});
});
