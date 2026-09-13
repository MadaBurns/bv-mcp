// SPDX-License-Identifier: BUSL-1.1

/**
 * `sge_quickscan` — the wrapper's own contract.
 *
 * The evaluator's logic is tested in `packages/dns-checks/src/__tests__/sge/`.
 * What is tested HERE is everything the wrapper adds and everything it must not
 * lose on the way to a user:
 *
 *  1. It reuses the evaluator rather than re-deriving a control.
 *  2. All three control states, and the evaluator's `evidence[]`, survive into
 *     the report object AND into the RENDERED TEXT.
 *  3. An unmeasured control reads as unmeasured in the rendered text — not as a
 *     pass, not as a failure, and never omitted.
 *  4. The output cannot be read as a clean bill of health when the evaluator
 *     abstained on SMTP TLS.
 *
 * Assertions 2–4 are made against the rendered STRING, because the defect this
 * tool exists to avoid is a rendering defect: an object can carry a perfectly
 * honest `not_measured` and still print a green tick.
 */

import { describe, it, expect } from 'vitest';
import type { CheckResult, Finding } from '../src/lib/scoring';
import { evaluateSgeCompliance } from '@blackveil/dns-checks';
import {
	buildSgeQuickscanReport,
	formatSgeQuickscan,
	SGE_TRANSPORT_TLS_CAVEAT,
	SGE_UNASSESSED_CAVEAT,
	type SgeQuickscanReport,
} from '../src/tools/sge-quickscan';

/**
 * Build a CheckResult directly, so `passed`/`score` can be set to CONTRADICT the
 * structural signals. That contradiction is the point: a wrapper that reached
 * for `passed` or a score band would disagree with these expectations.
 */
function result(category: string, over: Partial<CheckResult> = {}): CheckResult {
	return { category, passed: true, score: 100, findings: [] as Finding[], ...over } as CheckResult;
}

const MX_PRESENT = result('mx', { controlPresent: true });

/**
 * MEASURED-GOOD. Every DNS-observable control satisfied, and deliberately
 * hostile to the old oracles: DMARC carries `passed: false` and `score: 0`
 * beside a genuine `p=reject`, and DKIM carries `passed: false` beside an
 * affirmatively observed key.
 */
const MEASURED_GOOD: CheckResult[] = [
	MX_PRESENT,
	result('dmarc', { controlPresent: true, recordPresent: true, passed: false, score: 0 }),
	result('spf', { metadata: { spfAll: '-all' } }),
	result('dkim', { controlPresent: true, passed: false, score: 0 }),
	result('mta_sts', { recordPresent: true, metadata: { mtaStsMode: 'enforce' } }),
	result('tlsrpt', { recordPresent: true }),
];

/**
 * MEASURED-BAD. Every DNS-observable control measured and found unmet, and
 * again hostile: each result carries `passed: true` and `score: 100`, the exact
 * shape that made `map_compliance` publish 100% compliance for a domain missing
 * the controls (bv-mcp #705/#706).
 */
const MEASURED_BAD: CheckResult[] = [
	MX_PRESENT,
	// A PUBLISHED p=none record: recordPresent true, not enforcing.
	result('dmarc', { controlPresent: false, recordPresent: true }),
	result('spf', { metadata: { spfAll: '~all' } }),
	// DKIM stays satisfied here on purpose, so the failure of the others cannot
	// be explained away as "the fixture fails everything".
	result('dkim', { controlPresent: true }),
	result('mta_sts', { recordPresent: true, metadata: { mtaStsMode: 'testing' } }),
	result('tlsrpt', { recordPresent: false }),
];

/**
 * ABSTAINING. Every check attempted, none completed — a transient DNS/network
 * failure. Nothing was measured, so nothing may be asserted either way.
 */
const ABSTAINING: CheckResult[] = ['mx', 'dmarc', 'spf', 'dkim', 'mta_sts', 'tlsrpt'].map((c) =>
	result(c, { checkStatus: 'timeout', passed: true, score: 100 } as Partial<CheckResult>),
);

function report(checks: CheckResult[]): SgeQuickscanReport {
	return buildSgeQuickscanReport('example.test', checks);
}

function controlOf(r: SgeQuickscanReport, id: string) {
	const found = r.controls.find((c) => c.control === id);
	if (!found) throw new Error(`control ${id} missing`);
	return found;
}

describe('sge_quickscan — it REUSES the evaluator, it does not re-derive', () => {
	it('reproduces evaluateSgeCompliance exactly: same verdict, controls, evidence and counts', () => {
		for (const [label, checks] of [
			['measured-good', MEASURED_GOOD],
			['measured-bad', MEASURED_BAD],
			['abstaining', ABSTAINING],
		] as const) {
			const direct = evaluateSgeCompliance('example.test', checks);
			const wrapped = report(checks);
			expect(wrapped.verdict, label).toBe(direct.verdict);
			expect(wrapped.mailTransport, label).toBe(direct.mailTransport);
			expect(wrapped.counts, label).toEqual(direct.counts);
			// Deep equality on the controls array covers evidence[] verbatim and the
			// fixed six-control ordering: a wrapper that filtered, reordered or
			// summarised a control fails here.
			expect(wrapped.controls, label).toEqual(direct.controls);
		}
	});
});

describe('sge_quickscan — measured-good', () => {
	const r = report(MEASURED_GOOD);
	const rendered = formatSgeQuickscan(r, 'full');

	it('satisfies the five DNS-observable controls and abstains on SMTP TLS', () => {
		expect(r.counts).toEqual({ satisfied: 5, notSatisfied: 0, notMeasured: 1 });
		expect(controlOf(r, 'smtp_tls').status).toBe('not_measured');
		expect(controlOf(r, 'smtp_tls').notMeasuredReason).toBe('no_transport_probe');
	});

	// The product fact: five green ticks is NOT a pass. This is the assertion
	// that stops the tool being read as a clean bill of health.
	it('reports INDETERMINATE, never COMPLIANT, and says so in the rendered text', () => {
		expect(r.verdict).toBe('indeterminate');
		expect(rendered).toContain('INDETERMINATE');
		expect(rendered).toContain('NOT a pass');
		expect(rendered).not.toContain('COMPLIANT — all six SGE controls were measured and satisfied.');
	});

	it('states plainly, in the rendered text, that SMTP TLS was not measured here', () => {
		expect(r.transportTlsCaveat).toBe(SGE_TRANSPORT_TLS_CAVEAT);
		expect(rendered).toContain(SGE_TRANSPORT_TLS_CAVEAT);
		expect(rendered).toContain('never opens an SMTP session');
	});

	it('renders the unmeasured control as NOT MEASURED — not a tick, not a cross, not omitted', () => {
		const line = rendered.split('\n').find((l) => l.includes('**SMTP TLS**'));
		expect(line).toBeDefined();
		expect(line).toContain('❓');
		expect(line).toContain('NOT MEASURED');
		expect(line).not.toContain('✅');
		expect(line).not.toContain('❌');
	});

	it('renders the evaluator evidence verbatim, so the verdict is re-derivable from the text', () => {
		expect(rendered).toContain('Evidence: CheckResult.controlPresent (dmarc: enforcing) = true');
		expect(rendered).toContain('Evidence: spfAllQualifier() = -all');
		expect(rendered).toContain('Evidence: mtaStsPolicyMode() = enforce');
		// `undefined` must print as `undefined`, never as a blank that reads as absent.
		expect(rendered).toContain('Evidence: SgeEvaluateOptions.smtpTls = undefined');
	});
});

describe('sge_quickscan — measured-bad', () => {
	const r = report(MEASURED_BAD);
	const rendered = formatSgeQuickscan(r, 'full');

	it('is NOT COMPLIANT on measured failures, despite every check carrying passed:true / score:100', () => {
		expect(r.verdict).toBe('non_compliant');
		expect(r.counts).toEqual({ satisfied: 1, notSatisfied: 4, notMeasured: 1 });
		expect(rendered).toContain('NOT COMPLIANT');
	});

	it('renders each measured failure with the failure glyph and label', () => {
		for (const label of ['DMARC', 'SPF', 'MTA-STS', 'TLS-RPT']) {
			const line = rendered.split('\n').find((l) => l.includes(`**${label}**`));
			expect(line, label).toContain('❌');
			expect(line, label).toContain('NOT SATISFIED');
		}
	});

	it('still abstains on SMTP TLS rather than folding an unmeasured control into the failure count', () => {
		expect(controlOf(r, 'smtp_tls').status).toBe('not_measured');
		expect(r.counts.notMeasured).toBe(1);
	});

	it('keeps the one satisfied control visibly satisfied', () => {
		const line = rendered.split('\n').find((l) => l.includes('**DKIM**'));
		expect(line).toContain('✅');
		expect(line).toContain('SATISFIED');
	});
});

describe('sge_quickscan — abstaining (every check attempted, none completed)', () => {
	const r = report(ABSTAINING);
	const rendered = formatSgeQuickscan(r, 'full');

	it('measures nothing, claims nothing, and reports INDETERMINATE', () => {
		expect(r.assessed).toBe(false);
		expect(r.caveat).toBe(SGE_UNASSESSED_CAVEAT);
		expect(r.counts).toEqual({ satisfied: 0, notSatisfied: 0, notMeasured: 6 });
		expect(r.verdict).toBe('indeterminate');
	});

	it('renders ALL SIX controls as NOT MEASURED — none omitted, none a pass, none a failure', () => {
		expect(rendered).toContain(SGE_UNASSESSED_CAVEAT);
		for (const label of ['DMARC', 'SPF', 'DKIM', 'SMTP TLS', 'MTA-STS', 'TLS-RPT']) {
			const line = rendered.split('\n').find((l) => l.includes(`**${label}**`));
			expect(line, `${label} must be rendered`).toBeDefined();
			expect(line, label).toContain('❓');
			expect(line, label).toContain('NOT MEASURED');
			expect(line, label).not.toContain('✅');
			expect(line, label).not.toContain('❌');
		}
		// Positive control on the zeros above: the same predicate DOES find a tick
		// and a cross in the other two fixtures, so "no ✅/❌ here" is a measured
		// absence rather than a broken matcher.
		expect(formatSgeQuickscan(report(MEASURED_GOOD), 'full')).toContain('✅');
		expect(formatSgeQuickscan(report(MEASURED_BAD), 'full')).toContain('❌');
	});

	it('explains WHY each control is unmeasured instead of leaving a bare question mark', () => {
		expect(rendered).toContain('Why not measured: the check did not complete (timeout or error)');
	});
});

describe('sge_quickscan — compact format keeps the same three-state vocabulary', () => {
	it('distinguishes all three states and repeats both caveats', () => {
		const good = formatSgeQuickscan(report(MEASURED_GOOD), 'compact');
		expect(good).toContain(' ✓ DMARC: SATISFIED');
		expect(good).toContain(' ? SMTP TLS: NOT MEASURED');
		expect(good).toContain(SGE_TRANSPORT_TLS_CAVEAT);
		expect(good).toContain('INDETERMINATE');

		const bad = formatSgeQuickscan(report(MEASURED_BAD), 'compact');
		expect(bad).toContain(' ✗ DMARC: NOT SATISFIED');

		const none = formatSgeQuickscan(report(ABSTAINING), 'compact');
		expect(none).toContain(SGE_UNASSESSED_CAVEAT);
		expect(none.split('\n').filter((l) => l.startsWith(' ? '))).toHaveLength(6);
	});
});

describe('sge_quickscan — a no-MX domain is not failed for mail it cannot receive', () => {
	const r = report([
		result('mx', { controlPresent: false }),
		result('dmarc', { controlPresent: true, recordPresent: true }),
		result('spf', { metadata: { spfAll: '-all' } }),
		result('dkim', { controlPresent: true }),
	]);

	it('renders the three inbound-transport controls as NOT MEASURED with the no-mail reason', () => {
		const rendered = formatSgeQuickscan(r, 'full');
		expect(r.mailTransport).toBe('absent');
		expect(rendered).toContain('no mail exchanger, or a null MX');
		expect(rendered).toContain('Why not measured: the domain publishes no mail exchanger');
		expect(r.verdict).toBe('indeterminate');
	});

	it('carries NO transport-TLS caveat — that control is unmeasured for a different reason', () => {
		expect(r.transportTlsCaveat).toBeNull();
		expect(formatSgeQuickscan(r, 'full')).not.toContain(SGE_TRANSPORT_TLS_CAVEAT);
	});
});
