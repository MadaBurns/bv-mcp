// SPDX-License-Identifier: BUSL-1.1

/**
 * NZ Secure Government Email (SGE) — per-domain quick scan.
 *
 * The MCP surface for ONE question: "is THIS domain NZ SGE compliant?".
 *
 * WHAT THIS FILE IS, AND IS NOT
 *
 * It is a WRAPPER. Every compliance judgement is made by
 * `evaluateSgeCompliance` in `@blackveil/dns-checks` (`src/sge/`), which owns
 * the six controls, their three-state semantics and the verdict rule. Nothing
 * here re-derives a control, and nothing here reads `passed`,
 * `controlPresent`-as-presence, `recordPresent`, a score, a band, a grade or a
 * finding title. Those oracles are exactly the ones that made `map_compliance`
 * publish NIST + PCI DSS 100% for a domain with no DNSSEC and no CAA
 * (bv-mcp #705/#706). The evaluator was written to end that class of defect;
 * re-deriving anything here would reintroduce it one layer up.
 *
 * So the only logic in this file is presentation, plus two caveats that the
 * evaluator's structured output implies but cannot say in words.
 *
 * ALL THREE STATES SURVIVE TO THE RENDERED TEXT
 *
 * `satisfied` / `not_satisfied` / `not_measured` each get their OWN glyph and
 * their OWN label, and every control is rendered every time — the controls array
 * is never filtered and never reordered. An unmeasured control must read as
 * unmeasured: reusing the failure glyph would put "nobody looked" back in the
 * same visual column as "we looked and it is broken", and omitting it would let
 * a reader count five green ticks as a pass. The evaluator's `evidence[]` is
 * carried through verbatim so a caller can re-derive the verdict without
 * trusting this renderer.
 *
 * SMTP TLS IS NEVER MEASURED HERE — SAID OUT LOUD, NOT IMPLIED
 *
 * `@blackveil/dns-checks` reads DNS and HTTPS. It never opens a session to port
 * 25, so it cannot observe whether a mail exchanger negotiates TLS. The
 * evaluator therefore leaves control 4 of 6 `not_measured` unless a caller
 * supplies a transport observation, and this tool has none to supply: the
 * operator-only `BV_TLS_PROBE` binding is a direct-TLS prober (default port
 * 443, no STARTTLS), so feeding it here would be an inference from an adjacent
 * protocol, not an observation. Inferring the control from `mode: enforce`
 * MTA-STS or from DANE would be the same mistake in DNS clothing.
 *
 * The consequence is a product fact, not a footnote: a real-world run of this
 * tool tops out at `indeterminate`, and `indeterminate` is NOT a pass. The
 * rendered output states that in the headline caveat rather than leaving a user
 * to read five ticks as a clean bill of health.
 *
 * OPEN QUESTION, DELIBERATELY NOT SETTLED HERE
 *
 * The evaluator reports DMARC `satisfied` for `p=reject; sp=none` (health.govt.nz
 * is exactly this shape). Whether SGE should accept an unprotected subdomain
 * tree is an operator/policy judgement with real-world consequences for NZ
 * government agencies, so it is filed as an issue rather than decided in code.
 * This wrapper implements the evaluator's CURRENT behaviour and does not
 * pre-empt the decision.
 */

import { evaluateSgeCompliance } from '@blackveil/dns-checks';
import type { SgeControlStatus, SgeEvaluation, SgeMailTransport, SgeNotMeasuredReason, SgeVerdict } from '@blackveil/dns-checks';
import type { CheckResult } from '../lib/scoring';
import { scanDomain } from './scan-domain';
import type { ScanRuntimeOptions } from './scan/post-processing';
import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';
// The SAME completed-evidence predicate `map_compliance` grades on. Re-spelling
// it is banned by `test/audits/completed-evidence-predicate-ssot.audit.test.ts`;
// an allowlist (`undefined | 'completed'`) rather than a denylist is the point.
import { hasCompletedEvidence } from '../lib/ungraded-display';

/**
 * The tool's report. It is {@link SgeEvaluation} verbatim — same `verdict`,
 * same `mailTransport`, same six `controls` in the same order, same `evidence`,
 * same `counts` — plus the two fields a MACHINE consumer needs in order to
 * render the same caveats a human reader gets in the prose.
 *
 * Nothing is dropped on the way through. A projection layer that quietly
 * deletes the correct oracle is its own documented defect class (the app-side
 * `SingleCheckView` dropped `recordPresent` for four weeks), so this type is
 * additive over the evaluation and never a subset of it.
 */
export interface SgeQuickscanReport extends SgeEvaluation {
	/**
	 * Did ANY check complete for this domain? `false` means nothing was
	 * measured and every control is `not_measured`. Machine consumers must gate
	 * on this before charting anything — it is the structured twin of
	 * {@link SGE_UNASSESSED_CAVEAT}.
	 */
	assessed: boolean;
	/** Populated only when `assessed` is false; `null` otherwise. */
	caveat: string | null;
	/**
	 * Populated whenever SMTP transport TLS went unmeasured for want of a
	 * probe — i.e. on every DNS-only run of a mail-bearing domain. `null` when
	 * the control was measured, or when it was unmeasured for a DIFFERENT
	 * reason (a no-MX domain has no transport to probe, which this caveat would
	 * misdescribe).
	 */
	transportTlsCaveat: string | null;
}

/**
 * The one wording of the "this scanner cannot see SMTP TLS" qualifier, carried
 * on BOTH surfaces — the prose a user reads and the `transportTlsCaveat` field
 * a machine consumes. Exported so tests assert against the SSOT rather than a
 * copy that can drift out of the renderer.
 */
export const SGE_TRANSPORT_TLS_CAVEAT =
	'SMTP transport TLS (control 4 of 6) is NOT MEASURED here: this scanner reads DNS and HTTPS and never opens an SMTP session, ' +
	'so it never observes whether a mail exchanger negotiates TLS. A DNS-only result can therefore never be COMPLIANT — ' +
	'INDETERMINATE is the ceiling, and INDETERMINATE is not a pass. Supply a transport observation from an SMTP probe to decide this control.';

/** The "nothing was measured at all" qualifier. @see SGE_TRANSPORT_TLS_CAVEAT */
export const SGE_UNASSESSED_CAVEAT =
	'No check completed for this domain, so NONE of the six SGE controls were measured. Every control below is reported as ' +
	'NOT MEASURED — the absence of a verdict, never a pass and never a requirement found unmet.';

/**
 * Per-verdict headline. `indeterminate` says "NOT a pass" in the headline
 * itself: a reader who skims the first line and five ticks must not be able to
 * come away thinking the domain was cleared.
 */
const VERDICT_HEADLINE: Record<SgeVerdict, string> = {
	compliant: 'COMPLIANT — all six SGE controls were measured and satisfied.',
	non_compliant: 'NOT COMPLIANT — at least one SGE control was measured and found unmet.',
	indeterminate:
		'INDETERMINATE — this is NOT a pass and NOT a failure. One or more controls could not be measured, ' +
		'so SGE compliance can be neither confirmed nor denied for this domain.',
};

/**
 * Per-status display vocabulary. Three states, three glyphs, three labels.
 * `not_measured` gets its own of each — sharing the failure glyph or the pass
 * glyph is the whole defect.
 */
const STATUS_ICON_FULL: Record<SgeControlStatus, string> = {
	satisfied: '✅',
	not_satisfied: '❌',
	not_measured: '❓',
};

const STATUS_ICON_COMPACT: Record<SgeControlStatus, string> = {
	satisfied: ' ✓',
	not_satisfied: ' ✗',
	not_measured: ' ?',
};

const STATUS_LABEL: Record<SgeControlStatus, string> = {
	satisfied: 'SATISFIED',
	not_satisfied: 'NOT SATISFIED',
	not_measured: 'NOT MEASURED — no verdict was reached (neither a pass nor a failure)',
};

/**
 * Plain-language reason per {@link SgeNotMeasuredReason}. A `Record` on purpose:
 * a new reason added upstream fails the build here instead of silently
 * rendering `undefined` next to an unmeasured control.
 */
const NOT_MEASURED_REASON_TEXT: Record<SgeNotMeasuredReason, string> = {
	check_absent: 'no result was produced for the underlying check.',
	check_not_completed: 'the check did not complete (timeout or error), so nothing was observed.',
	signal_absent: 'the check completed but emitted no signal this control can read.',
	policy_unreadable: 'an MTA-STS record is published, but its policy file could not be fetched or parsed.',
	selector_enumeration_inconclusive:
		'no common DKIM selector answered. DKIM has no discovery mechanism, so a miss is indistinguishable from a key under an uncommon selector — it is not evidence of absence.',
	no_mail_exchanger: 'the domain publishes no mail exchanger, so there is no inbound mail transport to measure.',
	no_transport_probe: 'this scanner never opens an SMTP session, so transport TLS is never observed here.',
};

const MAIL_TRANSPORT_TEXT: Record<SgeMailTransport, string> = {
	present: 'present (the domain publishes a mail exchanger)',
	absent: 'absent (no mail exchanger, or a null MX) — the inbound-transport controls have nothing to measure',
	unknown: 'unknown (the MX check reached no conclusion) — the inbound-transport controls are evaluated anyway',
};

/**
 * Build the report from check results that have ALREADY been gathered.
 *
 * Split out from {@link sgeQuickscan} so the pure evaluation-and-caveat step is
 * testable against fixtures without a scan, and so a caller holding results
 * from elsewhere reuses this exact logic rather than a second opinion.
 *
 * No `smtpTls` observation is passed to the evaluator. See the module docblock:
 * this tool has nothing honest to put there.
 */
export function buildSgeQuickscanReport(domain: string, checks: readonly CheckResult[]): SgeQuickscanReport {
	const evaluation = evaluateSgeCompliance(domain, checks);
	const assessed = hasCompletedEvidence(checks);

	// Read the control the evaluator produced rather than re-deriving "did we
	// probe SMTP?" from anything else. Narrowed to `no_transport_probe`: a
	// `no_mail_exchanger` domain is unmeasured for a different reason, and this
	// caveat would misdescribe it.
	const smtpTls = evaluation.controls.find((c) => c.control === 'smtp_tls');
	const transportTlsCaveat =
		smtpTls?.status === 'not_measured' && smtpTls.notMeasuredReason === 'no_transport_probe' ? SGE_TRANSPORT_TLS_CAVEAT : null;

	return {
		...evaluation,
		assessed,
		caveat: assessed ? null : SGE_UNASSESSED_CAVEAT,
		transportTlsCaveat,
	};
}

/**
 * Answer "is this domain NZ SGE compliant?".
 *
 * Runs a scan (or reuses the cached one, exactly as `map_compliance` does), then
 * hands the check results to the evaluator. The scan is the shared, cached
 * source of check results across every intelligence tool — running a private
 * six-check fan-out here would be a second, unshared code path to the same DNS.
 */
export async function sgeQuickscan(domain: string, kv?: KVNamespace, runtimeOptions?: ScanRuntimeOptions): Promise<SgeQuickscanReport> {
	const scanResult = await scanDomain(domain, kv, runtimeOptions);
	return buildSgeQuickscanReport(domain, scanResult.checks);
}

/** One `signal = value` evidence line. `undefined` renders as `undefined`, never as blank. */
function formatEvidenceValue(value: string | boolean | number | undefined): string {
	return value === undefined ? 'undefined' : sanitizeOutputText(String(value), 120);
}

/**
 * Format an SGE quick-scan report for display.
 *
 * Both formats render ALL SIX controls with their distinct three-state
 * vocabulary; `full` additionally renders the requirement text and the
 * evidence, so the verdict is re-derivable from the output alone.
 */
export function formatSgeQuickscan(report: SgeQuickscanReport, format: OutputFormat = 'full'): string {
	const lines: string[] = [];
	const domain = sanitizeOutputText(report.domain, 253);
	const { satisfied, notSatisfied, notMeasured } = report.counts;
	const tally = `${satisfied} satisfied | ${notSatisfied} not satisfied | ${notMeasured} not measured (of ${report.controls.length})`;

	if (format === 'compact') {
		lines.push(`NZ SGE: ${domain} — ${VERDICT_HEADLINE[report.verdict]}`);
		lines.push(tally);
		if (report.caveat) lines.push(report.caveat);
		if (report.transportTlsCaveat) lines.push(report.transportTlsCaveat);
		lines.push('');

		for (const c of report.controls) {
			const reason = c.notMeasuredReason ? ` — ${NOT_MEASURED_REASON_TEXT[c.notMeasuredReason]}` : '';
			lines.push(`${STATUS_ICON_COMPACT[c.status]} ${sanitizeOutputText(c.label, 40)}: ${STATUS_LABEL[c.status]}${reason}`);
		}
	} else {
		lines.push(`# NZ Secure Government Email (SGE): ${domain}`);
		lines.push(`**Verdict:** ${VERDICT_HEADLINE[report.verdict]}`);
		lines.push(`**Controls:** ${tally}`);
		lines.push(`**Inbound mail transport:** ${MAIL_TRANSPORT_TEXT[report.mailTransport]}`);
		if (report.caveat) lines.push(`> **${report.caveat}**`);
		if (report.transportTlsCaveat) lines.push(`> **${report.transportTlsCaveat}**`);
		lines.push('');

		for (const c of report.controls) {
			lines.push(`${STATUS_ICON_FULL[c.status]} **${sanitizeOutputText(c.label, 40)}** — ${STATUS_LABEL[c.status]}`);
			lines.push(`  - Requirement: ${sanitizeOutputText(c.requirement, 200)}`);
			if (c.notMeasuredReason) {
				lines.push(`  - Why not measured: ${NOT_MEASURED_REASON_TEXT[c.notMeasuredReason]}`);
			}
			for (const e of c.evidence) {
				lines.push(`  - Evidence: ${sanitizeOutputText(e.signal, 80)} = ${formatEvidenceValue(e.value)}`);
			}
			lines.push('');
		}
	}

	return lines.join('\n').trimEnd();
}
