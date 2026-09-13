// SPDX-License-Identifier: BUSL-1.1

/**
 * NZ Secure Government Email (SGE) — per-domain evaluator.
 *
 * NZ government agencies must meet SGE by October 2026. The six controls
 * evaluated here are the ones an agency is measured on:
 *
 *   1. DMARC at `p=reject`
 *   2. SPF terminating in `-all`
 *   3. DKIM signing
 *   4. SMTP transport TLS
 *   5. MTA-STS at `mode: enforce`
 *   6. TLS-RPT reporting
 *
 * WHAT THIS MODULE REFUSES TO DO, and why
 *
 * - It never reads `passed`. `passed` means "this check did not penalize the
 *   domain", not "the control exists" — an absent-but-unpenalized control
 *   returns `passed: true`. Four surfaces have misread it as a verdict
 *   (bv-mcp #705 #706 #725 #809); `map_compliance` published NIST + PCI DSS
 *   100% for a domain with no DNSSEC and no CAA on exactly that mistake.
 * - It never reads `controlPresent` as a PRESENCE oracle. `controlPresent` is
 *   ENFORCEMENT-shaped and means something different per check: a published
 *   `v=DMARC1; p=none; rua=…` reads `controlPresent: false` while being a real,
 *   published record. It is read here ONLY where its enforcement meaning is
 *   exactly the question (dmarc: "is it enforcing?", dkim: "is there an active
 *   key?", mx: "is there real mail?"), never as "does a record exist".
 * - It never reads a score, a score band, or a grade. A published-but-weak
 *   control and an absent one land in the same band.
 * - It never matches finding TEXT. Subject-supplied data has reached prose
 *   predicates before (a scanned domain's own name supplying the substring
 *   "missing" zeroed a category, 2026-08-20). The one prose-derived predicate
 *   used at all is the package's OWN canonical `findingsIndicateMissingControl`
 *   — used in the NEGATIVE direction only, never to affirm compliance.
 * - It never parses a raw SPF or MTA-STS record itself. The structured readers
 *   `spfAllQualifier()` and `mtaStsPolicyMode()` (added 1.42.0, bv-mcp #987)
 *   exist precisely so a compliance consumer does not have to. The check_spf
 *   FINDING path still matches `all` as an unanchored substring (bv-mcp #988),
 *   so a hostname like `include:send-all.example.net` can make a `~all` record
 *   look like `-all` in the findings — a second reason the reader is the only
 *   safe source.
 *
 * NO MX IS NOT NON-COMPLIANCE — the documented decision
 *
 * A domain that publishes no mail exchanger (or a null MX) receives no mail.
 * The three INBOUND-TRANSPORT controls — SMTP TLS, MTA-STS, TLS-RPT — then have
 * no transport to describe, so they are reported `not_measured` with reason
 * `no_mail_exchanger`. They are NOT reported `not_satisfied`: failing a domain
 * for not securing mail it cannot receive would be an affirmative adverse claim
 * about a posture that NIST SP 800-177r1 §4.4.2 actually recommends. They are
 * equally NOT reported `satisfied` — nothing was observed.
 *
 * The three ANTI-SPOOFING controls — DMARC, SPF, DKIM — are evaluated normally
 * on a no-MX domain. MX is inbound; a domain with no MX can still SEND, and a
 * parked domain must still publish `p=reject` / `-all` so it cannot be spoofed.
 *
 * Consequence, stated plainly: a no-MX domain can never reach `compliant` here.
 * It reaches `indeterminate` with three `no_mail_exchanger` controls, which is
 * the honest answer — deciding that a non-mail domain is SGE-compliant is a
 * policy judgement, and this module reports evidence rather than making it.
 *
 * @module
 */

import type { CheckCategory, CheckResult } from '../types';
import {
	findingsIndicateMissingControl,
	findingsIndicatePartialEnforcement,
	isCheckMeasured,
	mtaStsPolicyMode,
	spfAllQualifier,
} from '../scoring';
import {
	SGE_CONTROL_IDS,
	type SgeControlEvaluation,
	type SgeControlId,
	type SgeEvaluateOptions,
	type SgeEvaluation,
	type SgeEvidence,
	type SgeMailTransport,
	type SgeNotMeasuredReason,
	type SgeVerdict,
} from './types';

const LABELS: Record<SgeControlId, { label: string; requirement: string }> = {
	dmarc_reject: { label: 'DMARC', requirement: 'A published DMARC record at p=reject, applied to 100% of mail.' },
	spf_hardfail: { label: 'SPF', requirement: 'A published SPF record terminating in -all (hard fail).' },
	dkim: { label: 'DKIM', requirement: 'An active DKIM signing key published for the domain.' },
	smtp_tls: { label: 'SMTP TLS', requirement: 'Mail exchangers offer and use TLS for SMTP transport.' },
	mta_sts_enforce: { label: 'MTA-STS', requirement: 'An MTA-STS policy served at mode: enforce.' },
	tls_rpt: { label: 'TLS-RPT', requirement: 'A published TLS-RPT record so transport failures are reported.' },
};

function satisfied(control: SgeControlId, evidence: SgeEvidence[]): SgeControlEvaluation {
	return { control, ...LABELS[control], status: 'satisfied', evidence };
}

function notSatisfied(control: SgeControlId, evidence: SgeEvidence[]): SgeControlEvaluation {
	return { control, ...LABELS[control], status: 'not_satisfied', evidence };
}

function notMeasured(control: SgeControlId, reason: SgeNotMeasuredReason, evidence: SgeEvidence[]): SgeControlEvaluation {
	return { control, ...LABELS[control], status: 'not_measured', notMeasuredReason: reason, evidence };
}

/**
 * The one gate every control-bearing check passes through first.
 *
 * Returns a `not_measured` evaluation when the result is missing or the check
 * did not complete, and `undefined` when the caller may proceed. `checkStatus`
 * is consulted through the package's own allowlist predicate `isCheckMeasured`
 * — anything that is not affirmatively `'completed'` (or absent, meaning "ran
 * normally") is unmeasured, including an out-of-union value from a cache read.
 */
function measurementGate(control: SgeControlId, result: CheckResult | undefined): SgeControlEvaluation | undefined {
	if (!result) return notMeasured(control, 'check_absent', []);
	if (!isCheckMeasured(result.checkStatus)) {
		return notMeasured(control, 'check_not_completed', [{ signal: 'CheckResult.checkStatus', value: result.checkStatus }]);
	}
	return undefined;
}

/**
 * DMARC at `p=reject`.
 *
 * `controlPresent === true` on the dmarc check means ENFORCING, i.e. `p=`
 * quarantine or reject (check-dmarc.ts: `dmarcEnforcing`). The remaining step —
 * separating quarantine from reject — is the package's structural
 * `partialEnforcement` finding metadata, which the dmarc classifier sets for
 * `p=quarantine` and for any `pct<100`, and for nothing else. Both are read
 * through the canonical exported predicate, never by inspecting metadata here.
 *
 * `sp=none` deliberately does NOT make this control fail: it is a real
 * subdomain weakness and the scan reports it, but the SGE control named here is
 * the organisational domain's own `p=`. Reading the sp= finding as a failure is
 * how a p=reject domain produced a FALSE NEGATIVE under the old oracle.
 */
function evaluateDmarc(result: CheckResult | undefined): SgeControlEvaluation {
	const gated = measurementGate('dmarc_reject', result);
	if (gated || !result) return gated ?? notMeasured('dmarc_reject', 'check_absent', []);

	// The predicate's docblock requires callers operating on whole results to gate
	// it with `isCheckMeasured` first — the measurement gate above did that.
	const partial = findingsIndicatePartialEnforcement(result.findings);
	const evidence: SgeEvidence[] = [
		{ signal: 'CheckResult.recordPresent', value: result.recordPresent },
		{ signal: 'CheckResult.controlPresent (dmarc: enforcing)', value: result.controlPresent },
		{ signal: 'findingsIndicatePartialEnforcement()', value: partial },
	];

	if (result.controlPresent === true) {
		// Enforcing. Partial enforcement (quarantine, or pct<100) is not reject.
		return partial ? notSatisfied('dmarc_reject', evidence) : satisfied('dmarc_reject', evidence);
	}
	if (result.recordPresent === false || result.controlPresent === false) {
		// Either no record at all, or a published record that is not enforcing
		// (p=none). Both are measured negatives against "p=reject".
		return notSatisfied('dmarc_reject', evidence);
	}
	return notMeasured('dmarc_reject', 'signal_absent', evidence);
}

/**
 * SPF terminating in `-all`.
 *
 * `spfAllQualifier()` is the ONLY source. `undefined` from it means "not
 * determined" — the check emitted no qualifier — which a domain with no SPF
 * record produces (check-spf returns before the qualifier is computed). To turn
 * that into a measured negative rather than an unmeasured one, and only in that
 * direction, the package's canonical `findingsIndicateMissingControl` predicate
 * is consulted: no SPF record published is a measured negative against `-all`.
 * If neither signal resolves, the control stays unmeasured.
 *
 * The spf check deliberately sets neither `controlPresent` nor `recordPresent`
 * (check-spf.ts), so there is no presence flag to read here and none is faked.
 */
function evaluateSpf(result: CheckResult | undefined): SgeControlEvaluation {
	const gated = measurementGate('spf_hardfail', result);
	if (gated || !result) return gated ?? notMeasured('spf_hardfail', 'check_absent', []);

	const qualifier = spfAllQualifier(result);
	const evidence: SgeEvidence[] = [{ signal: 'spfAllQualifier()', value: qualifier }];

	if (qualifier === '-all') return satisfied('spf_hardfail', evidence);
	if (qualifier !== undefined) return notSatisfied('spf_hardfail', evidence);

	const missing = findingsIndicateMissingControl(result.findings);
	evidence.push({ signal: 'findingsIndicateMissingControl()', value: missing });
	if (missing) return notSatisfied('spf_hardfail', evidence);

	return notMeasured('spf_hardfail', 'signal_absent', evidence);
}

/**
 * DKIM signing.
 *
 * `controlPresent === true` means an ACTIVE key was observed (found selector
 * with a non-empty `p=`); that is an affirmative measurement and the control is
 * satisfied.
 *
 * `controlPresent === false` is NOT a measured absence and must never be
 * reported as `not_satisfied`. DKIM has no discovery mechanism: the check
 * probes a list of COMMON selectors, and a domain signing with a selector
 * outside that list is indistinguishable from a domain that does not sign at
 * all. The check itself is careful about this — it narrows its own absence
 * claim to the selectors that actually answered and records the rest as
 * unmeasured. So a miss is `not_measured` with
 * `selector_enumeration_inconclusive`.
 *
 * DKIM is also one of the five categories that emit no `recordPresent` at all
 * (spf, dkim, ssl, ns, http_security), so there is no presence oracle to fall
 * back to. This is the residual gap recorded against bv-mcp #705; closing it
 * requires the check to emit the signal, which is not this module's to do.
 */
function evaluateDkim(result: CheckResult | undefined): SgeControlEvaluation {
	const gated = measurementGate('dkim', result);
	if (gated || !result) return gated ?? notMeasured('dkim', 'check_absent', []);

	const evidence: SgeEvidence[] = [{ signal: 'CheckResult.controlPresent (dkim: active key)', value: result.controlPresent }];

	if (result.controlPresent === true) return satisfied('dkim', evidence);
	if (result.controlPresent === false) return notMeasured('dkim', 'selector_enumeration_inconclusive', evidence);
	return notMeasured('dkim', 'signal_absent', evidence);
}

/**
 * SMTP transport TLS.
 *
 * Always `not_measured` unless a caller supplies an observation: this package
 * never connects to port 25. It would be easy and wrong to infer the control
 * from `mode: enforce` MTA-STS or from a DANE TLSA record — both are DNS-side
 * declarations of INTENT, not observations that a session negotiated TLS.
 */
function evaluateSmtpTls(transport: SgeMailTransport, options: SgeEvaluateOptions): SgeControlEvaluation {
	if (transport === 'absent') {
		return notMeasured('smtp_tls', 'no_mail_exchanger', [{ signal: 'mailTransport', value: transport }]);
	}
	const observed = options.smtpTls;
	const evidence: SgeEvidence[] = [{ signal: 'SgeEvaluateOptions.smtpTls', value: observed }];
	if (observed === 'enforced') return satisfied('smtp_tls', evidence);
	if (observed === 'not_enforced') return notSatisfied('smtp_tls', evidence);
	return notMeasured('smtp_tls', 'no_transport_probe', evidence);
}

/**
 * MTA-STS at `mode: enforce`.
 *
 * `mtaStsPolicyMode()` reports a mode only when a policy file was actually
 * fetched AND parsed. `undefined` therefore covers two different situations,
 * which are separated by `recordPresent`:
 *
 * - `recordPresent === false` — no `_mta-sts` TXT record was published. A
 *   measured negative.
 * - `recordPresent === true` and no mode — the record exists but the policy
 *   file could not be read. `not_measured` / `policy_unreadable`. Treating an
 *   unreadable policy as `mode: none` would be an affirmative adverse claim
 *   from zero evidence, which is exactly what the reader's docblock forbids.
 */
function evaluateMtaSts(result: CheckResult | undefined, transport: SgeMailTransport): SgeControlEvaluation {
	if (transport === 'absent') {
		return notMeasured('mta_sts_enforce', 'no_mail_exchanger', [{ signal: 'mailTransport', value: transport }]);
	}
	const gated = measurementGate('mta_sts_enforce', result);
	if (gated || !result) return gated ?? notMeasured('mta_sts_enforce', 'check_absent', []);

	const mode = mtaStsPolicyMode(result);
	const evidence: SgeEvidence[] = [
		{ signal: 'mtaStsPolicyMode()', value: mode },
		{ signal: 'CheckResult.recordPresent', value: result.recordPresent },
	];

	if (mode === 'enforce') return satisfied('mta_sts_enforce', evidence);
	if (mode !== undefined) return notSatisfied('mta_sts_enforce', evidence);
	if (result.recordPresent === false) return notSatisfied('mta_sts_enforce', evidence);
	return notMeasured('mta_sts_enforce', 'policy_unreadable', evidence);
}

/**
 * TLS-RPT reporting.
 *
 * `recordPresent` is the correct oracle here and the tlsrpt check emits it
 * (it is one of the nine categories that do). `controlPresent` is never set by
 * that check, so there is nothing to confuse it with.
 *
 * ⚠️ KNOWN LIMITATION, deliberately not papered over: check-tlsrpt sets
 * `recordPresent: true` for a published record that carries no `rua=` — a
 * record that names no reporting address and therefore reports nothing. No
 * structured signal distinguishes the two states today, and inferring it from
 * the finding title is forbidden. This evaluator therefore reports such a
 * domain `satisfied`, which is a narrow false affirmative. Closing it needs the
 * check to emit a structured reporting-address signal, the same way bv-mcp #987
 * added `spfAll` and `mtaStsMode`. Out of scope here; recorded so the next
 * reader does not mistake it for an oversight.
 */
function evaluateTlsRpt(result: CheckResult | undefined, transport: SgeMailTransport): SgeControlEvaluation {
	if (transport === 'absent') {
		return notMeasured('tls_rpt', 'no_mail_exchanger', [{ signal: 'mailTransport', value: transport }]);
	}
	const gated = measurementGate('tls_rpt', result);
	if (gated || !result) return gated ?? notMeasured('tls_rpt', 'check_absent', []);

	const evidence: SgeEvidence[] = [{ signal: 'CheckResult.recordPresent', value: result.recordPresent }];
	if (result.recordPresent === true) return satisfied('tls_rpt', evidence);
	if (result.recordPresent === false) return notSatisfied('tls_rpt', evidence);
	return notMeasured('tls_rpt', 'signal_absent', evidence);
}

/**
 * Inbound mail transport, from the mx check's `controlPresent`.
 *
 * This is the one place `controlPresent` is read for mx, and it is read for
 * exactly what it means there: `true` = a real mail exchanger, `false` = no MX
 * or a null MX. An mx check that did not complete, or is absent, yields
 * `unknown` — and `unknown` evaluates the transport controls normally, because
 * "we do not know whether this domain receives mail" is not grounds to excuse
 * them.
 */
function resolveMailTransport(mx: CheckResult | undefined): SgeMailTransport {
	if (!mx || !isCheckMeasured(mx.checkStatus)) return 'unknown';
	if (mx.controlPresent === true) return 'present';
	if (mx.controlPresent === false) return 'absent';
	return 'unknown';
}

function byCategory(results: readonly CheckResult[], category: CheckCategory): CheckResult | undefined {
	return results.find((r) => r.category === category);
}

function verdictFrom(controls: readonly SgeControlEvaluation[]): SgeVerdict {
	if (controls.some((c) => c.status === 'not_satisfied')) return 'non_compliant';
	if (controls.some((c) => c.status === 'not_measured')) return 'indeterminate';
	return 'compliant';
}

/**
 * Evaluate a domain against the six NZ SGE controls.
 *
 * @param domain  The domain the results describe. Echoed back; never parsed.
 * @param results The check results to read. Extra categories are ignored and
 *                missing ones become `not_measured` / `check_absent` — a
 *                control is never dropped from the output.
 */
export function evaluateSgeCompliance(domain: string, results: readonly CheckResult[], options: SgeEvaluateOptions = {}): SgeEvaluation {
	const transport = resolveMailTransport(byCategory(results, 'mx'));

	const controls: SgeControlEvaluation[] = [
		evaluateDmarc(byCategory(results, 'dmarc')),
		evaluateSpf(byCategory(results, 'spf')),
		evaluateDkim(byCategory(results, 'dkim')),
		evaluateSmtpTls(transport, options),
		evaluateMtaSts(byCategory(results, 'mta_sts'), transport),
		evaluateTlsRpt(byCategory(results, 'tlsrpt'), transport),
	];

	// Order contract: the array above must match SGE_CONTROL_IDS exactly. Asserted
	// in the test suite rather than at runtime — a reordering is a source edit, not
	// a runtime condition.
	void SGE_CONTROL_IDS;

	return {
		domain,
		verdict: verdictFrom(controls),
		mailTransport: transport,
		controls,
		counts: {
			satisfied: controls.filter((c) => c.status === 'satisfied').length,
			notSatisfied: controls.filter((c) => c.status === 'not_satisfied').length,
			notMeasured: controls.filter((c) => c.status === 'not_measured').length,
		},
	};
}
