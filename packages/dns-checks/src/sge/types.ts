// SPDX-License-Identifier: BUSL-1.1

/**
 * NZ Secure Government Email (SGE) — per-domain compliance types.
 *
 * SCOPE. This answers ONE question, per domain: "is THIS domain compliant with
 * NZ SGE?" It is not an aggregate statistic, and it is deliberately NOT a
 * compliance-framework map (`map_compliance`'s shape) — it maps six named
 * controls, each with its own evidence, and nothing else.
 *
 * @module
 */

/**
 * The six SGE controls, in the fixed order an evaluation reports them.
 *
 * Ordering is part of the contract: consumers render this as a checklist, and a
 * reordering would silently reshuffle a rendered table.
 */
export const SGE_CONTROL_IDS = ['dmarc_reject', 'spf_hardfail', 'dkim', 'smtp_tls', 'mta_sts_enforce', 'tls_rpt'] as const;

export type SgeControlId = (typeof SGE_CONTROL_IDS)[number];

/**
 * A control's state. THREE states, always — never a `boolean`, and never
 * `boolean | null`.
 *
 * A boolean makes UNKNOWN compile silently into `false`; `false` on a security
 * control is an affirmative claim ("this domain does not have it") made from
 * zero evidence. That is the exact shape of the 2026-08-19 `map_compliance`
 * defect (bv-mcp #705/#706), inverted. So:
 *
 * - `satisfied`     — measured, and the control meets the SGE requirement.
 * - `not_satisfied` — measured, and it does not. An affirmative negative.
 * - `not_measured`  — no verdict is available. Never rendered as a pass, never
 *                     as a fail, and never omitted from the output.
 *
 * The discriminator is the check's COMPLETION STATUS and its structured
 * signals — never its score, never `passed`, never finding prose.
 */
export type SgeControlStatus = 'satisfied' | 'not_satisfied' | 'not_measured';

/**
 * Why a control could not be measured. Present iff `status === 'not_measured'`.
 *
 * These are distinct facts and must not be collapsed into one another: "we did
 * not probe" and "we probed and found nothing" are different, and only the
 * second is evidence.
 */
export type SgeNotMeasuredReason =
	/** No `CheckResult` was supplied for the underlying category at all. */
	| 'check_absent'
	/** A result exists but the check did not complete (`checkStatus` timeout/error, or an out-of-union value). */
	| 'check_not_completed'
	/** The check completed but emitted no signal this control can read (e.g. an older result predating the signal). */
	| 'signal_absent'
	/** MTA-STS: the `_mta-sts` TXT record was published, but the policy file could not be fetched or parsed. */
	| 'policy_unreadable'
	/** DKIM: selector enumeration returned no hit. Guessing a selector list and missing is NOT measured absence. */
	| 'selector_enumeration_inconclusive'
	/** The domain publishes no mail exchanger, so there is no inbound mail transport to measure. */
	| 'no_mail_exchanger'
	/** SMTP TLS: this package opens no SMTP connection, so it never measures transport TLS. */
	| 'no_transport_probe';

/**
 * One structured signal a verdict was derived from.
 *
 * `signal` names the field or predicate read (e.g. `spfAllQualifier()`,
 * `CheckResult.recordPresent`); `value` is what it returned. Deliberately
 * structural: no finding titles, no finding details, no score bands. A consumer
 * or an auditor can re-derive the verdict from this list alone.
 */
export interface SgeEvidence {
	signal: string;
	value: string | boolean | number | undefined;
}

export interface SgeControlEvaluation {
	control: SgeControlId;
	/** Short human label for the control. Display only — never parsed. */
	label: string;
	/** The SGE requirement in one line. Display only — never parsed. */
	requirement: string;
	status: SgeControlStatus;
	/** Set iff `status === 'not_measured'`. */
	notMeasuredReason?: SgeNotMeasuredReason;
	evidence: SgeEvidence[];
}

/**
 * Domain-level verdict.
 *
 * `compliant` requires all six controls `satisfied`. A single `not_measured`
 * control yields `indeterminate`, never `compliant` — certifying compliance
 * over an unmeasured control is the false affirmative this module exists to
 * prevent. `non_compliant` wins over `indeterminate`: one measured failure is
 * enough to decide the domain, whatever else went unmeasured.
 */
export type SgeVerdict = 'compliant' | 'non_compliant' | 'indeterminate';

/**
 * Whether the domain publishes inbound mail transport.
 *
 * Read from the `mx` check's `controlPresent` (`true` = a real mail exchanger,
 * `false` = no MX or a null MX, `undefined` = the query did not resolve the
 * question). Never from an MX finding's prose, and never from `passed`.
 */
export type SgeMailTransport = 'present' | 'absent' | 'unknown';

export interface SgeEvaluation {
	domain: string;
	verdict: SgeVerdict;
	mailTransport: SgeMailTransport;
	/** All six controls, always, in `SGE_CONTROL_IDS` order. Never filtered. */
	controls: SgeControlEvaluation[];
	counts: {
		satisfied: number;
		notSatisfied: number;
		notMeasured: number;
	};
}

/**
 * An externally supplied SMTP transport-TLS observation.
 *
 * `@blackveil/dns-checks` reads DNS and HTTPS. It never opens a connection to
 * port 25, so it cannot itself observe whether a mail exchanger offers or
 * requires STARTTLS. Rather than infer the control from MTA-STS or DANE (which
 * would be an affirmative claim from adjacent evidence), the evaluator leaves
 * it `not_measured` unless a caller that DID probe the transport supplies the
 * result here.
 */
export type SgeSmtpTlsObservation = 'enforced' | 'not_enforced';

export interface SgeEvaluateOptions {
	/** @see SgeSmtpTlsObservation */
	smtpTls?: SgeSmtpTlsObservation;
}
