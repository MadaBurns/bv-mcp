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

/**
 * Advisories — facts that sit ALONGSIDE the six controls and never change one.
 *
 * WHY THIS EXISTS (bv-mcp #991). `p=reject; sp=none` satisfies `dmarc_reject`:
 * RFC 9989 §4.7 says `sp` "applies only to existing subdomains … and not to the
 * Organizational Domain itself", SGE's requirement is "DMARC needs to be set to
 * p=reject on all email enabled domains" and never mentions `sp`, and NZISM
 * 15 point 2 point 36 point C point 02 is likewise silent on it. Downgrading
 * the control would be a false negative against the written requirement.
 *
 * But the subdomain tree really is exposed, and this package's own scorer says
 * so at severity `high`. An SGE surface that reported six green ticks and
 * nothing else would read as a clean bill of health on subdomains while the
 * scorer said the opposite — two live surfaces, opposite impressions, same
 * input. Advisories are how the evaluator carries the second fact without
 * corrupting the first.
 *
 * They are STRUCTURED, not prose, so a caller renders them distinctly — their
 * own section, their own severity column, their own evidence. A sentence
 * appended to a control's text would be unrenderable and unparseable.
 */
export const SGE_ADVISORY_IDS = ['subdomain_policy_gap', 'pct_tag_present'] as const;

export type SgeAdvisoryId = (typeof SGE_ADVISORY_IDS)[number];

/**
 * How an advisory should read next to the controls.
 *
 * - `exposure` — a MEASURED security gap the six controls do not cover. It is
 *   not a control failure and must never be rendered as one, but it must never
 *   be rendered as cosmetic either.
 * - `advisory` — a conformance or spec-currency note with no measured attack
 *   surface of its own.
 *
 * Deliberately NOT the `Severity` union used by findings: that union is
 * score-bearing, and reusing it here would invite a consumer to add these into
 * a severity tally that the scoring engine never saw.
 */
export type SgeAdvisorySeverity = 'exposure' | 'advisory';

export interface SgeAdvisory {
	id: SgeAdvisoryId;
	/** Short human label. Display only — never parsed. */
	label: string;
	severity: SgeAdvisorySeverity;
	/**
	 * The control this advisory sits ALONGSIDE, so a renderer can place it. It
	 * is emphatically NOT the control it modifies — no advisory ever changes a
	 * control's `status`, and the verdict is computed from the controls alone.
	 */
	relatedControl: SgeControlId;
	/** One-line explanation, with the standards basis. Display only. */
	summary: string;
	/** @see SgeEvidence — same structural rules; re-derivable, never prose-matched. */
	evidence: SgeEvidence[];
}

export interface SgeEvaluation {
	domain: string;
	verdict: SgeVerdict;
	mailTransport: SgeMailTransport;
	/** All six controls, always, in `SGE_CONTROL_IDS` order. Never filtered. */
	controls: SgeControlEvaluation[];
	/**
	 * Zero or more advisories, in `SGE_ADVISORY_IDS` order. ALWAYS an array —
	 * empty rather than absent — so a consumer cannot skip the field by testing
	 * for its existence.
	 *
	 * ⚠️ A `compliant` verdict with a non-empty `advisories` array is a real and
	 * expected state. It means the six written SGE controls are met AND a gap
	 * outside them was measured. Rendering the verdict without the advisories
	 * reintroduces exactly the "reads as clean" defect they exist to close.
	 */
	advisories: SgeAdvisory[];
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
