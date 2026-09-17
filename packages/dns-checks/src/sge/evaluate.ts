// SPDX-License-Identifier: BUSL-1.1

/**
 * NZ Secure Government Email (SGE) — per-domain evaluator.
 *
 * NZ government agencies must meet SGE by October 2026. The seven controls
 * evaluated here are the ones an agency is measured on:
 *
 *   1. DMARC at `p=reject`
 *   2. SPF terminating in `-all`
 *   3. DKIM signing
 *   4. SMTP transport TLS
 *   5. MTA-STS at `mode: enforce`
 *   6. TLS-RPT reporting
 *   7. Full sub-domain coverage
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

// bv-oversize-ok: one pure evaluator with no glue to split off — the length is
// the per-control rationale this module is required to carry in-code, not
// tangled responsibilities. Types live in ./types, readers in ../scoring.
import type { CheckCategory, CheckResult } from '../types';
import {
	dmarcNonExistentSubdomainPolicy,
	dmarcPctTagPresent,
	dmarcPolicyTag,
	dmarcRecordInheritedFromParent,
	dmarcSubdomainPolicy,
	findingsIndicateMissingControl,
	findingsIndicatePartialEnforcement,
	isCheckMeasured,
	mtaStsPolicyMode,
	spfAllQualifier,
	type DmarcPolicyValue,
} from '../scoring';
import {
	SGE_ADVISORY_IDS,
	type SgeAdvisory,
	type SgeAdvisoryId,
	SGE_CONTROL_IDS,
	type SgeControlEvaluation,
	type SgeControlId,
	type SgeEvaluateOptions,
	type SgeEvaluation,
	type SgeEvidence,
	type SgeMailTransport,
	type SgeNotMeasuredReason,
	type SgeSubdomainObservation,
	type SgeVerdict,
} from './types';

const LABELS: Record<SgeControlId, { label: string; requirement: string }> = {
	dmarc_reject: { label: 'DMARC', requirement: 'A published DMARC record at p=reject, applied to 100% of mail.' },
	spf_hardfail: { label: 'SPF', requirement: 'A published SPF record terminating in -all (hard fail).' },
	dkim: { label: 'DKIM', requirement: 'An active DKIM signing key published for the domain.' },
	smtp_tls: { label: 'SMTP TLS', requirement: 'Mail exchangers offer and use TLS for SMTP transport.' },
	mta_sts_enforce: { label: 'MTA-STS', requirement: 'An MTA-STS policy served at mode: enforce.' },
	tls_rpt: { label: 'TLS-RPT', requirement: 'A published TLS-RPT record so transport failures are reported.' },
	subdomain_coverage: {
		label: 'Sub-domain coverage',
		requirement:
			'EVERY sub-domain publishes its own _dmarc record, v=spf1 -all and a null v=DKIM1; p= record — down to a sub-domain that is only an A record. sp= at the apex does not satisfy this.',
	},
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
 * `sp=none` deliberately does NOT make this control fail — SETTLED by operator
 * ruling on bv-mcp #991, not an open question. RFC 9989 §4.7, verbatim: `sp`
 * "applies only to existing subdomains of the message's Organizational Domain in
 * the DNS hierarchy and not to the Organizational Domain itself", so it cannot
 * weaken the apex policy this control is about. SGE's requirement in full is
 * "DMARC needs to be set to p=reject on all email enabled domains" and never
 * mentions `sp`; NZISM 15 point 2 point 36 point C point 02, the only binding NZ
 * control naming DMARC, is likewise silent on it. Reading the sp= finding as a
 * failure is how a p=reject domain produced a FALSE NEGATIVE under the old
 * oracle.
 *
 * The exposure is REAL and is reported — as a separate `subdomain_policy_gap`
 * advisory on the evaluation, never by touching this control's status. See
 * {@link subdomainPolicyGap}.
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
 * Full sub-domain coverage (bv-mcp #996).
 *
 * THE REQUIREMENT, in SGE's own terms: every sub-domain publishes its OWN
 * anti-spoofing records — an explicit `_dmarc` record, `v=spf1 -all`, and a null
 * `v=DKIM1; p=` record — down to a sub-domain consisting of "as little as a
 * single A record".
 *
 * SGE REFUSES `sp=` AS THE MECHANISM, verbatim: "This requirement remains even
 * if the root level domain has SP=reject set within its DMARC record", and
 * "having SP=reject in the root record will only partially resolve the issue".
 * So nothing about the apex record — not `p=`, not `sp=`, not `np=` — can
 * satisfy or excuse this control, and none of those signals is read here. The
 * apex-only fact this evaluator CAN measure is reported separately as the
 * `subdomain_policy_gap` advisory; see {@link subdomainPolicyGap}.
 *
 * WHY IT IS AN INPUT. This function performs no I/O — the module is pure by
 * design — and verifying the requirement needs enumeration plus a per-name scan.
 * The caller owns both, exactly as it owns the SMTP transport observation. With
 * no input the control is `not_measured` / `no_subdomain_enumeration`: "we
 * enumerated nothing" is NOT "the sub-domains are uncovered", and recording the
 * second from the first would zero a control nobody measured (bv-mcp #638).
 *
 * THE ORDER OF THE BRANCHES IS THE WHOLE DESIGN, and it is deliberately NOT
 * "incomplete enumeration short-circuits everything":
 *
 * 1. A MEASURED FAILURE WINS, whatever the enumeration claims. If an observed
 *    sub-domain is measurably missing one of the three records, SGE's "every
 *    sub-domain" is measurably violated and the control is `not_satisfied`.
 *    Discarding that because the LIST might be incomplete would suppress real
 *    evidence — the mirror image of the false affirmative, and against the
 *    module's own rule that one measured failure decides.
 * 2. An INCOMPLETE enumeration can never produce `satisfied`. "Every sub-domain
 *    is covered" is an unbounded negative; a partial list cannot support it
 *    however many observed names pass.
 * 3. A COMPLETE enumeration whose observations left records UNMEASURED is
 *    `not_measured` too — undefined is not a pass.
 * 4. Only a complete enumeration in which every observation carries all three
 *    records is `satisfied`.
 *
 * TRANSPORT IS IRRELEVANT HERE. Unlike the three inbound-transport controls this
 * one is NOT excused on a no-MX domain: it is anti-spoofing, and a parked domain
 * with an unprotected sub-domain tree is exactly the case SGE is written about.
 */
function evaluateSubdomainCoverage(options: SgeEvaluateOptions): SgeControlEvaluation {
	const coverage = options.subdomainCoverage;
	if (!coverage) {
		return notMeasured('subdomain_coverage', 'no_subdomain_enumeration', [
			{ signal: 'SgeEvaluateOptions.subdomainCoverage', value: undefined },
		]);
	}

	const evidence: SgeEvidence[] = [
		{ signal: 'SgeSubdomainCoverage.enumeration', value: coverage.enumeration },
		{ signal: 'SgeSubdomainCoverage.source', value: coverage.source },
		{ signal: 'SgeSubdomainCoverage.observations.length', value: coverage.observations.length },
	];

	const uncovered = coverage.observations.filter(isMeasurablyUncovered);
	if (uncovered.length > 0) {
		evidence.push({ signal: 'subdomainsMeasurablyMissingRecords', value: nameList(uncovered) });
		return notSatisfied('subdomain_coverage', evidence);
	}

	if (coverage.enumeration !== 'complete') {
		return notMeasured('subdomain_coverage', 'subdomain_enumeration_incomplete', evidence);
	}

	const unmeasured = coverage.observations.filter((o) => !isFullyMeasuredAndCovered(o));
	if (unmeasured.length > 0) {
		evidence.push({ signal: 'subdomainsWithUnmeasuredRecords', value: nameList(unmeasured) });
		return notMeasured('subdomain_coverage', 'subdomain_records_not_measured', evidence);
	}

	// A complete enumeration with zero sub-domains satisfies "every sub-domain
	// publishes …" vacuously. The truth of `'complete'` is the caller's claim, the
	// same way `smtpTls` is — this module reports what it was told, structurally.
	return satisfied('subdomain_coverage', evidence);
}

/**
 * Is this sub-domain MEASURABLY missing one of the three records?
 *
 * `undefined` is never a miss — it is "not measured", and answering it as a miss
 * is the whole defect this control was designed around. Only an affirmative
 * `false`, or an SPF qualifier that was read and is not `-all`, counts.
 */
function isMeasurablyUncovered(o: SgeSubdomainObservation): boolean {
	return o.dmarcRecordPresent === false || o.dkimNullRecordPresent === false || (o.spfAll !== undefined && o.spfAll !== '-all');
}

/** Were all three records measured AND found compliant on this sub-domain? */
function isFullyMeasuredAndCovered(o: SgeSubdomainObservation): boolean {
	return o.dmarcRecordPresent === true && o.dkimNullRecordPresent === true && o.spfAll === '-all';
}

/**
 * Sub-domain names for an evidence value, bounded.
 *
 * Structural, like every other evidence value: it names WHICH sub-domains the
 * verdict came from so a reader can re-derive it. Capped so one evidence line
 * cannot become an unbounded dump of subject-supplied strings; the exact count
 * is already carried by its own signal.
 */
const EVIDENCE_NAME_LIMIT = 10;

function nameList(observations: readonly SgeSubdomainObservation[]): string {
	const shown = observations.slice(0, EVIDENCE_NAME_LIMIT).map((o) => o.name);
	const overflow = observations.length - shown.length;
	return overflow > 0 ? `${shown.join(', ')} (+${overflow} more)` : shown.join(', ');
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

/**
 * Enforcement strength, for comparing `sp=` against `p=`.
 *
 * Only the three real policy values are ranked. `not-specified` and `invalid`
 * are deliberately absent: neither is a weaker policy, and giving either a rank
 * would let an unstated or unparseable tag compare as though it had been
 * measured as permissive. Callers must handle them before comparing.
 */
const POLICY_STRENGTH: Partial<Record<DmarcPolicyValue, number>> = { none: 0, quarantine: 1, reject: 2 };

/**
 * The SGE subdomain exposure — the distinct finding the #991 ruling requires.
 *
 * THE RULING, verbatim: "`p=reject; sp=none` SATISFIES the SGE `dmarc_reject`
 * control. The real exposure is reported as a SEPARATE, distinct finding —
 * never by downgrading `dmarc_reject`." This function is that separate finding,
 * and it is the ONLY place the sp= signal is read.
 *
 * WHEN IT FIRES. The apex is enforcing AND `sp=` is published strictly weaker
 * than `p=`. Each conjunct earns its place:
 *
 * - APEX ENFORCING. A `p=none` domain already fails `dmarc_reject` outright;
 *   adding a subdomain advisory would report one absence of enforcement twice.
 * - `sp=` PUBLISHED. An ABSENT `sp=` is not a gap — RFC 9989 §4.7 has
 *   subdomains apply `p=` in that case — so `not-specified` never fires. This
 *   is why the signal keeps `not-specified` as a member distinct from `none`;
 *   collapsing them would manufacture this advisory on every well-configured
 *   apex-only record in existence.
 * - STRICTLY WEAKER. `sp=reject` under `p=quarantine` is stronger, not a gap.
 *
 * WHY np= DOES NOT RETRACT IT. RFC 9989 §4.7, verbatim: "If the 'np' tag is
 * absent, the policy specified by the 'sp' tag (if the 'sp' tag is present) or
 * the policy specified by the 'p' tag (if the 'sp' tag is not present) MUST be
 * applied for non-existent subdomains." So `np=reject` closes the NON-EXISTENT
 * half and nothing else; EXISTING subdomains stay on `sp=`. The evidence records
 * which half is mitigated rather than letting a partial mitigation silence the
 * whole advisory — which is also what the scorer does, downgrading its finding
 * to `low` under `np` while never withdrawing it.
 *
 * WHY IT IS NOT SGE'S FULL SUB-DOMAIN CONTROL. SGE explicitly refuses `sp` as
 * the mechanism ("This requirement remains even if the root level domain has
 * SP=reject set within its DMARC record") and demands an explicit `_dmarc`
 * record on EVERY sub-domain. That requirement is its own control —
 * {@link evaluateSubdomainCoverage}, added in bv-mcp #996 — and it reads a
 * caller-supplied enumeration, never this apex record. This advisory remains a
 * strictly narrower, fully-measurable statement about the apex record alone, and
 * is emitted independently of that control: it fires on a weaker `sp=` even when
 * no enumeration was supplied, and it is not an approximation of the control.
 */
function subdomainPolicyGap(dmarc: CheckResult | undefined): SgeAdvisory | undefined {
	if (!dmarc || !isCheckMeasured(dmarc.checkStatus)) return undefined;

	// On an inherited record the queried name IS the subdomain, so `sp=` describes
	// the name in hand rather than a gap beneath it.
	if (dmarcRecordInheritedFromParent(dmarc) !== false) return undefined;

	const policy = dmarcPolicyTag(dmarc);
	const sp = dmarcSubdomainPolicy(dmarc);
	if (policy === undefined || sp === undefined) return undefined;

	const apexStrength = POLICY_STRENGTH[policy];
	const spStrength = POLICY_STRENGTH[sp];
	// `not-specified` / `invalid` on either tag yields undefined here and stops.
	if (apexStrength === undefined || spStrength === undefined) return undefined;
	if (apexStrength === 0) return undefined; // p=none: a control failure, not a subdomain gap.
	if (spStrength >= apexStrength) return undefined;

	const np = dmarcNonExistentSubdomainPolicy(dmarc);
	const npMitigates = np === 'reject' || np === 'quarantine';

	return {
		id: 'subdomain_policy_gap',
		label: 'Subdomain DMARC policy weaker than the apex',
		severity: 'exposure',
		relatedControl: 'dmarc_reject',
		summary:
			`The apex enforces p=${policy}, but sp=${sp} applies to its existing subdomains. ` +
			'This does NOT affect the SGE DMARC control — RFC 9989 §4.7 confines sp= to subdomains and SGE requires only ' +
			'"DMARC needs to be set to p=reject on all email enabled domains" — but the subdomain tree is measurably unprotected. ' +
			(npMitigates
				? `np=${np} protects NON-EXISTENT subdomains; EXISTING subdomains remain on sp=${sp}.`
				: 'No np= tag is published, so under the RFC 9989 §4.7 np->sp->p fallback BOTH existing and non-existent subdomains are unenforced.') +
			' SGE does not accept sp= as the remedy in any case: it requires an explicit _dmarc record on every sub-domain.',
		evidence: [
			{ signal: 'dmarcPolicyTag()', value: policy },
			{ signal: 'dmarcSubdomainPolicy()', value: sp },
			{ signal: 'dmarcNonExistentSubdomainPolicy()', value: np },
			{ signal: 'npMitigatesNonExistentSubdomains', value: npMitigates },
		],
	};
}

/**
 * The `pct=` advisory.
 *
 * WHY IT LIVES HERE AND NOT AS A DMARC CHECK FINDING. Three reasons, in order
 * of weight:
 *
 * 1. It is a COMPLIANCE fact, not a security one. A `pct=100` record is not
 *    weaker than one with no `pct=` at all — receivers apply the policy to all
 *    mail either way. What makes it reportable is that RFC 9989 Appendix A.6
 *    ("Removal of the `pct` Tag") removed the tag from the specification and the
 *    DIA SGE Deployment Guide lists it among tags that should not be used. Both
 *    of those are SGE/spec-currency statements, and this module is the SGE
 *    surface.
 * 2. The security-relevant half is ALREADY reported by the check. The classifier
 *    flags `pct<100` as partial enforcement, which `dmarc_reject` reads through
 *    `findingsIndicatePartialEnforcement()` and turns into `not_satisfied`.
 *    A new finding would duplicate that for the only case that carries risk.
 * 3. Finding severities are SCORE-BEARING. Adding a finding to the classifier
 *    would move every scanned domain publishing `pct=` — an operator decision
 *    about re-grading customers, not a side effect of a compliance feature.
 *
 * Severity is `advisory`, never `exposure`: a removed tag is not an attack
 * surface.
 */
function pctTagPresent(dmarc: CheckResult | undefined): SgeAdvisory | undefined {
	if (!dmarc || !isCheckMeasured(dmarc.checkStatus)) return undefined;
	if (dmarcPctTagPresent(dmarc) !== true) return undefined;

	return {
		id: 'pct_tag_present',
		label: 'DMARC pct= tag published',
		severity: 'advisory',
		relatedControl: 'dmarc_reject',
		summary:
			'The DMARC record publishes a pct= tag. RFC 9989 Appendix A.6 ("Removal of the pct Tag") removes it from the ' +
			'specification, and the DIA SGE Deployment Guide lists it among tags that should not be used — including at ' +
			'pct=100, where it is redundant. Remove the tag. (A pct below 100 is a separate and more serious matter: it is ' +
			'partial enforcement, and the DMARC control reports it as NOT SATISFIED on its own.)',
		evidence: [{ signal: 'dmarcPctTagPresent()', value: true }],
	};
}

/**
 * All advisories, in `SGE_ADVISORY_IDS` order.
 *
 * Ordering is part of the contract for the same reason `SGE_CONTROL_IDS` is: a
 * consumer renders this as a list, and a reshuffle would silently reorder it.
 */
function evaluateAdvisories(dmarc: CheckResult | undefined): SgeAdvisory[] {
	const byId: Partial<Record<SgeAdvisoryId, SgeAdvisory | undefined>> = {
		subdomain_policy_gap: subdomainPolicyGap(dmarc),
		pct_tag_present: pctTagPresent(dmarc),
	};
	return SGE_ADVISORY_IDS.map((id) => byId[id]).filter((a): a is SgeAdvisory => a !== undefined);
}

function verdictFrom(controls: readonly SgeControlEvaluation[]): SgeVerdict {
	if (controls.some((c) => c.status === 'not_satisfied')) return 'non_compliant';
	if (controls.some((c) => c.status === 'not_measured')) return 'indeterminate';
	return 'compliant';
}

/**
 * Evaluate a domain against the seven NZ SGE controls.
 *
 * @param domain  The domain the results describe. Echoed back; never parsed.
 * @param results The check results to read. Extra categories are ignored and
 *                missing ones become `not_measured` / `check_absent` — a
 *                control is never dropped from the output.
 * @param options Observations this package cannot make itself: an SMTP transport
 *                observation, and a sub-domain enumeration. Each omitted member
 *                leaves its control `not_measured` — never `not_satisfied`.
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
		evaluateSubdomainCoverage(options),
	];

	// Order contract: the array above must match SGE_CONTROL_IDS exactly. Asserted
	// in the test suite rather than at runtime — a reordering is a source edit, not
	// a runtime condition.
	void SGE_CONTROL_IDS;

	return {
		domain,
		// Computed from the CONTROLS ALONE. Advisories are orthogonal by design: the
		// #991 ruling is that the subdomain exposure must never reach a control status,
		// and letting it reach the verdict would be the same downgrade one level up.
		verdict: verdictFrom(controls),
		mailTransport: transport,
		controls,
		advisories: evaluateAdvisories(byCategory(results, 'dmarc')),
		counts: {
			satisfied: controls.filter((c) => c.status === 'satisfied').length,
			notSatisfied: controls.filter((c) => c.status === 'not_satisfied').length,
			notMeasured: controls.filter((c) => c.status === 'not_measured').length,
		},
	};
}
