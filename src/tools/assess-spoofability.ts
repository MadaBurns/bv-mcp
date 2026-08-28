// SPDX-License-Identifier: BUSL-1.1

/**
 * Composite email spoofability score (0–100).
 *
 * Combines SPF enforcement, DMARC enforcement, and DKIM coverage with
 * interaction multipliers to produce a single spoofability metric.
 *
 * Higher score = more spoofable (worse).
 * 0 = fully protected, 100 = completely exposed.
 *
 * ## Abstention (the rule this tool used to break)
 *
 * A sub-score is emitted ONLY for a control that is both applicable to the domain
 * and actually measured. Otherwise it is `null` with a `status` saying which:
 *
 * - `not_applicable` — the control cannot exist for this domain (a domain that
 *   publishes an explicit SPF no-send policy has no outbound mail to sign, so
 *   "DKIM coverage" is not a thing it can have).
 * - `unmeasured` — the lookup did not complete, or the answer is inconclusive
 *   (DKIM selector probing finding nothing is NOT proof of absence — the same
 *   confidence rule `scoreIndicatesMissingControl` applies in the scan model).
 *
 * Before this, both states were scored as if measured: `example.com` (all 40
 * probed selectors revoked, null MX, `v=spf1 -all`) reported `dkimProtection:
 * 100` and "Domain has strong email authentication", while `scan_domain` put the
 * same domain's DKIM in `notApplicableCategories` with a null score.
 *
 * ## Alignment with the per-control checks
 *
 * A sub-score may never claim MORE protection than the underlying `check_*`
 * measured — {@link boundedByCheckScore} enforces that as a structural invariant.
 * `github.com` reported `dkimProtection: 80` on a day `check_dkim` scored the same
 * domain 45 (`passed: false`): two tools disagreeing about one control on one
 * domain. The bucketing that produced the 80 is gone; DKIM now reports the
 * check's own score, and the SPF/DMARC enforcement ladders (which are genuinely
 * spoofability-specific — DMARC `p=none` is near-worthless against spoofing yet
 * scores respectably as a published record) are clamped by it.
 *
 * The ladders read the checks' stable finding TITLES rather than substring-matching
 * remediation prose. The prose matching was itself a fabrication source: the
 * `+all` finding's own remediation text contains the string `-all`, so a domain
 * publishing `v=spf1 +all` — the most spoofable configuration there is — was
 * classified as hard-fail and reported `spfProtection: 100`.
 */

import type { OutputFormat } from '../handlers/tool-args';
import type { CheckResult, Finding } from '@blackveil/dns-checks/scoring';
import type { QueryDnsOptions } from '../lib/dns-types';
import { isCompletedCheck, UNGRADED_DISPLAY } from '../lib/ungraded-display';
import { checkSpf } from './check-spf';
import { checkDmarc } from './check-dmarc';
import { checkDkim } from './check-dkim';

/** Why a control carries (or does not carry) a sub-score. */
export type ProtectionStatus = 'measured' | 'not_applicable' | 'unmeasured';

/** One control's contribution to the composite. */
export interface ControlAssessment {
	/** 0–100 protection (higher = better protected), or `null` when `status !== 'measured'`. */
	score: number | null;
	status: ProtectionStatus;
	/** Human-readable reason. Present whenever `status !== 'measured'`. Safe to render verbatim. */
	reason?: string;
}

/** Spoofability assessment result. */
export interface SpoofabilityResult {
	domain: string;
	/**
	 * 0–100 composite (higher = more spoofable), or `null` when NOT ONE of the
	 * three controls could be measured (e.g. a total resolver outage). `null` is
	 * "not assessed", never a zero — see {@link SpoofabilityResult.evidenceInsufficient}.
	 */
	spoofabilityScore: number | null;
	/** `null` exactly when `spoofabilityScore` is null. */
	riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'minimal' | null;
	/** 0–100 protection, or `null` when the control is not applicable / not measurable. */
	spfProtection: number | null;
	dmarcProtection: number | null;
	dkimProtection: number | null;
	/** Per-control detail: the same three numbers plus WHY a null is null. */
	controls: { spf: ControlAssessment; dmarc: ControlAssessment; dkim: ControlAssessment };
	/** `true` when the domain publishes an explicit SPF no-send policy (`-all`, no authorized senders). */
	noSendPolicy: boolean;
	/** `true` when no control was measurable, so `spoofabilityScore` is null. */
	evidenceInsufficient: boolean;
	interactionEffects: string[];
	summary: string;
}

/**
 * Composite weights. Unchanged from the original model, and deliberately NOT part
 * of the scan grade: `assess_spoofability` is a standalone composite
 * (`scanIncluded: false`, no `tier`), so nothing here can move a domain's score.
 * When a control abstains its weight is REMOVED and the rest renormalized — the
 * same treatment `computeScanScore` gives an inconclusive category, rather than
 * scoring the absent evidence as a zero or a full mark.
 */
const CONTROL_WEIGHTS = { spf: 0.3, dmarc: 0.45, dkim: 0.25 } as const;

/** Clamp any check-derived number into the 0–100 band the sub-scores are defined on. */
function clampScore(value: number): number {
	if (!Number.isFinite(value)) return 0;
	return Math.max(0, Math.min(100, Math.round(value)));
}

/** Does any finding on this result have the given title (prefix match, case-insensitive)? */
function hasFindingTitled(result: CheckResult, prefix: string): boolean {
	const needle = prefix.toLowerCase();
	return result.findings.some((f: Finding) => f.title.toLowerCase().startsWith(needle));
}

/**
 * A spoofability sub-score may never exceed the protection the underlying check
 * actually measured.
 *
 * This is the invariant that makes the reported 45-vs-80 DKIM divergence
 * impossible by construction. It is one-directional on purpose: the ladders may
 * be HARSHER than the check (DMARC `p=none` is a published, well-formed record
 * that scores respectably yet stops almost no spoofing), never more generous.
 */
function boundedByCheckScore(ladderValue: number, result: CheckResult): number {
	return Math.min(clampScore(ladderValue), clampScore(result.score));
}

/** The effective `all` posture of an SPF record, derived from the check's stable finding titles. */
type SpfPosture = 'hard_fail' | 'soft_fail' | 'permissive' | 'no_all' | 'unusable';

function deriveSpfPosture(result: CheckResult): SpfPosture {
	// No record, or several (RFC 7208 §4.5: receivers PermError on >1 and apply no
	// SPF at all) — either way there is no usable sender policy.
	if (hasFindingTitled(result, 'No SPF record found') || hasFindingTitled(result, 'Multiple SPF records')) return 'unusable';
	// `Permissive SPF: +all` / `Permissive SPF: ?all` — every sender authorized.
	if (hasFindingTitled(result, 'Permissive SPF:')) return 'permissive';
	if (hasFindingTitled(result, 'SPF soft fail')) return 'soft_fail';
	if (hasFindingTitled(result, "No 'all' mechanism")) return 'no_all';
	// A record with neither a permissive/soft/absent `all` finding ends in `-all`
	// (the check emits no finding for the recommended setting) or delegates via
	// `redirect=`, whose target governs and which the check already scores.
	return 'hard_fail';
}

/** DMARC enforcement posture, derived from the classifier's stable finding titles. */
type DmarcPosture = 'reject' | 'quarantine' | 'none' | 'absent';

interface DmarcFactsFromFindings {
	posture: DmarcPosture;
	/** `t=y` (DMARCbis test mode) disables enforcement regardless of `p=`. */
	testMode: boolean;
	strictAlignment: boolean;
	aggregateReporting: boolean;
}

function deriveDmarcFacts(result: CheckResult): DmarcFactsFromFindings {
	const absent =
		hasFindingTitled(result, 'No DMARC record found') ||
		hasFindingTitled(result, 'Multiple DMARC records') ||
		hasFindingTitled(result, 'Missing DMARC policy') ||
		hasFindingTitled(result, 'Invalid DMARC policy value');

	// The classifier emits a finding for `none` and for `quarantine`, and none at
	// all for `reject` (the strongest setting) — so `reject` is the residue.
	const posture: DmarcPosture = absent
		? 'absent'
		: hasFindingTitled(result, 'DMARC policy set to none')
			? 'none'
			: hasFindingTitled(result, 'DMARC policy set to quarantine')
				? 'quarantine'
				: 'reject';

	return {
		posture,
		testMode: hasFindingTitled(result, 'DMARC in test mode'),
		// Strict alignment is the ABSENCE of the relaxed-mode findings, which the
		// classifier emits whenever `adkim`/`aspf` is `r` or unset.
		strictAlignment: !absent && !hasFindingTitled(result, 'Relaxed DKIM alignment') && !hasFindingTitled(result, 'Relaxed SPF alignment'),
		aggregateReporting: !absent && !hasFindingTitled(result, 'No aggregate reporting'),
	};
}

/** Assess SPF's contribution (0–100, higher = more protected). */
function assessSpf(result: CheckResult): ControlAssessment {
	if (!isCompletedCheck(result)) {
		return { score: null, status: 'unmeasured', reason: 'The SPF lookup did not complete, so SPF could not be assessed.' };
	}

	const posture = deriveSpfPosture(result);
	if (posture === 'unusable' || posture === 'permissive') {
		return { score: 0, status: 'measured' };
	}

	const hasTrustSurface = result.findings.some((f: Finding) => f.metadata?.trustSurface === true);
	const ladder = posture === 'no_all' ? 25 : posture === 'soft_fail' ? 50 : hasTrustSurface ? 75 : 100;

	return { score: boundedByCheckScore(ladder, result), status: 'measured' };
}

/** Assess DMARC's contribution (0–100, higher = more protected). */
function assessDmarc(result: CheckResult): ControlAssessment {
	if (!isCompletedCheck(result)) {
		return { score: null, status: 'unmeasured', reason: 'The DMARC lookup did not complete, so DMARC could not be assessed.' };
	}

	const facts = deriveDmarcFacts(result);
	if (facts.posture === 'absent') {
		return { score: 0, status: 'measured' };
	}

	// t=y disables enforcement whatever `p=` says, so an enforcing policy in test
	// mode buys no more than a monitoring policy does.
	const effective: DmarcPosture = facts.testMode ? 'none' : facts.posture;

	let ladder: number;
	if (effective === 'reject') ladder = facts.strictAlignment ? 100 : 85;
	else if (effective === 'quarantine') ladder = facts.strictAlignment ? 70 : 60;
	else ladder = facts.aggregateReporting ? 30 : 15;

	return { score: boundedByCheckScore(ladder, result), status: 'measured' };
}

/**
 * Assess DKIM's contribution (0–100, higher = more protected).
 *
 * Reports the check's OWN score when DKIM is both applicable and confirmed, and
 * abstains otherwise. The two abstention paths are the two halves of the reported
 * defect: a non-sending domain has no DKIM to have (`not_applicable`), and a
 * selector probe that found nothing has not established absence (`unmeasured`).
 */
function assessDkim(result: CheckResult, noSendPolicy: boolean): ControlAssessment {
	if (!isCompletedCheck(result)) {
		return { score: null, status: 'unmeasured', reason: 'The DKIM lookup did not complete, so DKIM could not be assessed.' };
	}

	const activeKey = result.controlPresent === true;

	// Selectors were DISCOVERED but none carries a usable key — every published
	// selector is revoked (empty `p=`), the documented posture of a domain that
	// deliberately does not sign. Two check-side shapes express it (#808):
	//
	// - `DKIM keys revoked (non-sending)` — the check's plural consolidation,
	//   which only fires for >1 discovered selector. This is the shape that
	//   originally reported 100.
	// - a singular `Revoked DKIM key: <selector>` with NO absence finding —
	//   exactly one discovered selector, revoked (google.com's real shape). This
	//   shape used to fall through to the hardcoded measured 0 below, scoring the
	//   same posture 0 that scan_domain scored 85.
	//
	// Title-matching here is interim: the structural fact ("selectors found, none
	// valid") is not exported on CheckResult — `controlPresent: false` conflates
	// "no selector found" with "found but revoked". Exporting it is deferred with
	// the check-side `> 1` consolidation cliff (an operator-gated scoring change).
	// The absence-finding guard keeps a mixed hypothetical (a revoked selector
	// recorded alongside a probe-miss absence claim) out of this branch.
	const revokedOnly =
		hasFindingTitled(result, 'DKIM keys revoked') ||
		(hasFindingTitled(result, 'Revoked DKIM key') && !hasFindingTitled(result, 'No DKIM records found'));
	if (!activeKey && revokedOnly) {
		return {
			score: null,
			status: 'not_applicable',
			reason:
				'Every published DKIM selector is revoked (empty p=) — the domain does not sign outbound mail, so DKIM coverage does not apply.',
		};
	}

	if (!activeKey && noSendPolicy) {
		return {
			score: null,
			status: 'not_applicable',
			reason: 'The domain publishes an SPF no-send policy and sends no mail, so there is no outbound mail for DKIM to sign.',
		};
	}

	// Selector probing is heuristic by construction — the check says so in the
	// finding's own metadata. "We tried the common names and found nothing" is not
	// the same claim as "there is no key", and the scan model already refuses to
	// treat it as one.
	const inconclusiveProbe = result.findings.some(
		(f: Finding) => f.metadata?.confidence === 'heuristic' && /no dkim records found|dkim selector not discovered/i.test(f.title),
	);
	if (!activeKey && inconclusiveProbe) {
		return {
			score: null,
			status: 'unmeasured',
			reason: 'Selector probing found no DKIM key. A custom selector may still exist, so DKIM presence is neither confirmed nor ruled out.',
		};
	}

	if (!activeKey) {
		return { score: 0, status: 'measured' };
	}

	return { score: clampScore(result.score), status: 'measured' };
}

/** Map spoofability score to risk level. */
function scoreToRiskLevel(score: number): 'critical' | 'high' | 'medium' | 'low' | 'minimal' {
	if (score >= 80) return 'critical';
	if (score >= 60) return 'high';
	if (score >= 40) return 'medium';
	if (score >= 20) return 'low';
	return 'minimal';
}

/** The caveat sentence naming every control excluded from the composite. */
function abstentionCaveat(controls: SpoofabilityResult['controls']): string {
	const parts: string[] = [];
	for (const [name, assessment] of Object.entries(controls) as Array<[string, ControlAssessment]>) {
		if (assessment.status === 'measured') continue;
		parts.push(`${name.toUpperCase()} (${assessment.status === 'not_applicable' ? 'not applicable' : UNGRADED_DISPLAY})`);
	}
	if (parts.length === 0) return '';
	return ` Excluded from this assessment: ${parts.join(', ')}.`;
}

/**
 * Generate a human-readable summary.
 *
 * The no-send branch exists because the band prose was actively wrong for the
 * domains that trip it: `example.com` — which cannot send mail at all — was
 * described as having "strong email authentication", a claim about a mail flow
 * that does not exist. A domain that publishes a no-send policy is described by
 * what it actually is.
 */
function generateSummary(
	domain: string,
	score: number | null,
	controls: SpoofabilityResult['controls'],
	noSendPolicy: boolean,
	dmarc: DmarcFactsFromFindings | null,
): string {
	if (score === null) {
		return `Email spoofability for ${domain} is ${UNGRADED_DISPLAY}: none of SPF, DMARC or DKIM could be measured, so no risk verdict is available.`;
	}

	const caveat = abstentionCaveat(controls);

	if (noSendPolicy) {
		const enforcing = dmarc !== null && !dmarc.testMode && (dmarc.posture === 'reject' || dmarc.posture === 'quarantine');
		const tail = enforcing
			? `DMARC (p=${dmarc?.posture}) instructs receivers to ${dmarc?.posture === 'reject' ? 'reject' : 'quarantine'} anything claiming to be from it, so both halves of the no-send posture are in place.`
			: 'DMARC does not enforce, so receivers that ignore SPF have no policy telling them to drop forged mail — publish DMARC p=reject to close that gap.';
		return `${domain} publishes an explicit SPF no-send policy (-all with no authorized senders) and sends no email. ${tail}${caveat}`;
	}

	let band: string;
	if (score <= 10) band = 'Measured email authentication is strong. Spoofing risk is minimal.';
	else if (score <= 30) band = 'Domain has good email authentication with minor gaps.';
	else if (score <= 50) band = 'Domain has moderate email authentication gaps that could be exploited.';
	else if (score <= 70) band = 'Domain has significant email authentication weaknesses. Spoofing is feasible.';
	else if (score <= 90) band = 'Domain is highly vulnerable to email spoofing. Critical protections are missing.';
	else band = 'Domain has no effective email spoofing protection. Any server can send as this domain.';

	return `${band}${caveat}`;
}

/**
 * Assess email spoofability for a domain.
 *
 * @param domain - Validated, sanitized domain
 * @param dnsOptions - Optional DNS query options
 * @returns Composite spoofability assessment
 */
export async function assessSpoofability(domain: string, dnsOptions?: QueryDnsOptions): Promise<SpoofabilityResult> {
	// Run the three email auth checks in parallel
	const [spfResult, dmarcResult, dkimResult] = await Promise.all([
		checkSpf(domain, dnsOptions),
		checkDmarc(domain, dnsOptions),
		checkDkim(domain, undefined, dnsOptions),
	]);

	// The same signal `scan_domain`'s post-processing uses to decide a domain is a
	// non-sender, read from the SPF check's own finding metadata rather than
	// re-derived here.
	const noSendPolicy = spfResult.findings.some((f: Finding) => f.metadata?.noSendPolicy === true);

	const spf = assessSpf(spfResult);
	const dmarcFacts = isCompletedCheck(dmarcResult) ? deriveDmarcFacts(dmarcResult) : null;
	const dmarc = assessDmarc(dmarcResult);
	const dkim = assessDkim(dkimResult, noSendPolicy);
	const controls = { spf, dmarc, dkim };

	// Weighted mean over the MEASURED controls only, renormalized — an abstaining
	// control neither drags the composite down (as a 0 would) nor props it up (as
	// the old full-marks DKIM did).
	let weighted = 0;
	let weightTotal = 0;
	for (const [name, assessment] of Object.entries(controls) as Array<[keyof typeof CONTROL_WEIGHTS, ControlAssessment]>) {
		if (assessment.status !== 'measured' || assessment.score === null) continue;
		weighted += assessment.score * CONTROL_WEIGHTS[name];
		weightTotal += CONTROL_WEIGHTS[name];
	}

	const interactionEffects: string[] = [];

	if (weightTotal === 0) {
		return {
			domain,
			spoofabilityScore: null,
			riskLevel: null,
			spfProtection: null,
			dmarcProtection: null,
			dkimProtection: null,
			controls,
			noSendPolicy,
			evidenceInsufficient: true,
			interactionEffects,
			summary: generateSummary(domain, null, controls, noSendPolicy, dmarcFacts),
		};
	}

	let spoofability = 100 - weighted / weightTotal;

	// Interaction multipliers. Every one is gated on the controls it reasons about
	// being MEASURED — an effect asserted over an abstaining control would be the
	// same fabrication in prose form.
	const spfScore = spf.status === 'measured' ? spf.score : null;
	const dmarcScore = dmarc.status === 'measured' ? dmarc.score : null;
	const dkimScore = dkim.status === 'measured' ? dkim.score : null;
	const dmarcNonEnforcing =
		dmarcFacts !== null && (dmarcFacts.posture === 'absent' || dmarcFacts.posture === 'none' || dmarcFacts.testMode);

	// Non-enforcing DMARC + SPF trust surface = amplified risk.
	// "Weak DMARC enforcement" was the wrong name for this: p=quarantine IS
	// enforcing everywhere else in the product (it is the BIMI eligibility bar, and
	// scan_domain emits a "DMARC enforcing" signal for it). The condition is now
	// stated over the policy itself rather than a numeric threshold that a clamped
	// quarantine score could slip under.
	if (dmarcNonEnforcing && spfScore !== null && spfScore > 0 && spfScore <= 75) {
		spoofability = Math.min(100, spoofability * 1.3);
		interactionEffects.push(
			'Non-enforcing DMARC (p=none, test mode, or no record) combined with SPF trust surface exposure amplifies spoofing risk.',
		);
	}

	// No DMARC + No SPF = complete exposure
	if (dmarcScore === 0 && spfScore === 0) {
		spoofability = Math.min(100, spoofability * 1.2);
		interactionEffects.push('Complete absence of both SPF and DMARC means any server can send as this domain.');
	}

	// Strong DMARC + Strong SPF = defense-in-depth bonus
	if (dmarcScore !== null && dmarcScore >= 85 && spfScore !== null && spfScore >= 75) {
		spoofability = Math.max(0, spoofability * 0.7);
		interactionEffects.push('Strong DMARC enforcement with SPF provides defense-in-depth against spoofing.');
	}

	// Missing DKIM weakens DMARC alignment — but only when DKIM was MEASURED as
	// absent. Previously this also fired for a domain with no mail flow at all.
	if (dkimScore === 0 && dmarcScore !== null && dmarcScore > 0) {
		spoofability = Math.min(100, spoofability + 5);
		interactionEffects.push('Missing DKIM weakens DMARC alignment — messages rely solely on SPF alignment.');
	}

	// Clamp to 0–100
	spoofability = Math.round(Math.max(0, Math.min(100, spoofability)));

	return {
		domain,
		spoofabilityScore: spoofability,
		riskLevel: scoreToRiskLevel(spoofability),
		spfProtection: spf.score,
		dmarcProtection: dmarc.score,
		dkimProtection: dkim.score,
		controls,
		noSendPolicy,
		evidenceInsufficient: false,
		interactionEffects,
		summary: generateSummary(domain, spoofability, controls, noSendPolicy, dmarcFacts),
	};
}

/** Render one sub-score, naming the abstention rather than printing `null/100`. */
function protectionDisplay(assessment: ControlAssessment): string {
	if (assessment.status === 'not_applicable') return 'not applicable';
	if (assessment.score === null) return UNGRADED_DISPLAY;
	return `${assessment.score}/100`;
}

/** Format spoofability result as human-readable text. */
export function formatSpoofability(result: SpoofabilityResult, format: OutputFormat = 'full'): string {
	const { spf, dmarc, dkim } = result.controls;
	const headline =
		result.spoofabilityScore === null || result.riskLevel === null
			? UNGRADED_DISPLAY
			: `${result.spoofabilityScore}/100 (${result.riskLevel.toUpperCase()} risk)`;
	const breakdown = `SPF: ${protectionDisplay(spf)} | DMARC: ${protectionDisplay(dmarc)} | DKIM: ${protectionDisplay(dkim)}`;

	if (format === 'compact') {
		return `Spoofability: ${result.domain} — ${headline}\n${breakdown}`;
	}

	const lines: string[] = [];

	lines.push(`# Email Spoofability Assessment: ${result.domain}`);
	lines.push(`Spoofability Score: ${headline}`);
	lines.push('');
	lines.push(result.summary);
	lines.push('');

	lines.push('## Protection Breakdown');
	lines.push(`  SPF Protection:   ${protectionDisplay(spf)}`);
	lines.push(`  DMARC Protection: ${protectionDisplay(dmarc)}`);
	lines.push(`  DKIM Protection:  ${protectionDisplay(dkim)}`);

	const reasons = (Object.entries(result.controls) as Array<[string, ControlAssessment]>).filter(([, a]) => a.reason);
	if (reasons.length > 0) {
		lines.push('');
		lines.push('## Not Scored');
		for (const [name, assessment] of reasons) {
			lines.push(`  - ${name.toUpperCase()}: ${assessment.reason}`);
		}
	}

	if (result.interactionEffects.length > 0) {
		lines.push('');
		lines.push('## Interaction Effects');
		for (const effect of result.interactionEffects) {
			lines.push(`  - ${effect}`);
		}
	}

	return lines.join('\n');
}
