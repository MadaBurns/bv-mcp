// SPDX-License-Identifier: BUSL-1.1
//
// Pure DMARC scoring classifier — the single source of truth for DMARC findings,
// shared between bv-mcp's checkDMARC and bv-web's local DMARC check.
// Takes record-derived facts (no DNS I/O) and returns severity-tagged findings.

import type { Finding } from '../../types';
import { createFinding } from '../../check-utils';

/** Normalized, DNS-resolved facts about a domain's DMARC record. */
export interface DmarcFacts {
	/** Number of distinct `v=DMARC1` records found in the TXT RRset. */
	recordCount: number;
	/** Raw policy token from `p=` (may be invalid/unset). `null` when absent. */
	policy: string | null;
	/** The domain being checked, for interpolating into finding messages. Optional; falls back to a literal placeholder when absent. */
	domain?: string;
	/** Raw subdomain policy token from `sp=`. `undefined` when absent. */
	sp?: string;
	/** Raw non-existent-subdomain policy token from `np=` (DMARCbis). */
	np?: string;
	/** Raw `pct=` token (validated inside the classifier). `undefined` when absent. */
	pct?: string;
	/** Raw `ri=` token. `undefined` when absent. */
	ri?: string;
	/** Raw `fo=` token. `undefined` when absent. */
	fo?: string;
	/** Raw `rua=` token. `undefined` when absent. */
	rua?: string;
	/** Raw `ruf=` token. `undefined` when absent. */
	ruf?: string;
	/** Raw `adkim=` token. `undefined` when absent. */
	adkim?: string;
	/** Raw `aspf=` token. `undefined` when absent. */
	aspf?: string;
	/** Raw t= tag (DMARCbis test mode). 'y' = policy not enforced. */
	t?: string;
	/** True when this is a subdomain scan whose policy was inherited from an ancestor (caller-resolved tree-walk). Default false = organizational-domain scan. */
	inheritedFromParent?: boolean;
	/**
	 * The organizational domain's own `p=` token, on an inherited (subdomain) scan.
	 * Distinct from `policy`, which on such a scan is the *effective* policy (`sp` falling
	 * back to `p`). Lets the classifier report the parent-enforcing / subdomain-open
	 * asymmetry explicitly. `undefined` on organizational-domain scans.
	 */
	orgPolicy?: string;
	/** The ancestor name the DMARC record was actually found at, on an inherited scan. `undefined` on organizational-domain scans. */
	orgDomain?: string;
	/** Third-party aggregators in `rua=` (resolved by the caller). Empty when none. */
	aggregators?: string[];
	/** Invalid `rua=` URIs (resolved by the caller). Empty when none. */
	invalidRuaUris?: string[];
	/** Invalid `ruf=` URIs (resolved by the caller). Empty when none. */
	invalidRufUris?: string[];
}

/**
 * Produce the synchronous, record-derived DMARC findings. Pure — no DNS.
 * Cross-domain RUA-authorization findings (DNS-dependent) are appended by the
 * caller, not here.
 */
export function classifyDmarc(facts: DmarcFacts): Finding[] {
	const findings: Finding[] = [];

	if (facts.recordCount === 0) {
		findings.push(
			createFinding(
				'dmarc',
				'No DMARC record found',
				'high',
				`No DMARC record found at _dmarc.${facts.domain ?? '<domain>'}. Without DMARC, receivers cannot verify email authentication and spoofing is easier. (Escalated to critical by scan_domain when active lookalike/impersonation domains are detected.)`,
				// Declared, not accidental — same intent as the multiple-record and missing-p=
				// siblings below. Behaviour-neutral today: the static prose already zeroes via
				// scoreIndicatesMissingControl (pinned by missing-control-intent.audit.test.ts
				// assertion B); the flag makes the zeroing survive a reword of this sentence.
				{ missingControl: true },
			),
		);
		return findings;
	}

	// Multiple DMARC records = NO valid policy (RFC 9989: receivers ignore all and
	// apply no DMARC policy when more than one record is present). Treat as a missing
	// control (score 0), the same as no record — do NOT evaluate a "first" policy.
	if (facts.recordCount > 1) {
		findings.push(
			createFinding(
				'dmarc',
				'Multiple DMARC records — no valid policy',
				'high',
				`Found ${facts.recordCount} DMARC records at _dmarc.${facts.domain ?? '<domain>'}. Per RFC 9989, receivers treat more than one record as no DMARC policy at all — the domain is unprotected. Publish exactly one DMARC record.`,
				{ missingControl: true },
			),
		);
		return findings;
	}

	const validPolicies = new Set(['none', 'quarantine', 'reject']);

	// Check policy (p= tag)
	const policy = facts.policy ?? undefined;
	if (!policy) {
		findings.push(
			createFinding(
				'dmarc',
				'Missing DMARC policy',
				'critical',
				`DMARC record is missing the required "p=" tag. Without a policy, DMARC provides no protection.`,
				// Declared, not accidental. A record with no `p=` is a control that cannot be
				// evaluated by any receiver, so zeroing is correct — the same treatment the
				// no-record case (`:67`) and the multiple-record case (`:82`) already get.
				//
				// Today this flag is BEHAVIOURALLY INERT: `engine.ts` builds `missingControls`
				// from `scoreIndicatesMissingControl` alone and never reads `metadata`, and this
				// detail happens to contain both "missing" and "required", so the prose already
				// zeroes it. That accident is exactly the problem — reword the sentence and the
				// zeroing silently disappears. Declaring the intent here makes it survive a copy
				// edit and makes it legible if the engine ever starts reading the flag.
				{ missingControl: true },
			),
		);
	} else if (!validPolicies.has(policy)) {
		findings.push(
			createFinding(
				'dmarc',
				'Invalid DMARC policy value',
				'high',
				`DMARC policy value "${policy}" is invalid. Allowed values are none, quarantine, or reject.`,
				// `policy` is a raw token echoed from the scanned domain's OWN TXT record, so the
				// domain owner chooses this substring. Declared as subject data so it cannot arm
				// `scoreIndicatesMissingControl`: measured 2026-08-20, `p=missing` and `p=required`
				// dropped dmarc 50 → 0 while `p=bogus` stayed at 50. A single-label token is not
				// structurally distinguishable from prose, so the redactor cannot infer it — it has
				// to be declared here. See SUBJECT_TERMS_METADATA_KEY in scoring/model.ts.
				{ subjectTerms: [policy] },
			),
		);
	} else if (policy === 'none') {
		// Asymmetry case: a subdomain was scanned DIRECTLY, and the organizational domain it
		// inherits from is itself enforcing while handing this child `sp=none`. The effective
		// policy really is "none", so the severity and title are unchanged (both are load-bearing
		// downstream — the non-mail downgrade and the impersonation escalation match the title
		// exactly, and maturity staging / rollout planning match it by substring). Only the
		// DETAIL changes, and only to name the shape of the risk: the parent is locked down
		// while this specific child is wide open, which is precisely why it gets picked.
		const parentEnforcing = facts.inheritedFromParent === true && (facts.orgPolicy === 'quarantine' || facts.orgPolicy === 'reject');
		const self = facts.domain ?? '<domain>';
		const org = facts.orgDomain ?? 'the organizational domain';
		findings.push(
			createFinding(
				'dmarc',
				'DMARC policy set to none',
				'medium',
				parentEnforcing
					? `This subdomain has no DMARC enforcement: it publishes no DMARC record of its own and inherits sp=none from ${org}, whose own policy is "p=${facts.orgPolicy}". The enforcement is asymmetric — mail claiming to be from ${org} is rejected or quarantined, while mail claiming to be from ${self} is not, which is exactly why an attacker would pick the subdomain. Set sp=quarantine or sp=reject on ${org}, or publish a dedicated DMARC record at _dmarc.${self}. (Escalated to critical by scan_domain when active lookalike/impersonation domains are detected.)`
					: `DMARC policy is "none" which only monitors but does not reject or quarantine spoofed emails. Consider upgrading to "quarantine" or "reject". (Escalated to critical by scan_domain when active lookalike/impersonation domains are detected.)`,
			),
		);
	} else if (policy === 'quarantine') {
		findings.push(
			createFinding(
				'dmarc',
				'DMARC policy set to quarantine',
				'low',
				`DMARC policy is "quarantine". Consider upgrading to "reject" for maximum protection once you've verified legitimate email flows.`,
			),
		);
	}
	// "reject" is the strongest setting - no finding needed

	// DMARCbis (RFC 9989) test mode — t=y disables policy enforcement regardless of p=
	if (facts.t === 'y') {
		findings.push(
			createFinding(
				'dmarc',
				'DMARC in test mode (t=y)',
				'medium',
				'DMARC t=y (RFC 9989 DMARCbis test mode) disables policy enforcement — receivers honoring DMARCbis will not quarantine or reject. Remove t=y to activate the configured policy.',
			),
		);
	}

	// Check subdomain policy (sp= tag)
	const sp = facts.sp;
	// DMARCbis (RFC 9989) non-existent-subdomain policy. When `np=reject`/`np=quarantine`
	// is set, non-existent subdomain spoofing is explicitly protected — the practical risk
	// of `sp=none` is then limited to *existing* subdomains, which is a substantially
	// smaller surface than the "any unowned subdomain" risk without np=. We downgrade the
	// "Subdomain policy weaker than parent policy" finding accordingly.
	const np = facts.np;
	const npProtects = np === 'reject' || np === 'quarantine';
	if (!sp && policy === 'reject') {
		findings.push(
			createFinding(
				'dmarc',
				'No subdomain policy',
				'low',
				`No subdomain policy (sp=) specified. Subdomains inherit the main policy ("${policy}"), but explicitly setting sp= is recommended.`,
			),
		);
	} else if (!sp && policy === 'none') {
		findings.push(
			createFinding(
				'dmarc',
				'Subdomains inherit p=none policy',
				'info',
				'No subdomain policy (sp=) specified. Subdomains inherit the "none" policy, which provides no protection against spoofing.',
			),
		);
	} else if (sp) {
		if (!validPolicies.has(sp)) {
			findings.push(
				createFinding(
					'dmarc',
					'Invalid subdomain policy value',
					'medium',
					`DMARC subdomain policy value "${sp}" is invalid. Allowed values are none, quarantine, or reject.`,
				),
			);
		} else if (policy === 'none' && sp === 'none') {
			findings.push(
				createFinding(
					'dmarc',
					'Subdomain policy set to none',
					'info',
					'DMARC subdomain policy is set to "none" (sp=none), so subdomains have no enforcement against spoofing. Set sp=quarantine or sp=reject to enforce DMARC on subdomains.',
				),
			);
		} else if (policy === 'reject' && sp === 'none') {
			findings.push(
				createFinding(
					'dmarc',
					'Subdomain policy weaker than parent policy',
					npProtects ? 'low' : 'high',
					npProtects
						? `Subdomain policy is set to "none" while parent policy is "reject". Non-existent subdomains are still protected by DMARCbis np=${np}, so the residual risk is limited to existing subdomains.`
						: 'Subdomain policy is set to "none" while parent policy is "reject". This leaves subdomains vulnerable to spoofing.',
				),
			);
		} else if (policy === 'reject' && sp === 'quarantine') {
			findings.push(
				createFinding(
					'dmarc',
					'Subdomain policy weaker than parent policy',
					'low',
					'Subdomain policy is "quarantine" while parent policy is "reject". Consider using sp=reject for consistent enforcement.',
				),
			);
		} else if (policy === 'quarantine' && sp === 'none') {
			findings.push(
				createFinding(
					'dmarc',
					'Subdomain policy weaker than domain policy',
					'medium',
					'Subdomain policy is set to "none" while domain policy is "quarantine". Subdomains are unprotected against spoofing.',
				),
			);
		}
	}

	// DMARCbis (RFC 9989) np= non-existent-subdomain spoofability (org-domain scans only).
	// Distinct from the sp= finding above: sp= covers *existing* subdomains, np= covers
	// *non-existent* subdomains (e.g. payroll.example.com). They can legitimately co-occur.
	// Only fires when: this is an org-domain scan (not inherited), the domain enforces reject/
	// quarantine for known mail flows, AND np (or sp, or p as fallback) resolves to 'none'.
	// np=reject short-circuits the fallback chain — a domain with explicit np=reject is NOT flagged
	// even when sp=none.
	if (
		!facts.inheritedFromParent &&
		(facts.policy === 'reject' || facts.policy === 'quarantine') &&
		(facts.np ?? facts.sp ?? facts.policy) === 'none'
	) {
		findings.push(
			createFinding(
				'dmarc',
				'Non-existent subdomains spoofable (np=none)',
				'medium',
				'The organizational domain enforces DMARC but non-existent subdomains resolve to np=none, leaving them spoofable (e.g. payroll.example.com). Set np=reject to close this gap.',
			),
		);
	}

	// Check percentage (pct= tag)
	const pct = facts.pct;
	if (pct) {
		// RFC 7489 §6.3: pct is 1*3DIGIT. parseInt's prefix-parsing accepted "100%" /
		// "50abc" as valid; §6.6.3 has receivers discard syntactically invalid records, so
		// a malformed token is flagged, not charitably parsed. Leading zeros ("050") remain
		// ABNF-valid. (SCORING_MODEL_VERSION 1.13.0 — new detection on trailing-garbage
		// tokens; affected population unmeasured.)
		const pctValue = /^\d{1,3}$/.test(pct) ? Number.parseInt(pct, 10) : NaN;
		if (!Number.isFinite(pctValue) || pctValue > 100) {
			findings.push(
				createFinding(
					'dmarc',
					'Invalid DMARC percentage value',
					'medium',
					`DMARC pct value "${pct}" is invalid. Allowed range is 0-100.`,
				),
			);
		} else if (pctValue < 100) {
			findings.push(
				createFinding(
					'dmarc',
					'DMARC not applied to all emails',
					'medium',
					`DMARC pct=${pctValue} means the policy only applies to ${pctValue}% of emails. Set pct=100 for full coverage.`,
				),
			);
		}
	}

	// Check reporting interval (ri= tag) — RFC 7489 §6.3
	// Value must be a positive integer (> 0). Default is 86400 (24 hours).
	const ri = facts.ri;
	if (ri !== undefined) {
		// RFC 7489 §6.3: ri is 1*DIGIT — same strict-parse rationale as pct above
		// ("86400x" prefix-parsed to a valid 86400 and drew no finding).
		const riValue = /^\d+$/.test(ri) ? Number.parseInt(ri, 10) : NaN;
		if (!Number.isFinite(riValue) || riValue <= 0) {
			findings.push(
				createFinding(
					'dmarc',
					'Invalid DMARC reporting interval',
					'medium',
					`DMARC ri value "${ri}" is invalid. RFC 7489 §6.3 requires ri= to be a positive integer greater than zero. The default is 86400 (24 hours).`,
				),
			);
		}
	}

	// Check forensic failure reporting options (fo=)
	const fo = facts.fo;
	if (fo) {
		const allowedFoValues = new Set(['0', '1', 'd', 's']);
		const foValues = fo
			.split(':')
			.map((v) => v.trim())
			.filter((v) => v.length > 0);

		const invalidFo = foValues.filter((v) => !allowedFoValues.has(v));
		if (foValues.length === 0 || invalidFo.length > 0) {
			findings.push(
				createFinding(
					'dmarc',
					'Invalid DMARC failure reporting options',
					'medium',
					`DMARC fo value "${fo}" contains unsupported option(s): ${invalidFo.join(', ') || 'none'}. Allowed values: 0, 1, d, s.`,
				),
			);
		} else if (foValues.length === 1 && foValues[0] === '0') {
			findings.push(
				createFinding(
					'dmarc',
					'Limited DMARC failure reporting coverage',
					'low',
					'DMARC fo=0 only generates forensic reports when both SPF and DKIM fail. Consider fo=1 for broader failure visibility.',
				),
			);
		}
	}

	// Check for reporting (rua= tag)
	const rua = facts.rua;
	if (!rua) {
		findings.push(
			createFinding(
				'dmarc',
				'No aggregate reporting',
				'medium',
				`No aggregate report URI (rua=) specified. Without reporting, you cannot monitor DMARC authentication results.`,
			),
		);
	} else {
		// Validate rua= URI format (pre-resolved by caller)
		const invalidRuaUris = facts.invalidRuaUris ?? [];
		if (invalidRuaUris.length > 0) {
			findings.push(
				createFinding(
					'dmarc',
					'Invalid aggregate report URI format',
					'medium',
					`DMARC aggregate report URI(s) invalid: ${invalidRuaUris.join(', ')}. Must use mailto: scheme.`,
				),
			);
		}

		// Check for third-party aggregator services (pre-resolved by caller)
		const aggregators = facts.aggregators ?? [];
		if (aggregators.length > 0) {
			findings.push(
				createFinding(
					'dmarc',
					'Third-party DMARC aggregator detected',
					'info',
					`Using third-party aggregator(s): ${aggregators.join(', ')}. Ensure these services are authorized to receive your DMARC reports.`,
					{ aggregators },
				),
			);
		}

		// Cross-domain RUA authorization findings (DNS-dependent) are appended by the
		// caller, not here.
	}

	// Check forensic reporting (ruf= tag)
	const ruf = facts.ruf;
	if (ruf) {
		const invalidRufUris = facts.invalidRufUris ?? [];
		if (invalidRufUris.length > 0) {
			findings.push(
				createFinding(
					'dmarc',
					'Invalid forensic report URI format',
					'medium',
					`DMARC forensic report URI(s) invalid: ${invalidRufUris.join(', ')}. Must use mailto: scheme.`,
				),
			);
		}
	} else if (rua) {
		// rua= is present but ruf= is not
		findings.push(
			createFinding(
				'dmarc',
				'No forensic reporting configured (ruf= absent)',
				'low',
				'Aggregate reporting (rua=) is configured but forensic reporting (ruf=) is not. Forensic reports provide detailed failure information useful for troubleshooting.',
			),
		);
	}

	// Check DKIM alignment mode (adkim= tag)
	const adkim = facts.adkim;
	if (adkim && adkim !== 'r' && adkim !== 's') {
		findings.push(
			createFinding(
				'dmarc',
				'Invalid DKIM alignment mode',
				'medium',
				`DMARC adkim value "${adkim}" is invalid. Allowed values are "r" (relaxed) or "s" (strict).`,
			),
		);
	} else if (!adkim || adkim === 'r') {
		findings.push(
			createFinding(
				'dmarc',
				'Relaxed DKIM alignment',
				'low',
				`DKIM alignment mode is relaxed (adkim=r or unset). Consider adkim=s (strict) for stronger authentication.`,
			),
		);
	}

	// Check SPF alignment mode (aspf= tag)
	const aspf = facts.aspf;
	if (aspf && aspf !== 'r' && aspf !== 's') {
		findings.push(
			createFinding(
				'dmarc',
				'Invalid SPF alignment mode',
				'medium',
				`DMARC aspf value "${aspf}" is invalid. Allowed values are "r" (relaxed) or "s" (strict).`,
			),
		);
	} else if (!aspf || aspf === 'r') {
		// #842: this must stay ADVISORY (info, penalty 0) and must never revert to a bare
		// "consider aspf=s". The classifier receives only record-derived facts — no SPF
		// chain or sending-source inputs — so whether strict alignment is ACHIEVABLE
		// cannot be determined here. For any ESP-relayed domain (Resend, SendGrid,
		// Mailchimp, Postmark, SES with a custom MAIL FROM) the return-path sits on a
		// subdomain, so aspf=s fails SPF alignment on 100% of that traffic and deletes
		// one of DMARC's two authentication legs. Measured on our own production domain
		// (2026-08-30, 1,045 aggregate-report records): every ESP-sent message failed
		// SPF alignment under aspf=s, and 21 legitimate messages were rejected outright
		// on the occasions DKIM also failed. Title is load-bearing — assess-spoofability
		// matches 'Relaxed SPF alignment' by prefix.
		findings.push(
			createFinding(
				'dmarc',
				'Relaxed SPF alignment',
				'info',
				`SPF alignment mode is relaxed (aspf=r or unset). Strict alignment (aspf=s) only strengthens DMARC when every authorized sender's return-path (envelope-from) domain exactly matches the From domain — untrue for most ESP-relayed mail (e.g. Resend, SendGrid, Mailchimp, SES with a custom MAIL FROM), where the return-path sits on a subdomain: wherever the From domain differs from it (typically the apex), aspf=s fails SPF alignment for that traffic and leaves DKIM as the only authentication leg. Mail whose From address stays on that same subdomain still aligns under aspf=s. Set aspf=s only after DMARC aggregate reports confirm every sender's return-path domain exactly matches the From domain; otherwise aspf=r is the correct setting.`,
			),
		);
	}

	return findings;
}

/**
 * Append the "DMARC properly configured" reassurance finding when no
 * critical/high/medium finding is present. Apply this AFTER assembling the
 * complete finding set (synchronous classifier findings + any DNS-dependent
 * findings the caller adds), so it reflects the full picture. Mutates and
 * returns `findings`. `policy` is the resolved `p=` value (for the message).
 */
export function appendDmarcCleanInfo(findings: Finding[], policy: string | null): Finding[] {
	const hasSignificantIssues = findings.some(
		(f) => f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium',
	);
	if (!hasSignificantIssues) {
		findings.push(
			createFinding(
				'dmarc',
				'DMARC properly configured',
				'info',
				`DMARC record found with policy "${policy}" and valid core tags.`,
			),
		);
	}
	return findings;
}
