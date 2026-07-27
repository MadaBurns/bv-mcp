// SPDX-License-Identifier: BUSL-1.1

/**
 * Security Maturity Staging.
 *
 * Classifies a domain's security posture into a maturity stage (0-4). The
 * specific ladder depends on the scoring profile:
 *
 * - **mail-enabled** (and legacy default): email-centric ladder (SPF → DMARC
 *   monitoring → enforcement → hardened with transport/integrity signals).
 * - **web_only** (no MX): web-centric ladder. Web-only domains with strong
 *   web posture (SSL + HSTS + DNSSEC) but no email service should not be capped
 *   at "DNS-Only" just because they lack DKIM/MTA-STS — those don't apply.
 *
 * Defect I, cluster 3 (plan §5.3): the profile is now a first-class input.
 * Backward-compatibility: omitting `profile` yields the legacy mail-enabled
 * inference (including the historical "no-MX → DNS-Only" shortcut).
 */

import type { CheckResult, Finding } from '../../lib/scoring';
import type { DomainProfile } from '../../lib/scoring';

export interface MaturityStage {
	stage: number;
	label: string;
	description: string;
	nextStep: string;
	/**
	 * ADDITIVE-OPTIONAL (issue #574). `true` when the ladder could not determine a
	 * stage because a LOAD-BEARING input was never measured (its `checkStatus` is
	 * `'error'`/`'timeout'`, or the check is absent entirely). The `stage` number
	 * on such a result is a placeholder with NO measurement behind it, and the
	 * render layer (`format-report.ts`) withholds it exactly as it withholds the
	 * stage of an ungraded scan — the LABEL is kept, because "not determined" is
	 * information.
	 *
	 * Optional so every existing producer and consumer is unaffected; absent means
	 * "the stage is a measurement", which is what every pre-#574 result asserted
	 * implicitly.
	 */
	indeterminate?: true;
}

/**
 * Was this check actually MEASURED?
 *
 * The ladder used to read `passed` alone — but `scan-domain.ts` forcibly stamps
 * `score: 0, passed: false` onto every INCONCLUSIVE check (`degradedStatuses`),
 * so an edge-blocked probe was indistinguishable from a control that is
 * genuinely absent. That collapsed the two states the rest of the codebase works
 * hard to separate (`packages/dns-checks/src/scoring/evidence.ts`): INCONCLUSIVE
 * ("we could not measure it") vs NOT APPLICABLE / ABSENT ("we measured, and the
 * control is not there").
 *
 * `CheckStatus` is exactly `'completed' | 'timeout' | 'error'`, and an ABSENT
 * status means completed (legacy shape) — so those two values are the complete
 * set of inconclusive states.
 */
function measured(check?: CheckResult): boolean {
	return check != null && check.checkStatus !== 'error' && check.checkStatus !== 'timeout';
}

/**
 * Was this check ATTEMPTED and yet did not complete?
 *
 * Narrower than `!measured()`: it excludes a check that is simply absent from the
 * roster. Used only where an absent entry has a long-standing contracted meaning
 * that must not change (see the mail ladder's stage-0 abstention).
 */
function attemptedButInconclusive(check?: CheckResult): boolean {
	return check != null && (check.checkStatus === 'error' || check.checkStatus === 'timeout');
}

/**
 * Compute the email security maturity stage from scan check results.
 * Stages range from 0 (Unprotected) to 4 (Hardened).
 */
/**
 * Cap the maturity stage based on the overall scan score.
 * Prevents a domain from being labeled "Hardened" or "Enforcing"
 * when the actual security score indicates significant issues.
 *
 * - Score < 50 (F grade): cap at Stage 2 maximum
 * - Score < 63 (D/D+ grade): cap at Stage 3 maximum
 * - Score >= 63: no cap applied
 *
 * Stages already at or below the cap are returned unchanged.
 */
export function capMaturityStage(maturity: MaturityStage, score: number): MaturityStage {
	// A stage that was never DETERMINED cannot be score-capped — there is no
	// measurement to lower. Returning it untouched also stops the cap branches
	// below from dropping the `indeterminate` flag on the way out.
	if (maturity.indeterminate) return maturity;

	if (score < 50 && maturity.stage > 2) {
		return {
			stage: 2,
			label: 'Monitoring (score-capped)',
			description: 'Controls are present but the overall security score is too low for a higher maturity rating.',
			nextStep: 'Address critical and high-severity findings to improve the overall score before advancing maturity.',
		};
	}

	if (score < 63 && maturity.stage > 3) {
		return {
			stage: 3,
			label: 'Enforcing (score-capped)',
			description: 'Controls are present but the overall security score is too low for the highest maturity rating.',
			nextStep: 'Resolve remaining findings to raise the score above the D grade range and achieve full hardening.',
		};
	}

	return maturity;
}

/**
 * Web-only maturity ladder (no-MX domains with real web posture).
 *
 * Stages credit transport (SSL), DNS integrity (DNSSEC), browser hardening
 * (HSTS via http_security), and optional add-ons (CAA, anti-spoof SPF/DMARC).
 * Mail categories (DKIM, MTA-STS, BIMI, MX) are intentionally excluded — they
 * don't apply to a domain that doesn't accept email.
 */
function computeWebOnlyMaturity(checks: CheckResult[]): MaturityStage {
	const byCategory = new Map(checks.map((c) => [c.category, c]));
	const httpSecurityCheck = byCategory.get('http_security');
	const staged = computeWebOnlyLadder(byCategory);

	// Secondary instance of the same defect (issue #574 §"Silent ceiling"): HSTS is
	// read off `http_security` finding titles, so an inconclusive probe yields no
	// HSTS finding and stage 4 silently becomes unreachable. The stage below the
	// ceiling is still HONEST as a lower bound — it is derived from signals that
	// WERE measured — so the number stays; what was missing is the disclosure that
	// the top rung was never assessable.
	//
	// Gated on ATTEMPTED-but-inconclusive rather than `!measured`: a roster that
	// never included `http_security` has nothing to disclose, and every pre-existing
	// caller passing a partial check set keeps its exact wording.
	if (staged.indeterminate || staged.stage >= 4 || !attemptedButInconclusive(httpSecurityCheck)) return staged;
	return {
		...staged,
		description: `${staged.description} NOTE: the HTTP security probe did not complete, so HSTS could not be measured and the top maturity stage was not assessable — this stage is a lower bound.`,
		nextStep: `${staged.nextStep} Re-scan from an unblocked network to assess HSTS.`.trim(),
	};
}

/** The ladder proper. `computeWebOnlyMaturity` wraps it to add the unmeasured-HSTS disclosure. */
function computeWebOnlyLadder(byCategory: Map<string, CheckResult>): MaturityStage {
	const sslCheck = byCategory.get('ssl');
	const dnssecCheck = byCategory.get('dnssec');
	const httpSecurityCheck = byCategory.get('http_security');
	const spfCheck = byCategory.get('spf');
	const dmarcCheck = byCategory.get('dmarc');

	// Every signal is now gated on the check having been MEASURED. For the
	// `passed`-derived ones this is belt-and-braces (the pipeline already forces
	// `passed: false` on an inconclusive check); for the finding-title ones below
	// it is load-bearing, because an inconclusive check emits a "check error"
	// finding rather than the "No X record" finding those probes look for — so
	// they read TRUE and a measurement failure inflated maturity UPWARD.
	const sslMeasured = measured(sslCheck);
	const hasSsl = sslMeasured && (sslCheck?.passed ?? false);
	const hasDnssec = measured(dnssecCheck) && (dnssecCheck?.passed ?? false);
	const hasHsts =
		(measured(httpSecurityCheck) &&
			httpSecurityCheck?.findings.some((f: Finding) => /HSTS/i.test(f.title) && !/missing|no HSTS|no\s+HSTS/i.test(f.title))) ??
		false;
	// Anti-spoof posture: a published SPF -all (or restrictive include) + DMARC reject is
	// strong evidence even on a non-sending domain (defence against impersonation).
	const hasSpfRecord = measured(spfCheck) && !spfCheck!.findings.some((f: Finding) => /No SPF record/i.test(f.title));
	const hasDmarcReject =
		measured(dmarcCheck) &&
		!dmarcCheck!.findings.some((f: Finding) => /No DMARC record/i.test(f.title)) &&
		!dmarcCheck!.findings.some((f: Finding) => /policy set to (none|quarantine)/i.test(f.title));
	const hasAntiSpoof = hasSpfRecord || hasDmarcReject;

	// Stage 4 — Comprehensive: SSL + DNSSEC + HSTS + anti-spoof email policy.
	// Anti-spoof (SPF -all / DMARC reject) is REQUIRED for the top tier. A no-MX domain
	// is still freely impersonated in the From: header without it, so infrastructure
	// hardening alone (TLS/DNSSEC/HSTS/CAA) does not make the posture "comprehensive".
	if (hasSsl && hasDnssec && hasHsts && hasAntiSpoof) {
		return {
			stage: 4,
			label: 'Comprehensive',
			description:
				'This web-only domain has full transport (SSL), DNS integrity (DNSSEC), browser hardening (HSTS), and an anti-spoof email policy (SPF -all / DMARC reject).',
			nextStep: '',
		};
	}

	// Stage 3 — Defensive: SSL + DNSSEC + anti-spoof email policy.
	// Anti-spoof is required here too — a spoofable domain is not "defensive" no matter how
	// strong its transport/DNS hardening is. HSTS/CAA push toward Comprehensive (stage 4).
	if (hasSsl && hasDnssec && hasAntiSpoof) {
		return {
			stage: 3,
			label: 'Defensive',
			description:
				'This web-only domain has SSL, DNSSEC, and an anti-spoof email policy (SPF -all / DMARC reject). Strong defensive posture.',
			nextStep: 'Add HSTS preload and CAA pinning to reach full hardening.',
		};
	}

	// Stage 2 — Transport-Hardened: SSL plus a DNS/browser/anti-spoof control, but not a
	// complete defensive stack. Renamed from the former "Hardened" — that label both
	// overstated a mid-tier rung ("resists most passive attacks" for a domain that may be
	// fully spoofable) and COLLIDED with the mail ladder's Stage 4 "Hardened", so a
	// spoofable web-only domain displayed the same word as a protected mail domain.
	if (hasSsl && (hasDnssec || hasHsts || hasAntiSpoof)) {
		return {
			stage: 2,
			label: 'Transport-Hardened',
			description: hasAntiSpoof
				? 'Transport (TLS) plus an anti-spoof email policy (SPF -all / DMARC reject). Add DNSSEC and HSTS for full hardening.'
				: 'Transport (TLS) plus a DNS- or browser-hardening control. NOTE: without an anti-spoof email policy (SPF -all + DMARC reject) the domain name can still be impersonated in email, even though it sends no mail.',
			nextStep: hasAntiSpoof
				? 'Add DNSSEC and HSTS to reach a full defensive posture.'
				: 'Publish SPF (-all) and DMARC (p=reject) to block impersonation, then add DNSSEC and HSTS.',
		};
	}

	// Stage 1 — Basic: SSL present, nothing else
	if (hasSsl) {
		return {
			stage: 1,
			label: 'Basic',
			description: 'TLS is configured. No additional DNS or browser hardening detected.',
			nextStep: 'Enable DNSSEC and HSTS to layer protection above plain TLS.',
		};
	}

	// Not determined — the TLS probe was never measured (issue #574).
	//
	// This ladder is STRICTLY NESTED on `hasSsl`: rungs 4/3/2/1 are all gated on it,
	// so an unmeasured `ssl` is not "one signal missing", it is an unconditional
	// fallthrough to the bottom rung. And the bottom rung's description is an
	// affirmative, falsifiable factual claim published on a public report URL. When
	// an edge/CDN blocks or times out the HTTPS probe (22+ named consumer-banking
	// hosts in a single 2026-07-27 sweep) that claim is simply false: those hosts
	// demonstrably do serve TLS.
	//
	// The claim must therefore be UNREACHABLE without a TLS measurement — hence a
	// replacement, not an annotation. `capMaturityStage` cannot rescue this: it only
	// engages below score 63/50, and the affected hosts scored 67.
	if (!sslMeasured) {
		return {
			stage: 0,
			indeterminate: true,
			label: 'Not determined (TLS not measured)',
			description:
				'The TLS probe for this domain did not complete — it was blocked or timed out at the edge (a CDN or WAF commonly does this to automated clients). This is a measurement gap, NOT a security verdict: no conclusion about this domain’s transport security can be drawn from it, in either direction.',
			nextStep:
				'Re-scan later, or verify HTTPS directly from an unblocked network (for example `openssl s_client -connect <domain>:443`), before reading anything into this result.',
		};
	}

	// Stage 0 — Unprotected. Reachable only when the TLS probe COMPLETED and found
	// no usable HTTPS; that zero is a measurement.
	return {
		stage: 0,
		label: 'Unprotected',
		description: 'No TLS detected on this web-only domain. Traffic is not authenticated or encrypted.',
		nextStep: 'Configure HTTPS with a valid certificate before adding hardening layers.',
	};
}

export function computeMaturityStage(checks: CheckResult[], profile?: DomainProfile): MaturityStage {
	const byCategory = new Map(checks.map((c) => [c.category, c]));

	const mxCheck = byCategory.get('mx');
	const spfCheck = byCategory.get('spf');
	const dmarcCheck = byCategory.get('dmarc');
	const dkimCheck = byCategory.get('dkim');
	const mtaStsCheck = byCategory.get('mta_sts');
	const dnssecCheck = byCategory.get('dnssec');
	const bimiCheck = byCategory.get('bimi');

	// Profile-aware dispatch: explicit web_only domains use the web-only ladder.
	// Non_mail also routes through web-only — both share the "no mail service" shape.
	if (profile === 'web_only' || profile === 'non_mail') {
		return computeWebOnlyMaturity(checks);
	}

	// Non-mail domains should not receive email maturity stages.
	// The numeric stage values here (0 = "Unprotected", 1 = "DNS-Only") intentionally
	// reuse the same numbers as the mail-domain scale. This is safe because `stage` is
	// only ever rendered as a display value alongside `label` — it is never used as a
	// numeric index or compared against mail-domain stages in any downstream logic.
	//
	// Legacy fallback: when `profile` is undefined (older callers) and MX records are
	// missing, classify under the historical "DNS-Only" branch to preserve existing
	// behaviour and test coverage.
	const hasNoMx = measured(mxCheck) && mxCheck!.findings.some((f: Finding) => f.title === 'No MX records found');
	if (hasNoMx && profile === undefined) {
		const hasDnssec = measured(dnssecCheck) && (dnssecCheck?.passed ?? false);
		return {
			stage: hasDnssec ? 1 : 0,
			label: hasDnssec ? 'DNS-Only' : 'Unprotected',
			description: hasDnssec
				? 'This domain does not accept email. DNS security (DNSSEC) is in place.'
				: 'This domain does not accept email and has no DNSSEC.',
			nextStep: hasDnssec ? '' : 'Enable DNSSEC to protect DNS resolution integrity.',
		};
	}

	// Every presence probe below is gated on the check having been MEASURED (issue
	// #574). These are ABSENCE-OF-FINDING tests, which is the OPPOSITE polarity to
	// the web-only ladder's `hasSsl` and arguably worse: an inconclusive spf/dmarc/
	// dkim/bimi/dane emits a "check error" finding rather than the "No SPF record"
	// finding these probes look for, so they read TRUE and a measurement failure
	// inflated maturity UPWARD — false reassurance published as a posture verdict.
	// Determine SPF presence
	const hasSpf = measured(spfCheck) && !spfCheck!.findings.some((f: Finding) => /No SPF record/i.test(f.title));

	// Determine DMARC presence and policy
	const hasDmarc = measured(dmarcCheck) && !dmarcCheck!.findings.some((f: Finding) => /No DMARC record/i.test(f.title));
	const dmarcPolicyNone = dmarcCheck?.findings.some((f: Finding) => /policy set to none/i.test(f.title)) ?? false;
	const dmarcPolicyQuarantine = dmarcCheck?.findings.some((f: Finding) => /policy set to quarantine/i.test(f.title)) ?? false;
	// reject = no "policy set to none" and no "policy set to quarantine" and DMARC exists
	const dmarcPolicyReject = hasDmarc && !dmarcPolicyNone && !dmarcPolicyQuarantine;
	const hasRua = measured(dmarcCheck) && !dmarcCheck!.findings.some((f: Finding) => /No aggregate reporting/i.test(f.title));

	// Determine MTA-STS, DNSSEC, BIMI
	const hasMtaSts = measured(mtaStsCheck) && (mtaStsCheck?.passed ?? false);
	const hasDnssec = measured(dnssecCheck) && (dnssecCheck?.passed ?? false);
	const hasBimi = (measured(bimiCheck) && bimiCheck?.findings.some((f: Finding) => /BIMI record configured/i.test(f.title))) ?? false;

	// DANE presence
	const daneCheck = byCategory.get('dane');
	const hasDane = (measured(daneCheck) && daneCheck?.findings.some((f: Finding) => /DANE TLSA configured/i.test(f.title))) ?? false;

	// CAA presence (passed = CAA records found)
	const caaCheck = byCategory.get('caa');
	const hasCaa = measured(caaCheck) && (caaCheck?.passed ?? false);

	// DKIM "discovered" = at least one selector physically found (not provider-implied)
	// Provider-implied findings have metadata.detectionMethod === 'provider-implied'
	const hasDkimDiscovered =
		measured(dkimCheck) &&
		!dkimCheck!.findings.some((f: Finding) => /No DKIM records found|DKIM selector not discovered/i.test(f.title)) &&
		!dkimCheck!.findings.some((f: Finding) => f.metadata?.detectionMethod === 'provider-implied');

	// Stage 4 — Hardened: Stage 3 + at least 2 of (MTA-STS, DNSSEC, BIMI, DANE, CAA, DKIM-discovered)
	// AND at least one TRANSPORT/INTEGRITY signal: DNSSEC, MTA-STS, or DANE.
	//
	// Defect I (cluster 3): the 2026-05-28 fact-check showed a payments-platform domain
	// being labelled "Hardened" with only `CAA + DKIM-discovered = 2` hardening signals,
	// despite missing DNSSEC, MTA-STS, BIMI, and DANE. Both CAA and DKIM-discovery are
	// valuable but neither is a transport-encryption or DNS-integrity signal. Requiring
	// at least one of {DNSSEC, MTA-STS, DANE} keeps full-stack mail providers at stage 4
	// and drops the bare-DMARC-only stack to 3.
	// DKIM is no longer required for Stage 3 — enforcement alone (SPF + DMARC p=quarantine/reject) qualifies
	const isEnforcing = hasSpf && hasDmarc && (dmarcPolicyReject || dmarcPolicyQuarantine);
	const hardeningCount = [hasMtaSts, hasDnssec, hasBimi, hasDane, hasCaa, hasDkimDiscovered].filter(Boolean).length;
	const hasTransportOrIntegrityHardening = hasDnssec || hasMtaSts || hasDane;

	if (isEnforcing && hardeningCount >= 2 && hasTransportOrIntegrityHardening) {
		return {
			stage: 4,
			label: 'Hardened',
			description: 'Comprehensive email and DNS security posture with defense in depth.',
			nextStep: '',
		};
	}

	// Stage 3 — Enforcing: DMARC p=quarantine or p=reject, SPF exists, DKIM exists
	if (isEnforcing) {
		return {
			stage: 3,
			label: 'Enforcing',
			description: 'Email authentication is actively enforcing — spoofed emails are blocked or quarantined.',
			nextStep: 'Add MTA-STS, DNSSEC, and BIMI to reach full hardening.',
		};
	}

	// Stage 2 — Monitoring: SPF + DMARC with p=none and rua= present
	if (hasSpf && hasDmarc && dmarcPolicyNone && hasRua) {
		return {
			stage: 2,
			label: 'Monitoring',
			description: 'Email authentication is published and being monitored but not enforcing.',
			nextStep: 'After reviewing DMARC reports, move to p=quarantine and ensure DKIM is active.',
		};
	}

	// Stage 1 — Basic: SPF exists but DMARC is p=none or DMARC has no rua=
	if (hasSpf && hasDmarc) {
		return {
			stage: 1,
			label: 'Basic',
			description: 'Basic email records exist but are not enforcing or monitoring.',
			nextStep: 'Add DMARC aggregate reporting (rua=) and monitor for 2-4 weeks before enforcing.',
		};
	}

	// Not determined — an email-authentication probe was attempted and did not
	// complete (issue #574). Gating the presence probes on `measured()` above closes
	// the false-REASSURANCE path, but without this branch it would simply convert
	// that into a false ALARM: the bottom rung's description is the same class of
	// affirmative, falsifiable claim as the web-only ladder's "No TLS detected", and
	// an inconclusive spf or dmarc cannot support it. (A domain with a real
	// `p=reject` whose DMARC probe timed out would be told any server can send as
	// it.) The unmeasured input abstains at BOTH ends.
	//
	// Deliberately keyed on ATTEMPTED-but-inconclusive, not `!measured`: an ABSENT
	// spf/dmarc entry is the long-standing contracted meaning of this rung ("nothing
	// is published"), locked by `test/maturity-staging.spec.ts` — including the
	// empty-check-set case, which `format-report.ts` already withholds one layer up
	// via `isGraded`.
	if (attemptedButInconclusive(spfCheck) || attemptedButInconclusive(dmarcCheck)) {
		return {
			stage: 0,
			indeterminate: true,
			label: 'Not determined (email authentication not measured)',
			description:
				'The SPF and/or DMARC lookup for this domain did not complete, so its email-authentication posture could not be measured. This is a measurement gap, NOT a security verdict — no conclusion can be drawn from it in either direction.',
			nextStep: 'Re-scan later, or verify the SPF/DMARC TXT records directly, before reading anything into this result.',
		};
	}

	// Stage 0 — Unprotected. Reachable only when SPF/DMARC were measured.
	return {
		stage: 0,
		label: 'Unprotected',
		description: 'No email authentication — any server can send email as this domain.',
		nextStep: 'Publish SPF and DMARC records to begin protecting your domain.',
	};
}
