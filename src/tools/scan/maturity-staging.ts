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
	const sslCheck = byCategory.get('ssl');
	const dnssecCheck = byCategory.get('dnssec');
	const httpSecurityCheck = byCategory.get('http_security');
	const spfCheck = byCategory.get('spf');
	const dmarcCheck = byCategory.get('dmarc');

	const hasSsl = sslCheck?.passed ?? false;
	const hasDnssec = dnssecCheck?.passed ?? false;
	const hasHsts =
		httpSecurityCheck?.findings.some((f: Finding) => /HSTS/i.test(f.title) && !/missing|no HSTS|no\s+HSTS/i.test(f.title)) ?? false;
	// Anti-spoof posture: a published SPF -all (or restrictive include) + DMARC reject is
	// strong evidence even on a non-sending domain (defence against impersonation).
	const hasSpfRecord = spfCheck != null && !spfCheck.findings.some((f: Finding) => /No SPF record/i.test(f.title));
	const hasDmarcReject =
		dmarcCheck != null &&
		!dmarcCheck.findings.some((f: Finding) => /No DMARC record/i.test(f.title)) &&
		!dmarcCheck.findings.some((f: Finding) => /policy set to (none|quarantine)/i.test(f.title));
	const hasAntiSpoof = hasSpfRecord || hasDmarcReject;

	// Stage 4 — Comprehensive: SSL + DNSSEC + HSTS + anti-spoof email policy.
	// Anti-spoof (SPF -all / DMARC reject) is REQUIRED for the top tier. A no-MX domain
	// is still freely impersonated in the From: header without it, so infrastructure
	// hardening alone (TLS/DNSSEC/HSTS/CAA) does not make the posture "comprehensive".
	if (hasSsl && hasDnssec && hasHsts && hasAntiSpoof) {
		return {
			stage: 4,
			label: 'Comprehensive',
			description: 'This web-only domain has full transport (SSL), DNS integrity (DNSSEC), browser hardening (HSTS), and an anti-spoof email policy (SPF -all / DMARC reject).',
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
			description: 'This web-only domain has SSL, DNSSEC, and an anti-spoof email policy (SPF -all / DMARC reject). Strong defensive posture.',
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

	// Stage 0 — Unprotected
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
	const hasNoMx = mxCheck != null && mxCheck.findings.some((f: Finding) => f.title === 'No MX records found');
	if (hasNoMx && profile === undefined) {
		const hasDnssec = dnssecCheck?.passed ?? false;
		return {
			stage: hasDnssec ? 1 : 0,
			label: hasDnssec ? 'DNS-Only' : 'Unprotected',
			description: hasDnssec
				? 'This domain does not accept email. DNS security (DNSSEC) is in place.'
				: 'This domain does not accept email and has no DNSSEC.',
			nextStep: hasDnssec ? '' : 'Enable DNSSEC to protect DNS resolution integrity.',
		};
	}

	// Determine SPF presence
	const hasSpf = spfCheck != null && !spfCheck.findings.some((f: Finding) => /No SPF record/i.test(f.title));

	// Determine DMARC presence and policy
	const hasDmarc = dmarcCheck != null && !dmarcCheck.findings.some((f: Finding) => /No DMARC record/i.test(f.title));
	const dmarcPolicyNone = dmarcCheck?.findings.some((f: Finding) => /policy set to none/i.test(f.title)) ?? false;
	const dmarcPolicyQuarantine = dmarcCheck?.findings.some((f: Finding) => /policy set to quarantine/i.test(f.title)) ?? false;
	// reject = no "policy set to none" and no "policy set to quarantine" and DMARC exists
	const dmarcPolicyReject = hasDmarc && !dmarcPolicyNone && !dmarcPolicyQuarantine;
	const hasRua = dmarcCheck != null && !dmarcCheck.findings.some((f: Finding) => /No aggregate reporting/i.test(f.title));

	// Determine MTA-STS, DNSSEC, BIMI
	const hasMtaSts = mtaStsCheck?.passed ?? false;
	const hasDnssec = dnssecCheck?.passed ?? false;
	const hasBimi = bimiCheck?.findings.some((f: Finding) => /BIMI record configured/i.test(f.title)) ?? false;

	// DANE presence
	const daneCheck = byCategory.get('dane');
	const hasDane = daneCheck?.findings.some((f: Finding) => /DANE TLSA configured/i.test(f.title)) ?? false;

	// CAA presence (passed = CAA records found)
	const caaCheck = byCategory.get('caa');
	const hasCaa = caaCheck?.passed ?? false;

	// DKIM "discovered" = at least one selector physically found (not provider-implied)
	// Provider-implied findings have metadata.detectionMethod === 'provider-implied'
	const hasDkimDiscovered =
		dkimCheck != null &&
		!dkimCheck.findings.some((f: Finding) => /No DKIM records found|DKIM selector not discovered/i.test(f.title)) &&
		!dkimCheck.findings.some((f: Finding) => f.metadata?.detectionMethod === 'provider-implied');

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

	// Stage 0 — Unprotected
	return {
		stage: 0,
		label: 'Unprotected',
		description: 'No email authentication — any server can send email as this domain.',
		nextStep: 'Publish SPF and DMARC records to begin protecting your domain.',
	};
}
