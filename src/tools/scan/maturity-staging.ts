// SPDX-License-Identifier: BUSL-1.1

/**
 * Email Security Maturity Staging.
 * Classifies a domain's email security posture into a maturity stage (0-4)
 * based on the results of individual DNS security checks.
 */

import type { CheckResult, Finding } from '../../lib/scoring';

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

export function computeMaturityStage(checks: CheckResult[]): MaturityStage {
	const byCategory = new Map(checks.map((c) => [c.category, c]));

	const mxCheck = byCategory.get('mx');
	const spfCheck = byCategory.get('spf');
	const dmarcCheck = byCategory.get('dmarc');
	const dkimCheck = byCategory.get('dkim');
	const mtaStsCheck = byCategory.get('mta_sts');
	const dnssecCheck = byCategory.get('dnssec');
	const bimiCheck = byCategory.get('bimi');

	// Non-mail domains should not receive email maturity stages.
	// The numeric stage values here (0 = "Unprotected", 1 = "DNS-Only") intentionally
	// reuse the same numbers as the mail-domain scale. This is safe because `stage` is
	// only ever rendered as a display value alongside `label` — it is never used as a
	// numeric index or compared against mail-domain stages in any downstream logic.
	const hasNoMx = mxCheck != null && mxCheck.findings.some((f: Finding) => f.title === 'No MX records found');
	if (hasNoMx) {
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
	// DKIM is no longer required for Stage 3 — enforcement alone (SPF + DMARC p=quarantine/reject) qualifies
	const isEnforcing = hasSpf && hasDmarc && (dmarcPolicyReject || dmarcPolicyQuarantine);
	const hardeningCount = [hasMtaSts, hasDnssec, hasBimi, hasDane, hasCaa, hasDkimDiscovered].filter(Boolean).length;

	if (isEnforcing && hardeningCount >= 2) {
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
