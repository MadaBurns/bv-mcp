// SPDX-License-Identifier: MIT

/**
 * Email Security Maturity Staging.
 * Classifies a domain's email security posture into a maturity stage (0-4)
 * based on the results of individual DNS security checks.
 */

import type { CheckResult } from '../../lib/scoring';

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
export function computeMaturityStage(checks: CheckResult[]): MaturityStage {
	const byCategory = new Map(checks.map((c) => [c.category, c]));

	const mxCheck = byCategory.get('mx');
	const spfCheck = byCategory.get('spf');
	const dmarcCheck = byCategory.get('dmarc');
	const dkimCheck = byCategory.get('dkim');
	const mtaStsCheck = byCategory.get('mta_sts');
	const dnssecCheck = byCategory.get('dnssec');
	const bimiCheck = byCategory.get('bimi');

	// Non-mail domains should not receive email maturity stages
	const hasNoMx = mxCheck != null && mxCheck.findings.some((f) => /No MX records found/i.test(f.title));
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
	const hasSpf = spfCheck != null && !spfCheck.findings.some((f) => /No SPF record/i.test(f.title));

	// Determine DMARC presence and policy
	const hasDmarc = dmarcCheck != null && !dmarcCheck.findings.some((f) => /No DMARC record/i.test(f.title));
	const dmarcPolicyNone = dmarcCheck?.findings.some((f) => /policy set to none/i.test(f.title)) ?? false;
	const dmarcPolicyQuarantine = dmarcCheck?.findings.some((f) => /policy set to quarantine/i.test(f.title)) ?? false;
	// reject = no "policy set to none" and no "policy set to quarantine" and DMARC exists
	const dmarcPolicyReject = hasDmarc && !dmarcPolicyNone && !dmarcPolicyQuarantine;
	const hasRua = dmarcCheck != null && !dmarcCheck.findings.some((f) => /No aggregate reporting/i.test(f.title));

	// Determine DKIM presence
	const hasDkim = dkimCheck != null && !dkimCheck.findings.some((f) => /No DKIM records found/i.test(f.title));

	// Determine MTA-STS, DNSSEC, BIMI
	const hasMtaSts = mtaStsCheck?.passed ?? false;
	const hasDnssec = dnssecCheck?.passed ?? false;
	const hasBimi = bimiCheck?.findings.some((f) => /BIMI record configured/i.test(f.title)) ?? false;

	// Stage 4 — Hardened: Stage 3 + at least 2 of (MTA-STS, DNSSEC, BIMI)
	const isEnforcing = hasSpf && hasDkim && hasDmarc && (dmarcPolicyReject || dmarcPolicyQuarantine);
	const hardeningCount = [hasMtaSts, hasDnssec, hasBimi].filter(Boolean).length;

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
