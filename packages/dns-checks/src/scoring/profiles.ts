// SPDX-License-Identifier: BUSL-1.1

/**
 * Context-aware scoring profiles for scan_domain.
 *
 * Adapts importance weights based on detected domain purpose (mail-enabled,
 * enterprise mail, non-mail, web-only, minimal infrastructure).
 *
 * Phase 1: Auto-detection runs and reports the detected profile in the
 * structured result, but `auto` uses `mail_enabled` weights (identical to
 * today). Only explicit profile selection activates different weights.
 */

import type { CheckCategory, CheckResult } from '../types';

export type DomainProfile = 'mail_enabled' | 'enterprise_mail' | 'non_mail' | 'web_only' | 'minimal';

export interface DomainContext {
	profile: DomainProfile;
	signals: string[];
	weights: Record<CheckCategory, ImportanceProfile>;
	detectedProvider: string | null;
}

interface ImportanceProfile {
	importance: number;
}

/** Per-profile importance weights. */
export const PROFILE_WEIGHTS: Record<DomainProfile, Record<CheckCategory, ImportanceProfile>> = {
	mail_enabled: {
		// Core (sum=52)
		spf: { importance: 10 },
		dmarc: { importance: 16 },
		dkim: { importance: 10 },
		dnssec: { importance: 8 },
		ssl: { importance: 8 },
		// Protective (sum=20)
		subdomain_takeover: { importance: 4 },
		http_security: { importance: 3 },
		mta_sts: { importance: 3 },
		mx: { importance: 2 },
		caa: { importance: 2 },
		ns: { importance: 2 },
		lookalikes: { importance: 2 },
		shadow_domains: { importance: 2 },
		dane_https: { importance: 2 },
		svcb_https: { importance: 1 },
		// Hardening (all 0)
		dane: { importance: 0 },
		bimi: { importance: 0 },
		tlsrpt: { importance: 0 },
		txt_hygiene: { importance: 0 },
		mx_reputation: { importance: 0 },
		srv: { importance: 0 },
		zone_hygiene: { importance: 0 },
	},
	enterprise_mail: {
		// Core (sum=58)
		spf: { importance: 10 },
		dmarc: { importance: 18 },
		dkim: { importance: 12 },
		dnssec: { importance: 10 },
		ssl: { importance: 8 },
		// Protective (sum=22)
		subdomain_takeover: { importance: 5 },
		http_security: { importance: 3 },
		mta_sts: { importance: 4 },
		mx: { importance: 2 },
		caa: { importance: 2 },
		ns: { importance: 2 },
		lookalikes: { importance: 2 },
		shadow_domains: { importance: 2 },
		dane_https: { importance: 2 },
		svcb_https: { importance: 1 },
		// Hardening (all 0)
		dane: { importance: 0 },
		bimi: { importance: 0 },
		tlsrpt: { importance: 0 },
		txt_hygiene: { importance: 0 },
		mx_reputation: { importance: 0 },
		srv: { importance: 0 },
		zone_hygiene: { importance: 0 },
	},
	non_mail: {
		// Core (sum=19)
		spf: { importance: 2 },
		dmarc: { importance: 2 },
		dkim: { importance: 1 },
		dnssec: { importance: 8 },
		ssl: { importance: 8 },
		// Protective (sum=24)
		subdomain_takeover: { importance: 6 },
		http_security: { importance: 6 },
		mta_sts: { importance: 1 },
		mx: { importance: 1 },
		caa: { importance: 3 },
		ns: { importance: 3 },
		lookalikes: { importance: 2 },
		shadow_domains: { importance: 2 },
		dane_https: { importance: 2 },
		svcb_https: { importance: 1 },
		// Hardening (all 0)
		dane: { importance: 0 },
		bimi: { importance: 0 },
		tlsrpt: { importance: 0 },
		txt_hygiene: { importance: 0 },
		mx_reputation: { importance: 0 },
		srv: { importance: 0 },
		zone_hygiene: { importance: 0 },
	},
	web_only: {
		// Core (sum=20)
		spf: { importance: 0 },
		dmarc: { importance: 0 },
		dkim: { importance: 0 },
		dnssec: { importance: 8 },
		ssl: { importance: 12 },
		// Protective (sum=24)
		subdomain_takeover: { importance: 6 },
		http_security: { importance: 8 },
		mta_sts: { importance: 0 },
		mx: { importance: 0 },
		caa: { importance: 3 },
		ns: { importance: 3 },
		lookalikes: { importance: 2 },
		shadow_domains: { importance: 2 },
		dane_https: { importance: 2 },
		svcb_https: { importance: 1 },
		// Hardening (all 0)
		dane: { importance: 0 },
		bimi: { importance: 0 },
		tlsrpt: { importance: 0 },
		txt_hygiene: { importance: 0 },
		mx_reputation: { importance: 0 },
		srv: { importance: 0 },
		zone_hygiene: { importance: 0 },
	},
	minimal: {
		// Core (sum=10)
		spf: { importance: 1 },
		dmarc: { importance: 1 },
		dkim: { importance: 1 },
		dnssec: { importance: 3 },
		ssl: { importance: 4 },
		// Protective (sum=10)
		subdomain_takeover: { importance: 2 },
		http_security: { importance: 2 },
		mta_sts: { importance: 1 },
		mx: { importance: 1 },
		caa: { importance: 1 },
		ns: { importance: 1 },
		lookalikes: { importance: 1 },
		shadow_domains: { importance: 1 },
		dane_https: { importance: 0 },
		svcb_https: { importance: 0 },
		// Hardening (all 0)
		dane: { importance: 0 },
		bimi: { importance: 0 },
		tlsrpt: { importance: 0 },
		txt_hygiene: { importance: 0 },
		mx_reputation: { importance: 0 },
		srv: { importance: 0 },
		zone_hygiene: { importance: 0 },
	},
};

/** Which categories trigger the critical gap ceiling per profile. */
// DNSSEC added to all profiles per NIST SP 800-81r3 (mandatory control)
// DANE_HTTPS added to web/non-mail profiles (certificate integrity)
export const PROFILE_CRITICAL_CATEGORIES: Record<DomainProfile, CheckCategory[]> = {
	mail_enabled: ['spf', 'dmarc', 'dkim', 'ssl', 'dnssec'],
	enterprise_mail: ['spf', 'dmarc', 'dkim', 'ssl', 'dnssec'],
	non_mail: ['ssl', 'dnssec', 'http_security', 'subdomain_takeover', 'dane_https'],
	web_only: ['ssl', 'dnssec', 'http_security', 'subdomain_takeover', 'dane_https'],
	minimal: ['ssl', 'dnssec'],
};

/** Whether a profile is eligible for the email bonus. */
export const PROFILE_EMAIL_BONUS_ELIGIBLE: Record<DomainProfile, boolean> = {
	mail_enabled: true,
	enterprise_mail: true,
	non_mail: false,
	web_only: false,
	minimal: false,
};

/** Known enterprise mail providers detected via MX record patterns. */
const ENTERPRISE_PROVIDERS = [
	'google workspace',
	'microsoft 365',
	'proofpoint',
	'mimecast',
	'barracuda',
];

/**
 * Detect domain context from completed check results.
 * Pure function — reads findings metadata only, no DNS queries.
 */
export function detectDomainContext(results: CheckResult[]): DomainContext {
	const signals: string[] = [];

	const mxResult = results.find((r) => r.category === 'mx');
	const sslResult = results.find((r) => r.category === 'ssl');
	const caaResult = results.find((r) => r.category === 'caa');
	const dkimResult = results.find((r) => r.category === 'dkim');
	const mtaStsResult = results.find((r) => r.category === 'mta_sts');
	const bimiResult = results.find((r) => r.category === 'bimi');

	// Detect MX presence
	const hasNoMx = mxResult
		? mxResult.findings.some((f) => {
				const title = f.title.toLowerCase();
				return title.includes('no mx records') || title.includes('null mx');
			})
		: false;
	const hasMxUnknown = mxResult
		? mxResult.findings.some((f) => f.title.toLowerCase().includes('dns query failed'))
		: false;
	const hasMx = mxResult && !hasNoMx && !hasMxUnknown;

	if (hasMx) signals.push('MX present');
	if (hasNoMx) signals.push('No MX records');
	if (hasMxUnknown) signals.push('MX status unknown');

	// Detect enterprise provider from MX findings
	let hasEnterpriseProvider = false;
	let detectedProviderName: string | null = null;
	if (mxResult) {
		for (const finding of mxResult.findings) {
			const text = `${finding.title} ${finding.detail}`.toLowerCase();
			const providerName = finding.metadata?.provider;
			const providerStr = typeof providerName === 'string' ? providerName.toLowerCase() : '';
			for (const provider of ENTERPRISE_PROVIDERS) {
				if (text.includes(provider) || providerStr.includes(provider)) {
					hasEnterpriseProvider = true;
					detectedProviderName = provider;
					signals.push(`${provider} provider`);
					break;
				}
			}
			if (hasEnterpriseProvider) break;
		}
	}

	// Detect hardening signals (DKIM present, MTA-STS present, BIMI present)
	const dkimPresent = dkimResult
		? !dkimResult.findings.some((f) => {
				const text = `${f.title} ${f.detail}`.toLowerCase();
				return /(no\s+dkim|not\s+found|missing)/.test(text) && f.severity !== 'info';
			})
		: false;
	if (dkimPresent && hasMx) signals.push('DKIM present');

	const mtaStsPresent = mtaStsResult ? mtaStsResult.passed : false;
	if (mtaStsPresent) signals.push('MTA-STS present');

	const bimiPresent = bimiResult ? bimiResult.passed : false;
	if (bimiPresent) signals.push('BIMI present');

	const hasHardeningSignal = dkimPresent || mtaStsPresent || bimiPresent;

	// Detect web indicators
	const sslPass = sslResult ? sslResult.passed : false;
	const caaPass = caaResult ? caaResult.passed : false;
	if (sslPass) signals.push('SSL valid');
	if (caaPass) signals.push('CAA present');

	// Count failed/timed-out checks
	const totalChecks = results.length;
	const failedChecks = results.filter((r) => !r.passed).length;
	const failureRatio = totalChecks > 0 ? failedChecks / totalChecks : 0;
	if (failureRatio > 0.5) signals.push(`>${Math.round(failureRatio * 100)}% checks failed`);

	// Detection priority
	let profile: DomainProfile;

	if (hasNoMx) {
		// Explicitly no MX (no records or null MX) → non-mail profiles
		if (caaPass || sslPass) {
			profile = 'web_only';
		} else {
			profile = 'non_mail';
		}
	} else if (hasMxUnknown || !hasMx) {
		// MX lookup failed or no MX result at all → default to mail_enabled (safe fallback)
		profile = 'mail_enabled';
	} else if (hasMx && hasEnterpriseProvider && hasHardeningSignal) {
		profile = 'enterprise_mail';
	} else {
		profile = 'mail_enabled';
	}

	// Override to minimal if most checks failed
	if (failureRatio > 0.5) {
		profile = 'minimal';
	}

	return {
		profile,
		signals,
		weights: PROFILE_WEIGHTS[profile],
		detectedProvider: detectedProviderName,
	};
}

/** Look up the weight table for a given profile, optionally from runtime config. */
export function getProfileWeights(
	profile: DomainProfile,
	config?: import('./config').ScoringConfig,
): Record<CheckCategory, ImportanceProfile> {
	if (config) {
		const flat = config.profileWeights[profile];
		const result = {} as Record<CheckCategory, ImportanceProfile>;
		for (const key of Object.keys(flat) as CheckCategory[]) {
			result[key] = { importance: flat[key] };
		}
		return result;
	}
	return PROFILE_WEIGHTS[profile];
}
