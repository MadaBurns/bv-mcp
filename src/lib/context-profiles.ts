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

import type { CheckCategory, CheckResult } from './scoring-model';

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
		dmarc: { importance: 22 },
		dkim: { importance: 16 },
		spf: { importance: 10 },
		ssl: { importance: 5 },
		subdomain_takeover: { importance: 3 },
		dnssec: { importance: 2 },
		mta_sts: { importance: 2 },
		mx: { importance: 2 },
		tlsrpt: { importance: 1 },
		caa: { importance: 0 },
		ns: { importance: 0 },
		bimi: { importance: 0 },
		lookalikes: { importance: 0 },
		shadow_domains: { importance: 0 },
		txt_hygiene: { importance: 0 },
		http_security: { importance: 3 },
		dane: { importance: 1 },
		mx_reputation: { importance: 0 },
		srv: { importance: 0 },
		zone_hygiene: { importance: 0 },
	},
	enterprise_mail: {
		dmarc: { importance: 24 },
		dkim: { importance: 18 },
		spf: { importance: 12 },
		ssl: { importance: 5 },
		subdomain_takeover: { importance: 3 },
		dnssec: { importance: 3 },
		mta_sts: { importance: 4 },
		mx: { importance: 2 },
		tlsrpt: { importance: 2 },
		caa: { importance: 0 },
		ns: { importance: 0 },
		bimi: { importance: 1 },
		lookalikes: { importance: 0 },
		shadow_domains: { importance: 0 },
		txt_hygiene: { importance: 0 },
		http_security: { importance: 3 },
		dane: { importance: 2 },
		mx_reputation: { importance: 0 },
		srv: { importance: 0 },
		zone_hygiene: { importance: 0 },
	},
	non_mail: {
		ssl: { importance: 8 },
		subdomain_takeover: { importance: 5 },
		dnssec: { importance: 5 },
		caa: { importance: 3 },
		dmarc: { importance: 2 },
		ns: { importance: 2 },
		dkim: { importance: 1 },
		spf: { importance: 1 },
		mx: { importance: 0 },
		mta_sts: { importance: 0 },
		tlsrpt: { importance: 0 },
		bimi: { importance: 0 },
		lookalikes: { importance: 0 },
		shadow_domains: { importance: 0 },
		txt_hygiene: { importance: 0 },
		http_security: { importance: 5 },
		dane: { importance: 0 },
		mx_reputation: { importance: 0 },
		srv: { importance: 0 },
		zone_hygiene: { importance: 0 },
	},
	web_only: {
		ssl: { importance: 12 },
		subdomain_takeover: { importance: 5 },
		dnssec: { importance: 5 },
		caa: { importance: 5 },
		dmarc: { importance: 2 },
		ns: { importance: 2 },
		dkim: { importance: 1 },
		spf: { importance: 1 },
		mx: { importance: 0 },
		mta_sts: { importance: 0 },
		tlsrpt: { importance: 0 },
		bimi: { importance: 0 },
		lookalikes: { importance: 0 },
		shadow_domains: { importance: 0 },
		txt_hygiene: { importance: 0 },
		http_security: { importance: 5 },
		dane: { importance: 0 },
		mx_reputation: { importance: 0 },
		srv: { importance: 0 },
		zone_hygiene: { importance: 0 },
	},
	minimal: {
		dmarc: { importance: 5 },
		ssl: { importance: 5 },
		dnssec: { importance: 5 },
		dkim: { importance: 3 },
		spf: { importance: 3 },
		subdomain_takeover: { importance: 3 },
		ns: { importance: 2 },
		mx: { importance: 1 },
		caa: { importance: 1 },
		mta_sts: { importance: 0 },
		tlsrpt: { importance: 0 },
		bimi: { importance: 0 },
		lookalikes: { importance: 0 },
		shadow_domains: { importance: 0 },
		txt_hygiene: { importance: 0 },
		http_security: { importance: 2 },
		dane: { importance: 0 },
		mx_reputation: { importance: 0 },
		srv: { importance: 0 },
		zone_hygiene: { importance: 0 },
	},
};

/** Which categories trigger the critical gap ceiling per profile. */
export const PROFILE_CRITICAL_CATEGORIES: Record<DomainProfile, CheckCategory[]> = {
	mail_enabled: ['spf', 'dmarc', 'dkim', 'ssl', 'subdomain_takeover'],
	enterprise_mail: ['spf', 'dmarc', 'dkim', 'ssl', 'subdomain_takeover'],
	non_mail: ['ssl', 'subdomain_takeover', 'http_security'],
	web_only: ['ssl', 'subdomain_takeover', 'http_security'],
	minimal: ['ssl', 'subdomain_takeover'],
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
	config?: import('./scoring-config').ScoringConfig,
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
