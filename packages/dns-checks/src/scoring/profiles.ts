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

export type DomainProfile = 'mail_enabled' | 'enterprise_mail' | 'non_mail' | 'web_only' | 'minimal' | 'authoritative_dns_infra';

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
		// Core (sum=54)
		spf: { importance: 10 },
		dmarc: { importance: 16 },
		dkim: { importance: 10 },
		dnssec: { importance: 10 },
		ssl: { importance: 8 },
		// Protective (sum=23)
		subdomain_takeover: { importance: 4 },
		http_security: { importance: 3 },
		mta_sts: { importance: 3 },
		subdomailing: { importance: 3 },
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
		brand_discovery: { importance: 0 },
		authoritative_dns_infra: { importance: 0 },
		dnskey_strength: { importance: 0 },
	},
	enterprise_mail: {
		// Core (sum=63)
		spf: { importance: 10 },
		dmarc: { importance: 20 },
		dkim: { importance: 12 },
		dnssec: { importance: 13 },
		ssl: { importance: 8 },
		// Protective (sum=26)
		subdomain_takeover: { importance: 5 },
		http_security: { importance: 3 },
		mta_sts: { importance: 4 },
		subdomailing: { importance: 4 },
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
		brand_discovery: { importance: 0 },
		authoritative_dns_infra: { importance: 0 },
		dnskey_strength: { importance: 0 },
	},
	non_mail: {
		// Core (sum=29)
		spf: { importance: 2 },
		dmarc: { importance: 3 },
		dkim: { importance: 2 },
		dnssec: { importance: 12 },
		ssl: { importance: 10 },
		// Protective (sum=25)
		subdomain_takeover: { importance: 6 },
		http_security: { importance: 6 },
		mta_sts: { importance: 1 },
		subdomailing: { importance: 1 },
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
		brand_discovery: { importance: 0 },
		authoritative_dns_infra: { importance: 0 },
		dnskey_strength: { importance: 0 },
	},
	web_only: {
		// Core (sum=28)
		spf: { importance: 0 },
		dmarc: { importance: 0 },
		dkim: { importance: 0 },
		dnssec: { importance: 14 },
		ssl: { importance: 14 },
		// Protective (sum=24)
		subdomain_takeover: { importance: 6 },
		http_security: { importance: 8 },
		mta_sts: { importance: 0 },
		subdomailing: { importance: 0 },
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
		brand_discovery: { importance: 0 },
		authoritative_dns_infra: { importance: 0 },
		dnskey_strength: { importance: 0 },
	},
	minimal: {
		// Core (sum=15)
		spf: { importance: 1 },
		dmarc: { importance: 1 },
		dkim: { importance: 1 },
		dnssec: { importance: 5 },
		ssl: { importance: 7 },
		// Protective (sum=11)
		subdomain_takeover: { importance: 2 },
		http_security: { importance: 2 },
		mta_sts: { importance: 1 },
		subdomailing: { importance: 1 },
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
		brand_discovery: { importance: 0 },
		authoritative_dns_infra: { importance: 0 },
		dnskey_strength: { importance: 0 },
	},
	authoritative_dns_infra: {
		// Core
		spf: { importance: 0 },
		dmarc: { importance: 0 },
		dkim: { importance: 0 },
		dnssec: { importance: 20 },
		ssl: { importance: 0 },
		authoritative_dns_infra: { importance: 40 },
		// Protective
		subdomain_takeover: { importance: 0 },
		http_security: { importance: 0 },
		mta_sts: { importance: 0 },
		subdomailing: { importance: 0 },
		mx: { importance: 0 },
		caa: { importance: 0 },
		ns: { importance: 15 },
		lookalikes: { importance: 0 },
		shadow_domains: { importance: 0 },
		dane_https: { importance: 0 },
		svcb_https: { importance: 0 },
		// Hardening
		dane: { importance: 0 },
		bimi: { importance: 0 },
		tlsrpt: { importance: 0 },
		txt_hygiene: { importance: 0 },
		mx_reputation: { importance: 0 },
		srv: { importance: 0 },
		zone_hygiene: { importance: 10 },
		brand_discovery: { importance: 0 },
		dnskey_strength: { importance: 0 },
	},
};

/** Which categories trigger the critical gap ceiling per profile. */
// DNSSEC added to all profiles per NIST SP 800-81r3 (mandatory control)
// DANE_HTTPS added to web/non-mail profiles (certificate integrity)
export const PROFILE_CRITICAL_CATEGORIES: Record<DomainProfile, CheckCategory[]> = {
	mail_enabled: ['spf', 'dmarc', 'dkim', 'ssl', 'dnssec', 'subdomain_takeover'],
	enterprise_mail: ['spf', 'dmarc', 'dkim', 'ssl', 'dnssec', 'subdomain_takeover'],
	non_mail: ['ssl', 'dnssec', 'http_security', 'subdomain_takeover', 'dane_https'],
	web_only: ['ssl', 'dnssec', 'http_security', 'subdomain_takeover', 'dane_https'],
	minimal: ['ssl', 'dnssec', 'subdomain_takeover'],
	authoritative_dns_infra: ['authoritative_dns_infra', 'dnssec', 'ns', 'zone_hygiene'],
};

/** Whether a profile is eligible for the email bonus. */
export const PROFILE_EMAIL_BONUS_ELIGIBLE: Record<DomainProfile, boolean> = {
	mail_enabled: true,
	enterprise_mail: true,
	non_mail: false,
	web_only: false,
	minimal: false,
	authoritative_dns_infra: false,
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

	// Detect MX presence from the structured controlPresent signal (set by check-mx), not finding
	// prose. true = real mail-routing MX; false = no MX or null MX (RFC 7505 → not a mail domain);
	// undefined = the MX lookup failed (status unknown → safe mail_enabled fallback below).
	const hasMx = mxResult?.controlPresent === true;
	const hasNoMx = mxResult?.controlPresent === false;
	const hasMxUnknown = mxResult ? mxResult.controlPresent === undefined : false;

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

	// Detect hardening signals from controlPresent (an active record was observed), not passed/prose.
	// A bare passed===true is true for absent-but-not-penalized controls (MTA-STS/BIMI on a non-mail
	// domain) and the old DKIM prose check counted revoked keys as present — both inflated
	// enterprise_mail. controlPresent is false for absent OR inactive (revoked DKIM, non-enforcing BIMI).
	const dkimPresent = dkimResult?.controlPresent === true;
	if (dkimPresent && hasMx) signals.push('DKIM present');

	const mtaStsPresent = mtaStsResult?.controlPresent === true;
	if (mtaStsPresent) signals.push('MTA-STS present');

	const bimiPresent = bimiResult?.controlPresent === true;
	if (bimiPresent) signals.push('BIMI present');

	const hasHardeningSignal = dkimPresent || mtaStsPresent || bimiPresent;

	// Detect web indicators: reachable HTTPS / published CAA, again via controlPresent (a sparse
	// domain whose CAA is "absent-but-passed" must not read as web_only).
	const sslPass = sslResult?.controlPresent === true;
	const caaPass = caaResult?.controlPresent === true;
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
