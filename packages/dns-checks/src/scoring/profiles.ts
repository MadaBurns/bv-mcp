// SPDX-License-Identifier: BUSL-1.1

/**
 * Context-aware scoring profiles for scan_domain.
 *
 * Adapts importance weights based on detected domain purpose (mail-enabled,
 * enterprise mail, non-mail, web-only, minimal infrastructure).
 *
 * `auto` DOES apply the detected profile's own weights. `computeProfileAwareScanScore`
 * (engine.ts) calls `getProfileWeights(detectedProfile, config)` on the auto path exactly as
 * it does for an explicit profile — the two differ only in where the profile name came from
 * (detection vs. the caller). The former Phase-1 note here, that `auto` scored with
 * `mail_enabled` weights and only an explicit selection activated different ones, has been
 * stale since `587f1f81` ("align profile-aware DNS scoring policy", #334).
 *
 * {@link PROFILE_WEIGHTS} below is the SINGLE source of profile weight values;
 * `DEFAULT_SCORING_CONFIG.profileWeights` derives from it rather than restating it.
 */

import type { CheckCategory, CheckResult } from '../types';
import { isCheckMeasured } from './evidence';

export type DomainProfile = 'mail_enabled' | 'enterprise_mail' | 'non_mail' | 'web_only' | 'minimal' | 'authoritative_dns_infra';

export interface DomainContext {
	profile: DomainProfile;
	signals: string[];
	weights: Record<CheckCategory, ImportanceProfile>;
	detectedProvider: string | null;
}

export interface ImportanceProfile {
	importance: number;
}

/**
 * Per-profile importance weights.
 *
 * The tier section comments deliberately carry NO sum annotations: the engine normalizes
 * each tier by its ACTUAL weight sum, so the absolute total is not an invariant — and the
 * hand-maintained `(sum=N)` checksums that used to sit here had rotted in 4 of 6 profiles
 * (all stale by exactly the later-added dane_https+svcb_https weights) with no test
 * guarding them. A checksum that is usually wrong misleads the reviewer it exists to help.
 */
export const PROFILE_WEIGHTS: Record<DomainProfile, Record<CheckCategory, ImportanceProfile>> = {
	mail_enabled: {
		// Core
		spf: { importance: 10 },
		dmarc: { importance: 16 },
		dkim: { importance: 10 },
		dnssec: { importance: 10 },
		ssl: { importance: 8 },
		// Protective
		subdomain_takeover: { importance: 4 },
		http_security: { importance: 3 },
		mta_sts: { importance: 3 },
		subdomailing: { importance: 3 },
		mx: { importance: 2 },
		caa: { importance: 2 },
		// 2 → 3 with the lame-delegation CRITICAL escalation. A claimable stale delegation
		// is an authoritative-control defect, which is the weight class `web_only`/`non_mail`
		// already assign `ns` (both were ALREADY 3 and are deliberately left untouched — a
		// flat package-wide "2→3" would have double-bumped them).
		ns: { importance: 3 },
		lookalikes: { importance: 2 },
		shadow_domains: { importance: 2 },
		dane_https: { importance: 2 },
		svcb_https: { importance: 1 },
		// Hardening (all 0)
		dane: { importance: 0 },
		ptr: { importance: 0 },
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
		// Core
		spf: { importance: 10 },
		dmarc: { importance: 20 },
		dkim: { importance: 12 },
		dnssec: { importance: 13 },
		ssl: { importance: 8 },
		// Protective
		subdomain_takeover: { importance: 5 },
		http_security: { importance: 3 },
		mta_sts: { importance: 4 },
		subdomailing: { importance: 4 },
		mx: { importance: 2 },
		caa: { importance: 2 },
		// 2 → 3 with the lame-delegation CRITICAL escalation — see `mail_enabled`.
		ns: { importance: 3 },
		lookalikes: { importance: 2 },
		shadow_domains: { importance: 2 },
		dane_https: { importance: 2 },
		svcb_https: { importance: 1 },
		// Hardening (all 0)
		dane: { importance: 0 },
		ptr: { importance: 0 },
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
		// Core
		spf: { importance: 2 },
		dmarc: { importance: 3 },
		dkim: { importance: 2 },
		dnssec: { importance: 12 },
		ssl: { importance: 10 },
		// Protective
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
		ptr: { importance: 0 },
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
		// Core
		spf: { importance: 0 },
		dmarc: { importance: 0 },
		dkim: { importance: 0 },
		dnssec: { importance: 14 },
		ssl: { importance: 14 },
		// Protective
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
		ptr: { importance: 0 },
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
		// Core
		spf: { importance: 1 },
		dmarc: { importance: 1 },
		dkim: { importance: 1 },
		dnssec: { importance: 5 },
		ssl: { importance: 7 },
		// Protective
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
		ptr: { importance: 0 },
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
		ptr: { importance: 0 },
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
const ENTERPRISE_PROVIDERS = ['google workspace', 'microsoft 365', 'proofpoint', 'mimecast', 'barracuda'];

/**
 * Detect domain context from completed check results.
 * Pure function — reads findings metadata only, no DNS queries.
 */
export function detectDomainContext(results: CheckResult[]): DomainContext {
	const signals: string[] = [];

	// Profile selection may only read evidence from checks that were actually MEASURED.
	//
	// Every signal below is derived from `controlPresent`, and `controlPresent` is set by
	// a check that reached a conclusion. A check with `checkStatus` 'timeout'/'error'
	// (or any non-'completed' value from an unvalidated cache re-read) did NOT reach one,
	// yet its `controlPresent` was still being consulted — so a MEASUREMENT FAILURE could
	// select the weight table that then graded the domain.
	//
	// That is not hypothetical. It produced a fabricated ~88 on a domain that does not
	// exist (located 2026-08-02): with no MX, an errored `ssl` or `caa` still satisfied
	// `sslPass`/`caaPass` and selected `web_only` — the one profile that weights
	// spf/dmarc/dkim/mx at ZERO — so the four checks that correctly detected total
	// failure were weighted out of the score entirely.
	//
	// The failure-ratio signal further down already applied exactly this rule via
	// `measuredChecks`, for exactly this reason ("the measurement failure selected the
	// weight table that then graded the domain"). It was simply never applied to the
	// `controlPresent` reads. One filter now governs both, so they cannot drift again.
	const measuredChecks = results.filter((r) => isCheckMeasured(r.checkStatus));

	const mxResult = measuredChecks.find((r) => r.category === 'mx');
	const sslResult = measuredChecks.find((r) => r.category === 'ssl');
	const caaResult = measuredChecks.find((r) => r.category === 'caa');
	const dkimResult = measuredChecks.find((r) => r.category === 'dkim');
	const mtaStsResult = measuredChecks.find((r) => r.category === 'mta_sts');
	const bimiResult = measuredChecks.find((r) => r.category === 'bimi');
	const dmarcResult = measuredChecks.find((r) => r.category === 'dmarc');

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

	// Enterprise-maturity gate: DMARC is an ACTIVE anti-spoofing control only when enforcing
	// (check-dmarc sets controlPresent = p=quarantine|reject). Unlike DKIM — which Google Workspace
	// and M365 auto-provision, so provider+DKIM was nearly automatic — enforcement is a deliberate
	// policy choice. This is what gates the stricter enterprise_mail lens (was: any one of
	// DKIM/MTA-STS/BIMI present, which over-fired enterprise_mail on managed-provider SMB domains).
	const dmarcEnforcing = dmarcResult?.controlPresent === true;
	if (dmarcEnforcing) signals.push('DMARC enforcing');

	// Detect web indicators: reachable HTTPS / published CAA, again via controlPresent (a sparse
	// domain whose CAA is "absent-but-passed" must not read as web_only).
	const sslPass = sslResult?.controlPresent === true;
	const caaPass = caaResult?.controlPresent === true;
	if (sslPass) signals.push('SSL valid');
	if (caaPass) signals.push('CAA present');

	// Count failed checks over MEASURED checks only. A check whose execution failed
	// (checkStatus 'timeout'/'error', or any other non-'completed'/non-absent status) was NOT
	// measured, and counting it as "failed" let a transient DNS/fetch failure push failureRatio
	// past 0.5 and flip the domain to the `minimal` profile — i.e. the measurement failure
	// selected the weight table that then graded the domain. Excluding unmeasured checks from
	// BOTH numerator and denominator leaves genuine measured failures (what `minimal` was
	// designed for) behaving exactly as before, so a scan in which every check completed
	// produces an identical ratio, profile and score. Uses the shared `isCheckMeasured`
	// allowlist predicate (see evidence.ts) rather than a local denylist, so an out-of-union
	// `checkStatus` (reachable via an unvalidated cache re-read) is excluded here too.
	// `measuredChecks` is now computed once at the top of this function and shared with the
	// controlPresent reads — see the note there.
	const totalChecks = measuredChecks.length;
	const failedChecks = measuredChecks.filter((r) => !r.passed).length;
	const failureRatio = totalChecks > 0 ? failedChecks / totalChecks : 0;
	if (failureRatio > 0.5) signals.push(`>${Math.round(failureRatio * 100)}% of measured checks failed`);

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
	} else if (hasMx && hasEnterpriseProvider && dmarcEnforcing) {
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
