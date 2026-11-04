// SPDX-License-Identifier: BUSL-1.1

/**
 * Scoring model 2.0.0 (US-17 B1): the binary hardening tier is retired, its categories are
 * weighted protective members, and the email bonus and the -15 overall penalty default to 0.
 *
 * These assertions pin the five properties that must survive the move:
 *   1. no divisor dilution - extra roster checks move a score only through explicit weights;
 *   2. cross-roster parity - the MCP's two extra checks (ptr, dnskey_strength) cannot change
 *      a mail-profile score relative to the web product's 17-check roster;
 *   3. a verified missing DMARC control still caps at 64 with the penalty at 0;
 *   4. a wholly unmeasured former-hardening set yields no NaN and forfeits nothing;
 *   5. an explicit ScoringConfig override still applies, and ungraded stays null.
 */

import { describe, expect, it } from 'vitest';
import { checkDMARC } from '../../checks/check-dmarc';
import {
	DEFAULT_SCORING_CONFIG,
	buildCheckResult,
	computeProfileAwareScanScore,
	computeScanScore,
	createFinding,
	type DomainProfile,
} from '../../scoring';
import type { CheckCategory, CheckResult, DNSQueryFunction } from '../../types';

const FORMER_HARDENING: CheckCategory[] = [
	'dane',
	'ptr',
	'bimi',
	'tlsrpt',
	'txt_hygiene',
	'mx_reputation',
	'srv',
	'zone_hygiene',
	'brand_discovery',
	'dnskey_strength',
];

/** The web product's 17-category roster (no ptr, no dnskey_strength). */
const WEB_17: CheckCategory[] = [
	'spf',
	'dmarc',
	'dkim',
	'dnssec',
	'ssl',
	'mta_sts',
	'ns',
	'caa',
	'subdomain_takeover',
	'mx',
	'http_security',
	'dane_https',
	'svcb_https',
	'subdomailing',
	'dane',
	'bimi',
	'tlsrpt',
];

function passing(category: CheckCategory): CheckResult {
	return buildCheckResult(category, [createFinding(category, `${category} OK`, 'info', 'Check passed')], true);
}

function failing(category: CheckCategory): CheckResult {
	return { ...buildCheckResult(category, [createFinding(category, `${category} weak`, 'high', 'Control is weak')], false), score: 0, passed: false };
}

function errored(category: CheckCategory): CheckResult {
	return { ...failing(category), checkStatus: 'error', partial: true, passed: false, score: 0 };
}

function web17(overrides: Partial<Record<CheckCategory, CheckResult>> = {}): CheckResult[] {
	return WEB_17.map((category) => overrides[category] ?? passing(category));
}

function overallFor(results: CheckResult[], profile: DomainProfile): number {
	const { score } = computeProfileAwareScanScore(results, { profile });
	if (score.overall === null) throw new Error(`fixture ungraded: ${score.summary}`);
	return score.overall;
}

describe('2.0.0 no divisor dilution (acceptance 1)', () => {
	it('the same pass/fail states submitted as 5 vs 3 former-hardening keys differ only by explicit weights', () => {
		// non_mail weighs every former-hardening category 0: failing two extra keys must be a no-op.
		// Under the retired binary tier every extra failing key re-divided the 10 hardening points.
		const three = [...web17().filter((r) => !['dane', 'bimi', 'tlsrpt'].includes(r.category)), passing('dane'), passing('bimi'), failing('tlsrpt')];
		const five = [...three, failing('ptr'), failing('dnskey_strength')];
		for (const profile of ['non_mail', 'web_only', 'minimal'] as const) {
			expect(overallFor(five, profile)).toBe(overallFor(three, profile));
		}
	});

	it('a weighted key (tlsrpt 2 in a mail profile) does move the score when measured failing', () => {
		const pass = overallFor(web17(), 'mail_enabled');
		const fail = overallFor(web17({ tlsrpt: failing('tlsrpt') }), 'mail_enabled');
		expect(fail).toBeLessThan(pass);
	});
});

describe('2.0.0 cross-roster parity (acceptance 2)', () => {
	it('mail profiles: 17 results score identically with and without ptr + dnskey_strength, whatever their state', () => {
		for (const profile of ['mail_enabled', 'enterprise_mail'] as const) {
			for (const roster of [web17(), web17({ dane: failing('dane'), tlsrpt: failing('tlsrpt') })]) {
				const base = overallFor(roster, profile);
				expect(overallFor([...roster, passing('ptr'), passing('dnskey_strength')], profile)).toBe(base);
				expect(overallFor([...roster, failing('ptr'), failing('dnskey_strength')], profile)).toBe(base);
				expect(overallFor([...roster, errored('ptr'), errored('dnskey_strength')], profile)).toBe(base);
			}
		}
	});
});

describe('2.0.0 missing DMARC ceiling still arms with the penalty at 0 (acceptance 3)', () => {
	const noDmarcDns: DNSQueryFunction = async () => [];

	it('a verified missing DMARC control caps a mail-profile scan at 64', async () => {
		const missing = await checkDMARC('victim.example', noDmarcDns);
		const roster = web17({ dmarc: missing });
		const { score } = computeProfileAwareScanScore(roster, { profile: 'mail_enabled' });
		expect(score.criticalGaps).toContain('dmarc');
		expect(score.overall).not.toBeNull();
		expect(score.overall!).toBeLessThanOrEqual(64);
		expect(DEFAULT_SCORING_CONFIG.thresholds.criticalOverallPenalty).toBe(0);
	});
});

describe('2.0.0 wholly unmeasured former-hardening set (acceptance 4)', () => {
	it('produces no NaN and forfeits no points: renormalises over the measured categories', () => {
		// The web roster's whole former-hardening subset (dane, bimi, tlsrpt) is unmeasured. Submitting
		// all ten would trip the evidence-sufficiency abstention (ungraded), which is a different gate.
		const unmeasured = WEB_17.filter((c) => FORMER_HARDENING.includes(c));
		expect(unmeasured).toEqual(['dane', 'bimi', 'tlsrpt']);
		const core = WEB_17.filter((c) => !FORMER_HARDENING.includes(c)).map(passing);
		const withAllErrored = [...core, ...unmeasured.map(errored)];
		for (const profile of ['mail_enabled', 'non_mail', 'authoritative_dns_infra'] as const) {
			const { score } = computeProfileAwareScanScore(withAllErrored, { profile });
			expect(score.overall).not.toBeNull();
			expect(Number.isNaN(score.overall)).toBe(false);
			expect(Number.isNaN(score.tierBreakdown?.protective)).toBe(false);
			// The same scan with the set simply omitted scores the same: nothing is forfeited.
			expect(score.overall).toBe(computeProfileAwareScanScore(core, { profile }).score.overall);
		}
		// All else perfect in a mail profile: the unmeasured set costs nothing against 100.
		expect(overallFor(withAllErrored, 'mail_enabled')).toBe(100);
	});
});

describe('2.0.0 override surface and ungraded stay intact (acceptance 5)', () => {
	it('an explicit criticalOverallPenalty override still subtracts', () => {
		const verifiedCritical = buildCheckResult('subdomain_takeover', [
			createFinding('subdomain_takeover', 'Verified takeover', 'critical', 'Fingerprint confirmed', { verificationStatus: 'verified' }),
		]);
		const byDefault = computeScanScore([verifiedCritical]).overall;
		const overridden = computeScanScore([verifiedCritical], undefined, {
			...DEFAULT_SCORING_CONFIG,
			thresholds: { ...DEFAULT_SCORING_CONFIG.thresholds, criticalOverallPenalty: 15 },
		}).overall;
		expect(byDefault).not.toBeNull();
		expect(overridden).toBe(byDefault! - 15);
	});

	it('an explicit emailBonus override still adds', () => {
		const mail = ['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'].map((c) => passing(c as CheckCategory));
		const config = {
			...DEFAULT_SCORING_CONFIG,
			tierSplit: { core: 70, protective: 20, hardening: 10 },
			thresholds: { ...DEFAULT_SCORING_CONFIG.thresholds, emailBonusFull: 5 },
		};
		expect(computeScanScore(mail, undefined, config).overall).toBe(95);
	});

	it('an empty scan stays ungraded (null, never 0) and scoring is deterministic', () => {
		expect(computeScanScore([]).overall).toBeNull();
		const roster = web17({ tlsrpt: failing('tlsrpt') });
		expect(computeScanScore(roster)).toEqual(computeScanScore(roster));
		expect(overallFor(roster, 'mail_enabled')).toBe(overallFor(roster, 'mail_enabled'));
	});
});
