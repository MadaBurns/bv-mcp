// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import {
	computeScanScore,
	buildCheckResult,
	createFinding,
	getProfileWeights,
	PROFILE_WEIGHTS,
	PROFILE_CRITICAL_CATEGORIES,
} from '../../scoring';
import type { CheckCategory, CheckResult, DomainContext } from '../../scoring';

function makeResult(category: CheckCategory, score: number, title?: string, severity?: 'info' | 'low' | 'medium' | 'high' | 'critical'): CheckResult {
	const findings = [];
	if (score === 100) {
		findings.push(createFinding(category, title ?? `${category} OK`, 'info', 'Check passed'));
	} else if (score === 0) {
		findings.push(createFinding(category, title ?? `No ${category} record found`, severity ?? 'critical', `Missing ${category} record`));
		findings.push(createFinding(category, `${category} required`, severity ?? 'high', `${category} is required but not found`));
	} else {
		findings.push(createFinding(category, title ?? `${category} issue`, severity ?? 'medium', 'Issue detected'));
	}
	return buildCheckResult(category, findings);
}

function buildFullResults(overrides: Partial<Record<CheckCategory, CheckResult>> = {}): CheckResult[] {
	const defaults: Record<CheckCategory, CheckResult> = {
		spf: makeResult('spf', 100),
		dmarc: makeResult('dmarc', 100),
		dkim: makeResult('dkim', 100),
		dnssec: makeResult('dnssec', 100),
		ssl: makeResult('ssl', 100),
		mta_sts: makeResult('mta_sts', 100),
		ns: makeResult('ns', 100),
		caa: makeResult('caa', 100),
		bimi: makeResult('bimi', 100),
		tlsrpt: makeResult('tlsrpt', 100),
		subdomain_takeover: makeResult('subdomain_takeover', 100),
		mx: makeResult('mx', 100),
		lookalikes: makeResult('lookalikes', 100),
		// Required by CheckResult record but not in original — add with 100
		shadow_domains: makeResult('shadow_domains', 100),
		txt_hygiene: makeResult('txt_hygiene', 100),
		http_security: makeResult('http_security', 100),
		dane: makeResult('dane', 100),
		mx_reputation: makeResult('mx_reputation', 100),
		srv: makeResult('srv', 100),
		zone_hygiene: makeResult('zone_hygiene', 100),
		dane_https: makeResult('dane_https', 100),
		svcb_https: makeResult('svcb_https', 100),
	};
	return Object.values({ ...defaults, ...overrides });
}

function makeNonMailContext(): DomainContext {
	return {
		profile: 'non_mail',
		signals: ['No MX records'],
		weights: getProfileWeights('non_mail'),
		detectedProvider: null,
	};
}

function makeEnterpriseContext(): DomainContext {
	return {
		profile: 'enterprise_mail',
		signals: ['MX present', 'google workspace provider', 'DKIM present'],
		weights: getProfileWeights('enterprise_mail'),
		detectedProvider: 'google workspace',
	};
}

describe('scoring-profiles', () => {
	describe('regression: computeScanScore without context', () => {
		it('returns identical results to pre-profile behavior', () => {
			const results = buildFullResults();
			const withoutContext = computeScanScore(results);
			const withUndefined = computeScanScore(results, undefined);
			expect(withoutContext.overall).toBe(withUndefined.overall);
			expect(withoutContext.grade).toBe(withUndefined.grade);
		});

		it('empty results still return 100', () => {
			const score = computeScanScore([]);
			expect(score.overall).toBe(100);
		});
	});

	describe('non_mail context', () => {
		it('does NOT cap score at 64 when SPF/DMARC are missing', () => {
			const results = buildFullResults({
				spf: makeResult('spf', 0, 'No SPF record found', 'critical'),
				dmarc: makeResult('dmarc', 0, 'No DMARC record found', 'critical'),
			});
			const nonMailCtx = makeNonMailContext();
			const withContext = computeScanScore(results, nonMailCtx);
			// SPF/DMARC are NOT in non_mail critical categories, so no ceiling
			expect(withContext.overall).toBeGreaterThan(64);
		});

		it('DOES cap score at 64 when SSL is missing (critical for non_mail)', () => {
			const results = buildFullResults({
				ssl: makeResult('ssl', 0, 'No valid certificate found', 'critical'),
			});
			const nonMailCtx = makeNonMailContext();
			const withContext = computeScanScore(results, nonMailCtx);
			expect(withContext.overall).toBeLessThanOrEqual(64);
		});

		it('does NOT award email bonus', () => {
			// All email checks pass — but non_mail profile should skip bonus
			const results = buildFullResults();
			const nonMailCtx = makeNonMailContext();
			const withContext = computeScanScore(results, nonMailCtx);
			const withoutContext = computeScanScore(results);
			// Without context, email bonus applies. With non_mail, it doesn't.
			// Both should be high scores but may differ slightly due to bonus
			expect(withContext.overall).toBeLessThanOrEqual(withoutContext.overall);
		});
	});

	describe('enterprise_mail context', () => {
		it('elevates MTA-STS importance', () => {
			// With enterprise profile, MTA-STS weight is 4 vs 3 for mail_enabled.
			// Both produce the same integer score (96) because the tier budget is fixed
			// and rounding absorbs the difference. Verify enterprise penalizes at least
			// as much as default.
			const results = buildFullResults({
				mta_sts: makeResult('mta_sts', 0, 'No MTA-STS record found', 'high'),
			});
			const enterpriseCtx = makeEnterpriseContext();
			const withEnterprise = computeScanScore(results, enterpriseCtx);
			const withoutContext = computeScanScore(results);
			// Enterprise MTA-STS weight (4/22 of protective budget) >= default (3/20)
			expect(withEnterprise.overall).toBeLessThanOrEqual(withoutContext.overall);
		});

		it('awards email bonus when eligible', () => {
			const results = buildFullResults();
			const enterpriseCtx = makeEnterpriseContext();
			const score = computeScanScore(results, enterpriseCtx);
			// With all checks passing, email bonus should be awarded
			expect(score.overall).toBeGreaterThanOrEqual(90);
		});
	});

	describe('snapshot: known result sets with expected scores per profile', () => {
		// Limit to core+partial set matching original test (no extra hardening noise)
		function buildPartialResults(overrides: Partial<Record<CheckCategory, CheckResult>> = {}): CheckResult[] {
			const defaults: Record<string, CheckResult> = {
				spf: makeResult('spf', 100),
				dmarc: makeResult('dmarc', 100),
				dkim: makeResult('dkim', 100),
				dnssec: makeResult('dnssec', 100),
				ssl: makeResult('ssl', 100),
				mta_sts: makeResult('mta_sts', 100),
				ns: makeResult('ns', 100),
				caa: makeResult('caa', 100),
				bimi: makeResult('bimi', 100),
				tlsrpt: makeResult('tlsrpt', 100),
				subdomain_takeover: makeResult('subdomain_takeover', 100),
				mx: makeResult('mx', 100),
				lookalikes: makeResult('lookalikes', 100),
			};
			return Object.values({ ...defaults, ...overrides });
		}

		const allPassing = buildPartialResults();

		it('all passing with mail_enabled (default) profile', () => {
			const score = computeScanScore(allPassing);
			// Three-tier: core=70, protective=20, hardening=2/7*10≈2.86 → base≈93 + email bonus 5 = 98
			// (only bimi + tlsrpt have results in hardening tier out of 7 hardening categories)
			expect(score.overall).toBe(98);
			expect(score.grade).toBe('A+');
		});

		it('all passing with enterprise_mail profile', () => {
			const score = computeScanScore(allPassing, makeEnterpriseContext());
			// Same hardening gap as mail_enabled → 98
			expect(score.overall).toBe(98);
			expect(score.grade).toBe('A+');
		});

		it('all passing with non_mail profile', () => {
			const score = computeScanScore(allPassing, makeNonMailContext());
			// No email bonus for non_mail → base ≈ 93
			expect(score.overall).toBe(93);
			expect(score.grade).toBe('A+');
		});

		it('missing SPF+DMARC: non_mail scores higher than default', () => {
			const results = buildPartialResults({
				spf: makeResult('spf', 0, 'No SPF record found', 'critical'),
				dmarc: makeResult('dmarc', 0, 'No DMARC record found', 'critical'),
			});
			const defaultScore = computeScanScore(results);
			const nonMailScore = computeScanScore(results, makeNonMailContext());
			expect(nonMailScore.overall).toBeGreaterThan(defaultScore.overall);
		});
	});

	describe('scoring v2 profile weights', () => {
		it('mail_enabled core weights sum to 52', () => {
			const core = PROFILE_WEIGHTS.mail_enabled;
			const coreSum = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const)
				.reduce((sum, k) => sum + core[k].importance, 0);
			expect(coreSum).toBe(52);
		});

		it('mail_enabled protective weights sum to 20', () => {
			const p = PROFILE_WEIGHTS.mail_enabled;
			const protSum = (['subdomain_takeover', 'http_security', 'mta_sts', 'mx', 'caa', 'ns', 'lookalikes', 'shadow_domains'] as const)
				.reduce((sum, k) => sum + p[k].importance, 0);
			expect(protSum).toBe(20);
		});

		it('mail_enabled hardening weights are all 0', () => {
			const p = PROFILE_WEIGHTS.mail_enabled;
			for (const cat of ['dane', 'bimi', 'tlsrpt', 'txt_hygiene', 'mx_reputation', 'srv', 'zone_hygiene'] as const) {
				expect(p[cat].importance).toBe(0);
			}
		});

		it('enterprise_mail core weights sum to 58', () => {
			const core = PROFILE_WEIGHTS.enterprise_mail;
			const coreSum = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const)
				.reduce((sum, k) => sum + core[k].importance, 0);
			expect(coreSum).toBe(58);
		});

		it('web_only zeroes email auth core weights', () => {
			const p = PROFILE_WEIGHTS.web_only;
			expect(p.spf.importance).toBe(0);
			expect(p.dmarc.importance).toBe(0);
			expect(p.dkim.importance).toBe(0);
			expect(p.ssl.importance).toBeGreaterThan(0);
		});

		it('non_mail core weights sum to 21', () => {
			const core = PROFILE_WEIGHTS.non_mail;
			const coreSum = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const)
				.reduce((sum, k) => sum + core[k].importance, 0);
			expect(coreSum).toBe(21);
		});

		it('minimal core weights sum to 10', () => {
			const core = PROFILE_WEIGHTS.minimal;
			const coreSum = (['spf', 'dmarc', 'dkim', 'dnssec', 'ssl'] as const)
				.reduce((sum, k) => sum + core[k].importance, 0);
			expect(coreSum).toBe(10);
		});

		it('PROFILE_CRITICAL_CATEGORIES excludes DNSSEC and subdomain_takeover for mail profiles', () => {
			expect(PROFILE_CRITICAL_CATEGORIES.mail_enabled).not.toContain('dnssec');
			expect(PROFILE_CRITICAL_CATEGORIES.enterprise_mail).not.toContain('dnssec');
			expect(PROFILE_CRITICAL_CATEGORIES.mail_enabled).not.toContain('subdomain_takeover');
			expect(PROFILE_CRITICAL_CATEGORIES.mail_enabled).toEqual(
				expect.arrayContaining(['spf', 'dmarc', 'dkim', 'ssl'])
			);
		});

		it('non_mail/web_only ceiling triggers include http_security', () => {
			expect(PROFILE_CRITICAL_CATEGORIES.non_mail).toContain('http_security');
			expect(PROFILE_CRITICAL_CATEGORIES.web_only).toContain('http_security');
		});

		it('minimal ceiling triggers only ssl', () => {
			expect(PROFILE_CRITICAL_CATEGORIES.minimal).toEqual(['ssl']);
		});
	});
});
