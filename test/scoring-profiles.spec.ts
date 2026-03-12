import { describe, expect, it } from 'vitest';
import { computeScanScore } from '../src/lib/scoring-engine';
import { buildCheckResult, createFinding, type CheckCategory, type CheckResult } from '../src/lib/scoring-model';
import { getProfileWeights, type DomainContext } from '../src/lib/context-profiles';

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
			// With enterprise profile, MTA-STS weight is 4 vs 2 for mail_enabled
			const results = buildFullResults({
				mta_sts: makeResult('mta_sts', 0, 'No MTA-STS record found', 'high'),
			});
			const enterpriseCtx = makeEnterpriseContext();
			const withEnterprise = computeScanScore(results, enterpriseCtx);
			const withoutContext = computeScanScore(results);
			// Enterprise should penalize MTA-STS absence more
			expect(withEnterprise.overall).toBeLessThan(withoutContext.overall);
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
		const allPassing = buildFullResults();

		it('all passing with mail_enabled (default) profile', () => {
			const score = computeScanScore(allPassing);
			expect(score.overall).toBe(100);
			expect(score.grade).toBe('A+');
		});

		it('all passing with enterprise_mail profile', () => {
			const score = computeScanScore(allPassing, makeEnterpriseContext());
			expect(score.overall).toBe(100);
			expect(score.grade).toBe('A+');
		});

		it('all passing with non_mail profile', () => {
			const score = computeScanScore(allPassing, makeNonMailContext());
			expect(score.overall).toBe(100);
			expect(score.grade).toBe('A+');
		});

		it('missing SPF+DMARC: non_mail scores higher than default', () => {
			const results = buildFullResults({
				spf: makeResult('spf', 0, 'No SPF record found', 'critical'),
				dmarc: makeResult('dmarc', 0, 'No DMARC record found', 'critical'),
			});
			const defaultScore = computeScanScore(results);
			const nonMailScore = computeScanScore(results, makeNonMailContext());
			expect(nonMailScore.overall).toBeGreaterThan(defaultScore.overall);
		});
	});
});
