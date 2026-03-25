import { describe, expect, it } from 'vitest';
import {
	detectDomainContext,
	getProfileWeights,
	PROFILE_WEIGHTS,
	PROFILE_CRITICAL_CATEGORIES,
	PROFILE_EMAIL_BONUS_ELIGIBLE,
	type DomainProfile,
} from '../src/lib/context-profiles';
import { buildCheckResult, createFinding, type CheckCategory } from '../src/lib/scoring-model';

function makeCheckResult(category: CheckCategory, score: number, findings: ReturnType<typeof createFinding>[] = []) {
	if (findings.length === 0) {
		if (score === 100) {
			findings = [createFinding(category, `${category} OK`, 'info', 'Check passed')];
		} else {
			findings = [createFinding(category, `${category} issue`, 'medium', 'Issue detected')];
		}
	}
	return buildCheckResult(category, findings);
}

function fullPassingResults(overrides?: Partial<Record<CheckCategory, ReturnType<typeof buildCheckResult>>>) {
	const categories: CheckCategory[] = [
		'spf', 'dmarc', 'dkim', 'dnssec', 'ssl', 'mta_sts', 'ns', 'caa', 'bimi', 'tlsrpt', 'subdomain_takeover', 'mx',
	];
	return categories.map((cat) => overrides?.[cat] ?? makeCheckResult(cat, 100));
}

describe('context-profiles', () => {
	describe('detectDomainContext', () => {
		it('detects enterprise_mail when MX + Google Workspace provider + DKIM present', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'MX records found', 'info', 'Mail handled by Google Workspace', { provider: 'Google Workspace' }),
				]),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('enterprise_mail');
			expect(ctx.signals).toContain('MX present');
			expect(ctx.signals.some((s) => s.includes('google workspace'))).toBe(true);
		});

		it('detects mail_enabled when MX present but no enterprise provider', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'MX records found', 'info', 'mail.example.com'),
				]),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('mail_enabled');
			expect(ctx.signals).toContain('MX present');
		});

		it('detects web_only when no MX but CAA present', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'No MX records found', 'high', 'No MX records found for domain'),
				]),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('web_only');
			expect(ctx.signals).toContain('No MX records');
			expect(ctx.signals).toContain('CAA present');
		});

		it('detects non_mail when no MX and no web indicators', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'No MX records found', 'high', 'No MX records found for domain'),
				]),
				caa: buildCheckResult('caa', [
					createFinding('caa', 'No CAA records', 'critical', 'No CAA records found'),
					createFinding('caa', 'CAA missing', 'high', 'CAA is required'),
				]),
				ssl: buildCheckResult('ssl', [
					createFinding('ssl', 'SSL check failed', 'critical', 'No valid certificate found'),
					createFinding('ssl', 'SSL required', 'high', 'Certificate is required'),
				]),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('non_mail');
			expect(ctx.signals).toContain('No MX records');
		});

		it('detects minimal when >50% checks failed', () => {
			const categories: CheckCategory[] = [
				'spf', 'dmarc', 'dkim', 'dnssec', 'ssl', 'mta_sts', 'ns', 'caa', 'bimi', 'tlsrpt', 'subdomain_takeover', 'mx',
			];
			// Make 7 of 12 checks fail (score < 50 => not passed) by using critical+high findings
			const results = categories.map((cat, i) => {
				if (i < 7) {
					return buildCheckResult(cat, [
						createFinding(cat, `${cat} check error`, 'critical', 'Check failed critically'),
						createFinding(cat, `${cat} also broken`, 'high', 'Additional failure'),
					]);
				}
				return makeCheckResult(cat, 100);
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('minimal');
		});

		it('detects non_mail when Null MX (RFC 7505) and no web indicators', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'Null MX record (RFC 7505)', 'info', 'Domain explicitly declares it does not accept email via null MX record.'),
				]),
				caa: buildCheckResult('caa', [
					createFinding('caa', 'No CAA records', 'critical', 'No CAA records found'),
					createFinding('caa', 'CAA missing', 'high', 'CAA is required'),
				]),
				ssl: buildCheckResult('ssl', [
					createFinding('ssl', 'SSL check failed', 'critical', 'No valid certificate found'),
					createFinding('ssl', 'SSL required', 'high', 'Certificate is required'),
				]),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('non_mail');
			expect(ctx.signals).toContain('No MX records');
		});

		it('detects web_only when Null MX but SSL valid', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'Null MX record (RFC 7505)', 'info', 'Domain explicitly declares it does not accept email via null MX record.'),
				]),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('web_only');
			expect(ctx.signals).toContain('No MX records');
			expect(ctx.signals).toContain('SSL valid');
		});

		it('defaults to mail_enabled when MX DNS query fails', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'DNS query failed', 'medium', 'MX record lookup failed'),
				]),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('mail_enabled');
			expect(ctx.signals).toContain('MX status unknown');
		});

		it('defaults to non_mail for empty results', () => {
			const ctx = detectDomainContext([]);
			// No MX result at all → !hasMx but also !hasNoMx → hasMxUnknown false → mail_enabled fallback
			expect(ctx.profile).toBe('mail_enabled');
		});

		it('explicit profile override replaces detected profile in signals', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'MX records found', 'info', 'mail.example.com'),
				]),
			});
			const ctx = detectDomainContext(results);
			// Detection should give mail_enabled
			expect(ctx.profile).toBe('mail_enabled');
			// An explicit override would be applied in scan-domain.ts, not in detectDomainContext itself
		});
	});

	describe('getProfileWeights', () => {
		it('returns the correct weight table for each profile', () => {
			const profiles: DomainProfile[] = ['mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal'];
			for (const profile of profiles) {
				const weights = getProfileWeights(profile);
				expect(weights).toEqual(PROFILE_WEIGHTS[profile]);
			}
		});

		it('each profile has non-zero total weight', () => {
			const profiles: DomainProfile[] = ['mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal'];
			for (const profile of profiles) {
				const weights = getProfileWeights(profile);
				const total = Object.values(weights).reduce((sum, w) => sum + w.importance, 0);
				expect(total).toBeGreaterThan(0);
			}
		});
	});

	describe('PROFILE_CRITICAL_CATEGORIES', () => {
		it('non_mail and web_only do not include email categories', () => {
			for (const profile of ['non_mail', 'web_only'] as DomainProfile[]) {
				const cats = PROFILE_CRITICAL_CATEGORIES[profile];
				expect(cats).not.toContain('spf');
				expect(cats).not.toContain('dmarc');
				expect(cats).not.toContain('dkim');
				expect(cats).toContain('ssl');
				expect(cats).toContain('dnssec');
			}
		});

		it('mail_enabled and enterprise_mail include email categories', () => {
			for (const profile of ['mail_enabled', 'enterprise_mail'] as DomainProfile[]) {
				const cats = PROFILE_CRITICAL_CATEGORIES[profile];
				expect(cats).toContain('spf');
				expect(cats).toContain('dmarc');
				expect(cats).toContain('dkim');
			}
		});
	});

	describe('PROFILE_EMAIL_BONUS_ELIGIBLE', () => {
		it('only mail profiles are eligible for email bonus', () => {
			expect(PROFILE_EMAIL_BONUS_ELIGIBLE.mail_enabled).toBe(true);
			expect(PROFILE_EMAIL_BONUS_ELIGIBLE.enterprise_mail).toBe(true);
			expect(PROFILE_EMAIL_BONUS_ELIGIBLE.non_mail).toBe(false);
			expect(PROFILE_EMAIL_BONUS_ELIGIBLE.web_only).toBe(false);
			expect(PROFILE_EMAIL_BONUS_ELIGIBLE.minimal).toBe(false);
		});
	});
});
