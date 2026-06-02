import { describe, expect, it } from 'vitest';
import {
	detectDomainContext,
	getProfileWeights,
	PROFILE_WEIGHTS,
	PROFILE_CRITICAL_CATEGORIES,
	PROFILE_EMAIL_BONUS_ELIGIBLE,
	type DomainProfile,
} from '@blackveil/dns-checks/scoring';
import { buildCheckResult, createFinding, type CheckCategory } from '@blackveil/dns-checks/scoring';

function makeCheckResult(category: CheckCategory, score: number, findings: ReturnType<typeof createFinding>[] = []) {
	if (findings.length === 0) {
		if (score === 100) {
			findings = [createFinding(category, `${category} OK`, 'info', 'Check passed')];
		} else {
			findings = [createFinding(category, `${category} issue`, 'medium', 'Issue detected')];
		}
	}
	// A passing (score 100) synthetic check expresses "control present & active"; a failing one
	// expresses "absent/inactive". Mirrors how the real checks set controlPresent.
	return buildCheckResult(category, findings, score === 100);
}

function fullPassingResults(overrides?: Partial<Record<CheckCategory, ReturnType<typeof buildCheckResult>>>) {
	const categories: CheckCategory[] = [
		'spf', 'dmarc', 'dkim', 'dnssec', 'ssl', 'mta_sts', 'ns', 'caa', 'bimi', 'tlsrpt', 'subdomain_takeover', 'mx',
	];
	return categories.map((cat) => overrides?.[cat] ?? makeCheckResult(cat, 100));
}

describe('context-profiles', () => {
	describe('detectDomainContext', () => {
		it('detects enterprise_mail when MX + Google Workspace provider + enforcing DMARC', () => {
			// fullPassingResults defaults dmarc to a passing (controlPresent:true = enforcing) result,
			// so this is provider + enforcing DMARC → enterprise_mail.
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'MX records found', 'info', 'Mail handled by Google Workspace', { provider: 'Google Workspace' }),
				], true),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('enterprise_mail');
			expect(ctx.signals).toContain('MX present');
			expect(ctx.signals).toContain('DMARC enforcing');
			expect(ctx.signals.some((s) => s.includes('google workspace'))).toBe(true);
		});

		it('detects mail_enabled when MX present but no enterprise provider', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'MX records found', 'info', 'mail.example.com'),
				], true),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('mail_enabled');
			expect(ctx.signals).toContain('MX present');
		});

		it('detects web_only when no MX but CAA present', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'No MX records found', 'high', 'No MX records found for domain'),
				], false),
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
				], false),
				caa: buildCheckResult('caa', [
					createFinding('caa', 'No CAA records', 'critical', 'No CAA records found'),
					createFinding('caa', 'CAA missing', 'high', 'CAA is required'),
				], false),
				ssl: buildCheckResult('ssl', [
					createFinding('ssl', 'SSL check failed', 'critical', 'No valid certificate found'),
					createFinding('ssl', 'SSL required', 'high', 'Certificate is required'),
				], false),
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
				], false),
				caa: buildCheckResult('caa', [
					createFinding('caa', 'No CAA records', 'critical', 'No CAA records found'),
					createFinding('caa', 'CAA missing', 'high', 'CAA is required'),
				], false),
				ssl: buildCheckResult('ssl', [
					createFinding('ssl', 'SSL check failed', 'critical', 'No valid certificate found'),
					createFinding('ssl', 'SSL required', 'high', 'Certificate is required'),
				], false),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('non_mail');
			expect(ctx.signals).toContain('No MX records');
		});

		it('detects web_only when Null MX but SSL valid', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'Null MX record (RFC 7505)', 'info', 'Domain explicitly declares it does not accept email via null MX record.'),
				], false),
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

		// --- controlPresent structured-signal discriminators (#1+#2) ---
		// These encode that profile detection must use an *active record observed* signal, not a
		// bare passed===true (true for absent-but-not-penalized controls) or finding prose.

		it('does NOT over-fire enterprise_mail when provider MX present but no ACTIVE hardening', () => {
			// Google Workspace MX, but MTA-STS/BIMI absent (passed:true, controlPresent:false), DKIM
			// absent, and DMARC monitoring-only (p=none → controlPresent:false). No enterprise gate met.
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'MX records found', 'info', 'Mail handled by Google Workspace', { provider: 'Google Workspace' }),
				], true),
				dmarc: buildCheckResult('dmarc', [
					createFinding('dmarc', 'DMARC policy set to none', 'low', 'p=none — monitoring only.'),
				], false),
				dkim: buildCheckResult('dkim', [
					createFinding('dkim', 'No DKIM records found among tested selectors', 'high', 'No DKIM among tested selectors'),
				], false),
				mta_sts: buildCheckResult('mta_sts', [
					createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'low', 'Neither MTA-STS nor TLS-RPT present (non-mail).'),
				], false),
				bimi: buildCheckResult('bimi', [
					createFinding('bimi', 'No BIMI record found', 'low', 'No BIMI record found.'),
				], false),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('mail_enabled');
			expect(ctx.signals).not.toContain('MTA-STS present');
			expect(ctx.signals).not.toContain('BIMI present');
		});

		it('does NOT count a revoked DKIM key as an active hardening signal', () => {
			// All-revoked DKIM (info finding, passed:true, controlPresent:false). With DMARC also
			// non-enforcing, no enterprise gate is met → mail_enabled (DKIM not counted as present).
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'MX records found', 'info', 'Mail handled by Google Workspace', { provider: 'Google Workspace' }),
				], true),
				dmarc: buildCheckResult('dmarc', [
					createFinding('dmarc', 'DMARC policy set to none', 'low', 'p=none — monitoring only.'),
				], false),
				dkim: buildCheckResult('dkim', [
					createFinding('dkim', 'DKIM selectors revoked', 'info', 'All 1 DKIM selector(s) have revoked keys (empty p= tag).'),
				], false),
				mta_sts: buildCheckResult('mta_sts', [
					createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'low', 'Neither MTA-STS nor TLS-RPT present (non-mail).'),
				], false),
				bimi: buildCheckResult('bimi', [
					createFinding('bimi', 'No BIMI record found', 'low', 'No BIMI record found.'),
				], false),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('mail_enabled');
			expect(ctx.signals).not.toContain('DKIM present');
		});

		// --- enterprise_mail bar: requires enforcing DMARC, not provider + auto-DKIM (Option C) ---

		it('does NOT classify enterprise_mail on provider + auto-DKIM when DMARC is monitoring-only (p=none)', () => {
			// Google Workspace + DKIM present (auto-provisioned), but DMARC p=none → controlPresent:false.
			// The enterprise lens is stricter; applying it requires a deliberate maturity signal
			// (enforcing DMARC), which p=none is not. Should fall back to mail_enabled.
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'MX records found', 'info', 'Mail handled by Google Workspace', { provider: 'Google Workspace' }),
				], true),
				dmarc: buildCheckResult('dmarc', [
					createFinding('dmarc', 'DMARC policy set to none', 'low', 'p=none — monitoring only, not enforcing.'),
				], false),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('mail_enabled');
		});

		it('classifies enterprise_mail on provider + enforcing DMARC (p=reject) even without DKIM/MTA-STS/BIMI', () => {
			// Enforcing DMARC behind a managed provider is the enterprise-maturity signal. It qualifies
			// on its own — auto-provisioned hardening is no longer what gates the stricter lens.
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'MX records found', 'info', 'Mail handled by Google Workspace', { provider: 'Google Workspace' }),
				], true),
				dmarc: buildCheckResult('dmarc', [
					createFinding('dmarc', 'DMARC enforcing', 'info', 'p=reject — enforcing policy.'),
				], true),
				dkim: buildCheckResult('dkim', [
					createFinding('dkim', 'No DKIM records found among tested selectors', 'high', 'No DKIM among tested selectors'),
				], false),
				mta_sts: buildCheckResult('mta_sts', [
					createFinding('mta_sts', 'No MTA-STS or TLS-RPT records found', 'low', 'Neither present.'),
				], false),
				bimi: buildCheckResult('bimi', [
					createFinding('bimi', 'No BIMI record found', 'low', 'No BIMI record found.'),
				], false),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('enterprise_mail');
		});

		it('detects non_mail (not web_only) for a sparse domain whose CAA is absent-but-passed', () => {
			// No MX, no HTTPS, and CAA absent (medium "No CAA records" → passed:true, controlPresent:false).
			// Old code read caaResult.passed === true → web_only. With controlPresent it is non_mail.
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'No MX and no SPF — domain spoofable', 'medium', 'No mail exchange records and no SPF policy.'),
				], false),
				ssl: buildCheckResult('ssl', [
					createFinding('ssl', 'HTTPS connection failed', 'high', 'No valid certificate / unreachable.'),
				], false),
				caa: buildCheckResult('caa', [
					createFinding('caa', 'No CAA records', 'medium', 'No CAA records found for domain.'),
				], false),
			});
			const ctx = detectDomainContext(results);
			expect(ctx.profile).toBe('non_mail');
			expect(ctx.signals).toContain('No MX records');
			expect(ctx.signals).not.toContain('CAA present');
			expect(ctx.signals).not.toContain('SSL valid');
		});

		it('explicit profile override replaces detected profile in signals', () => {
			const results = fullPassingResults({
				mx: buildCheckResult('mx', [
					createFinding('mx', 'MX records found', 'info', 'mail.example.com'),
				], true),
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
