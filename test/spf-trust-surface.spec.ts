import { describe, it, expect } from 'vitest';
import { analyzeTrustSurface } from '../src/tools/spf-trust-surface';

describe('analyzeTrustSurface', () => {
	it('returns empty array for SPF with no shared platform includes', () => {
		const findings = analyzeTrustSurface('v=spf1 ip4:192.168.1.0/24 -all');
		expect(findings).toEqual([]);
	});

	it('returns one informational finding for SPF with one shared platform by default', () => {
		const findings = analyzeTrustSurface('v=spf1 include:_spf.google.com -all');
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].title).toContain('Google Workspace');
		expect(findings[0].metadata?.trustSurface).toBe(true);
		expect(findings[0].metadata?.platform).toBe('Google Workspace');
	});

	it('returns individual info findings plus info summary when DMARC is not weak', () => {
		const findings = analyzeTrustSurface('v=spf1 include:_spf.google.com include:sendgrid.net -all');
		// 2 individual + 1 summary = 3
		expect(findings).toHaveLength(3);
		const infos = findings.filter((f) => f.severity === 'info');
		expect(infos).toHaveLength(3);
		const summary = findings.find((f) => f.metadata?.platformCount === 2);
		expect(summary).toBeDefined();
		expect(summary!.title).toContain('2 shared platforms');
		expect(summary!.metadata?.platformCount).toBe(2);
	});

	it('elevates findings when weak DMARC corroborates the exposure', () => {
		const findings = analyzeTrustSurface('v=spf1 include:_spf.google.com include:sendgrid.net -all', {
			corroboratedByWeakDmarc: true,
			dmarcPolicy: 'none',
			dmarcAlignmentMode: 'relaxed',
		});

		expect(findings).toHaveLength(3);
		expect(findings.filter((f) => f.severity === 'medium')).toHaveLength(2);
		const summary = findings.find((f) => f.severity === 'high');
		expect(summary).toBeDefined();
		expect(summary!.metadata?.dmarcCorroborated).toBe(true);
	});

	/**
	 * Wording regression: an ENFORCING DMARC policy must never be described as "weak DMARC
	 * enforcement". The same scan_domain response lists "DMARC enforcing" in its scoring
	 * signals for p=quarantine (it is also this product's BIMI eligibility bar), so the old
	 * blanket suffix made one report contradict itself. Mirrored in the core copy's spec
	 * (packages/dns-checks/src/__tests__/checks/spf-trust-surface.test.ts).
	 */
	describe('corroboration prose matches the DMARC metadata', () => {
		it('does not claim weak enforcement for p=quarantine — cites relaxed alignment instead', () => {
			const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
				corroboratedByWeakDmarc: true,
				dmarcPolicy: 'quarantine',
				dmarcAlignmentMode: 'relaxed',
			});

			expect(findings).toHaveLength(1);
			expect(findings[0].detail).not.toMatch(/weak DMARC enforcement/i);
			expect(findings[0].detail).not.toMatch(/not enforcing/i);
			expect(findings[0].detail).toMatch(/alignment is relaxed/i);
			expect(findings[0].detail).toMatch(/p=quarantine/);
		});

		it('does not claim weak enforcement for p=reject', () => {
			const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
				corroboratedByWeakDmarc: true,
				dmarcPolicy: 'reject',
				dmarcAlignmentMode: 'relaxed',
			});

			expect(findings[0].detail).not.toMatch(/weak DMARC enforcement/i);
			expect(findings[0].detail).toMatch(/alignment is relaxed/i);
			expect(findings[0].detail).toMatch(/p=reject/);
		});

		it('does cite non-enforcement for p=none', () => {
			const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
				corroboratedByWeakDmarc: true,
				dmarcPolicy: 'none',
				dmarcAlignmentMode: 'relaxed',
			});

			expect(findings[0].detail).toMatch(/monitor-only \(p=none\) and is not enforcing/i);
		});

		it('does cite an absent DMARC record when there is none', () => {
			const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
				corroboratedByWeakDmarc: true,
				dmarcPolicy: 'missing',
				dmarcAlignmentMode: 'missing',
			});

			expect(findings[0].detail).toMatch(/No DMARC record is published/i);
			expect(findings[0].detail).not.toMatch(/weak DMARC enforcement/i);
		});

		it('cites partial application, not weak enforcement, for an enforcing pct<100 policy', () => {
			const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
				corroboratedByWeakDmarc: true,
				dmarcPolicy: 'reject; pct=50',
				dmarcAlignmentMode: 'strict',
			});

			expect(findings[0].detail).toMatch(/enforces \(p=reject\) on only 50% of mail/i);
			expect(findings[0].detail).not.toMatch(/weak DMARC enforcement/i);
		});

		it('leaves the uncorroborated (info) wording untouched', () => {
			const findings = analyzeTrustSurface('v=spf1 include:spf.protection.outlook.com -all', {
				corroboratedByWeakDmarc: false,
				dmarcPolicy: 'reject',
				dmarcAlignmentMode: 'strict',
			});

			expect(findings[0].severity).toBe('info');
			expect(findings[0].detail).toMatch(/not inherently a misconfiguration/i);
		});
	});

	it('detects platform via redirect= directive', () => {
		const findings = analyzeTrustSurface('v=spf1 redirect=_spf.google.com');
		expect(findings).toHaveLength(1);
		expect(findings[0].metadata?.platform).toBe('Google Workspace');
	});

	it('returns no findings for unknown include domain', () => {
		const findings = analyzeTrustSurface('v=spf1 include:mail.mycompany.com -all');
		expect(findings).toEqual([]);
	});

	it('matches subdomain of known platform (suffix match)', () => {
		const findings = analyzeTrustSurface('v=spf1 include:eu._spf.salesforce.com -all');
		expect(findings).toHaveLength(1);
		expect(findings[0].metadata?.platform).toBe('Salesforce');
		expect(findings[0].metadata?.includeDomain).toBe('eu._spf.salesforce.com');
	});
});
